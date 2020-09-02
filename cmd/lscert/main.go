// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/grantae/certinfo"

	"github.com/atc0005/check-certs/internal/certs"
	"github.com/atc0005/check-certs/internal/logging"
	"github.com/atc0005/check-certs/internal/textutils"
	"github.com/atc0005/go-nagios"
)

func main() {

	config := Config{}

	config.handleFlagsConfig()

	// Display application info and exit
	if config.ShowVersion {
		fmt.Println(Version())
		os.Exit(0)
	}

	if err := config.Validate(); err != nil {
		log.Err(err).Msg("Error validating configuration")
		flag.Usage()
		os.Exit(1)
	}

	// Set common fields here so that we don't have to repeat them explicitly
	// later. This will hopefully help to standardize the log messages to make
	// them easier to search through later when troubleshooting.
	log := zerolog.New(os.Stderr).With().Caller().
		Str("version", version).
		Str("logging_level", config.LoggingLevel).
		Str("server", config.Server).
		Int("port", config.Port).
		Str("filename", config.Filename).Logger()

	if err := logging.SetLoggingLevel(config.LoggingLevel); err != nil {
		log.Err(err).Msg("configuring logging level")
	}

	var certChain []*x509.Certificate

	// Anything from the specified file that couldn't be converted to a
	// certificate chain. While likely not of high value, it could help
	// identify why a certificate isn't being properly trusted by a client
	// application, so emitting it may be useful to the user of this
	// application.
	var parseAttemptLeftovers []byte

	var certChainSource string

	// Honor request to parse filename first
	switch {
	case config.Filename != "":

		var err error
		certChain, parseAttemptLeftovers, err = certs.GetCertsFromFile(config.Filename)
		if err != nil {
			log.Error().Err(err).Str("filename", config.Filename).Msgf(
				"error parsing certificates file")
			os.Exit(1)
		}

		// figure out what couldn't be parsed and display it

		certChainSource = config.Filename

	case config.Server != "":

		server := fmt.Sprintf("%s:%d", config.Server, config.Port)

		// log.Debug().Msg("Connecting to remote server")
		fmt.Printf(
			"\nConnecting to remote server %q at port %d\n",
			config.Server,
			config.Port,
		)
		cfg := tls.Config{
			// Allow insecure connection so that we can check not only the
			// initial certificate (which may be expired), but others in the
			// chain also to potentially catch any intermediates which may
			// also be expired. Also, ignore security (gosec) linting warnings
			// re this choice.
			// nolint:gosec
			InsecureSkipVerify: true,
		}

		// Create custom dialer with user-specified timeout value
		dialer := &net.Dialer{
			Timeout: time.Duration(config.Timeout) * time.Second,
		}

		conn, connErr := tls.DialWithDialer(dialer, "tcp", server, &cfg)
		if connErr != nil {
			log.Error().Err(connErr).Msgf("error connecting to server")
			os.Exit(1)
		}
		defer func() {
			if err := conn.Close(); err != nil {
				log.Error().Err(err).Msgf("error closing connection to server")
			}
		}()
		log.Debug().Msg("Connected")

		// certificate chain presented by remote peer
		certChain = conn.ConnectionState().PeerCertificates

		certChainSource = fmt.Sprintf(
			"service running on %s at port %d",
			config.Server,
			config.Port,
		)

	}

	now := time.Now().UTC()
	certsExpireAgeWarning := now.AddDate(0, 0, config.AgeWarning)
	certsExpireAgeCritical := now.AddDate(0, 0, config.AgeCritical)

	certsSummary := certs.ChainSummary(
		certChain,
		certsExpireAgeCritical,
		certsExpireAgeWarning,
	)

	textutils.PrintHeader("CERTIFICATES | AGE THRESHOLDS")
	fmt.Printf(
		"\n- %s:\tExpires before %v (%d days)\n",
		nagios.StateWARNINGLabel,
		certsExpireAgeWarning.Format(certs.CertValidityDateLayout),
		config.AgeWarning,
	)
	fmt.Printf(
		"- %s:\tExpires before %v (%d days)\n",
		nagios.StateCRITICALLabel,
		certsExpireAgeCritical.Format(certs.CertValidityDateLayout),
		config.AgeCritical,
	)

	textutils.PrintHeader("CERTIFICATES | SUMMARY")

	if certsSummary.TotalCertsCount == 0 {
		noCertsErr := fmt.Errorf("no certificates found")
		log.Err(noCertsErr).Msg("")

		// defer os.Exit so that the deferred server connection close step can
		// run
		defer func() {
			os.Exit(1)
		}()
	}

	fmt.Printf(
		"\n- %s: %d certs found for %s\n",
		nagios.StateOKLabel,
		certsSummary.TotalCertsCount,
		certChainSource,
	)

	if config.Server != "" {

		if len(certChain) > 0 {

			hostnameValueToUse := config.Server

			// Allow user to explicitly specify which hostname should be used
			// for comparison against the leaf certificate.
			if config.DNSName != "" {
				hostnameValueToUse = config.DNSName
			}

			// verify leaf certificate is valid for the provided server FQDN
			if err := certChain[0].VerifyHostname(hostnameValueToUse); err != nil {
				log.Warn().Err(err).Msgf(
					"provided hostname %q does not match server certificate",
					hostnameValueToUse,
				)
			} else {
				fmt.Println("- OK: Provided hostname matches discovered certificate")
			}
		}

	}

	// check SANS entries if provided via command-line
	if len(config.SANsEntries) > 0 {

		// Check for special keyword, skip SANs entry checks if provided
		firstSANsEntry := strings.ToLower(strings.TrimSpace(config.SANsEntries[0]))
		if firstSANsEntry != strings.ToLower(strings.TrimSpace(SkipSANSCheckKeyword)) {

			if mismatched, err := certs.CheckSANsEntries(certChain[0], config.SANsEntries); err != nil {

				log.Debug().
					Err(err).
					Int("sans_entries_requested", len(config.SANsEntries)).
					Int("sans_entries_found", len(certChain)).
					Int("sans_entries_mismatched", mismatched).
					Msg("SANs entries mismatch")

				fmt.Printf(
					"- %s: %v \n", err,
					certsSummary.ServiceCheckStatus,
				)
			}

		}
	}

	nextToExpire := fmt.Sprintf(
		"- %s",
		certs.OneLineCheckSummary(
			certsSummary.ServiceCheckStatus,
			certChain,
			// Leave off summary/overview as we'll emit it separately
			// certsSummary.Summary,
			"",
		),
	)
	fmt.Println(nextToExpire)

	statusOverview := fmt.Sprintf(
		"- %s: %s",
		certsSummary.ServiceCheckStatus,
		certsSummary.Summary,
	)
	fmt.Println(statusOverview)

	textutils.PrintHeader("CERTIFICATES | CHAIN DETAILS")

	fmt.Println(certs.GenerateCertsReport(
		certChain,
		certsExpireAgeCritical,
		certsExpireAgeWarning,
	))

	if config.EmitCertText {
		textutils.PrintHeader("CERTIFICATES | OpenSSL Text Format")

		for idx, certificate := range certChain {

			// generate text version of the certificate
			certText, err := certinfo.CertificateText(certificate)
			if err != nil {
				certText = err.Error()
			}

			fmt.Printf(
				"\nCertificate %d of %d:\n%s\n",
				idx+1,
				certsSummary.TotalCertsCount,
				certText,
			)

		}

	}

	if len(parseAttemptLeftovers) > 0 {
		textutils.PrintHeader("CERTIFICATES | UNKNOWN text in cert file")

		fmt.Printf("The following text was found in the %q file"+
			" and is provided here in case it is useful for"+
			" troubleshooting purposes.\n\n",
			config.Filename,
		)

		fmt.Println(string(parseAttemptLeftovers))
	}

}
