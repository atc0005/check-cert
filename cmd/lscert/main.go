// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"

	"github.com/grantae/certinfo"

	"github.com/atc0005/check-cert/internal/certs"
	"github.com/atc0005/check-cert/internal/config"
	"github.com/atc0005/check-cert/internal/netutils"
	"github.com/atc0005/check-cert/internal/textutils"
	"github.com/atc0005/go-nagios"
)

func main() {

	// Setup configuration by parsing user-provided flags.
	cfg, cfgErr := config.New(config.AppType{Inspecter: true})
	switch {
	case errors.Is(cfgErr, config.ErrVersionRequested):
		fmt.Println(config.Version())

		return

	case cfgErr != nil:
		// We're using the standalone Err function from rs/zerolog/log as we
		// do not have a working configuration.
		zlog.Err(cfgErr).Msg("Error initializing application")

		return
	}

	log := cfg.Log.With().Logger()

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
	case cfg.Filename != "":

		log.Debug().Msg("Attempting to retrieve certificates from file")

		var err error
		certChain, parseAttemptLeftovers, err = certs.GetCertsFromFile(cfg.Filename)
		if err != nil {
			log.Error().Err(err).Msg(
				"error parsing certificates file")
			os.Exit(1)
		}

		certChainSource = cfg.Filename

	case cfg.Server != "":

		log.Debug().Msg("Attempting to retrieve certificates from server")

		// We should only have one expanded host value from one given host
		// pattern (since IP ranges are not valid server flag input values).
		expandedHost, expandErr := netutils.ExpandHost(cfg.Server)
		switch {
		case expandErr != nil:
			log.Error().Err(expandErr).Msg(
				"error expanding given host pattern")
			os.Exit(1)

		case len(expandedHost) > 1:
			log.Error().Msgf(
				"given host pattern invalid; "+
					"host pattern expands to %d host values; only one expected",
				len(expandedHost),
			)
			os.Exit(1)

		case len(expandedHost[0].Expanded) == 0:
			log.Error().Msg(
				"error expanding given host value to IP Address")
			os.Exit(1)

		case len(expandedHost[0].Expanded) > 1:

			ipAddrs := zerolog.Arr()
			for _, ip := range expandedHost[0].Expanded {
				ipAddrs.Str(ip)
			}

			log.Warn().
				Int("num_ip_addresses", len(expandedHost[0].Expanded)).
				Array("ip_addresses", ipAddrs).
				Msg("Multiple IP Addresses resolved from given host pattern")
			log.Warn().Msg("Using first IP Address, ignoring others")

		}

		// Grab first IP Address from the resolved collection.
		ipAddr := expandedHost[0].Expanded[0]

		var hostVal string
		switch {
		case expandedHost[0].Resolved:
			hostVal = expandedHost[0].Given
			certChainSource = fmt.Sprintf(
				"service running on %s (%s) at port %d",
				hostVal,
				ipAddr,
				cfg.Port,
			)
		default:
			certChainSource = fmt.Sprintf(
				"service running on %s at port %d",
				ipAddr,
				cfg.Port,
			)
		}

		var certFetchErr error
		certChain, certFetchErr = netutils.GetCerts(
			// NOTE: This is a potentially empty string depending on whether
			// host pattern was a resolvable name/FQDN.
			hostVal,

			ipAddr,
			cfg.Port,
			cfg.Timeout(),
			log,
		)
		if certFetchErr != nil {
			log.Error().Err(certFetchErr).Msg(
				"error fetching certificates chain")
			os.Exit(1)
		}

	}

	now := time.Now().UTC()
	certsExpireAgeWarning := now.AddDate(0, 0, cfg.AgeWarning)
	certsExpireAgeCritical := now.AddDate(0, 0, cfg.AgeCritical)

	certsSummary := certs.ChainSummary(
		certChain,
		certsExpireAgeCritical,
		certsExpireAgeWarning,
	)

	textutils.PrintHeader("CERTIFICATES | AGE THRESHOLDS")
	fmt.Printf(
		"- %s:\tExpires before %v (%d days)\n",
		nagios.StateWARNINGLabel,
		certsExpireAgeWarning.Format(certs.CertValidityDateLayout),
		cfg.AgeWarning,
	)
	fmt.Printf(
		"- %s:\tExpires before %v (%d days)\n",
		nagios.StateCRITICALLabel,
		certsExpireAgeCritical.Format(certs.CertValidityDateLayout),
		cfg.AgeCritical,
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
		"- %s: %d certs found for %s\n",
		nagios.StateOKLabel,
		certsSummary.TotalCertsCount,
		certChainSource,
	)

	if cfg.Server != "" {

		if len(certChain) > 0 {

			hostnameValueToUse := cfg.Server

			// Allow user to explicitly specify which hostname should be used
			// for comparison against the leaf certificate.
			if cfg.DNSName != "" {
				hostnameValueToUse = cfg.DNSName
			}

			// verify leaf certificate is valid for the provided server FQDN
			if err := certChain[0].VerifyHostname(hostnameValueToUse); err != nil {
				fmt.Printf("- WARNING: Provided hostname %q does not match server certificate: %v\n", hostnameValueToUse, err)
			} else {
				fmt.Println("- OK: Provided hostname matches discovered certificate")
			}
		}

	}

	// check SANS entries if provided via command-line
	if len(cfg.SANsEntries) > 0 {

		// Check for special keyword, skip SANs entry checks if provided
		firstSANsEntry := strings.ToLower(strings.TrimSpace(cfg.SANsEntries[0]))
		if firstSANsEntry != strings.ToLower(strings.TrimSpace(config.SkipSANSCheckKeyword)) {

			if mismatched, err := certs.CheckSANsEntries(certChain[0], certChain, cfg.SANsEntries); err != nil {

				log.Debug().
					Err(err).
					Int("sans_entries_requested", len(cfg.SANsEntries)).
					Int("sans_entries_found", len(certChain)).
					Int("sans_entries_mismatched", mismatched).
					Msg("SANs entries mismatch")

				fmt.Printf(
					"- %s: %v \n", err,
					certsSummary.ServiceState().Label,
				)
			}

		}
	}

	nextToExpire := fmt.Sprintf(
		"- %s",
		certs.OneLineCheckSummary(certsSummary, false),
	)
	fmt.Println(nextToExpire)

	statusOverview := fmt.Sprintf(
		"- %s: %s",
		certsSummary.ServiceState().Label,
		certsSummary.Summary,
	)
	fmt.Println(statusOverview)

	textutils.PrintHeader("CERTIFICATES | CHAIN DETAILS")

	fmt.Println(certs.GenerateCertsReport(
		certsSummary,
		cfg.VerboseOutput,
	))

	if cfg.EmitCertText {
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
		textutils.PrintHeader("CERTIFICATES | UNKNOWN data in cert file")

		fmt.Printf("The following data (converted to text) was found in the %q file"+
			" and is provided here in case it is useful for"+
			" troubleshooting purposes.\n\n",
			cfg.Filename,
		)

		fmt.Println(string(parseAttemptLeftovers))
	}

}
