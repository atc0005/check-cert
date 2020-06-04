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
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/grantae/certinfo"

	"github.com/atc0005/check-certs/internal/certs"
	"github.com/atc0005/check-certs/internal/logging"
)

// TODO: Move to a better location?
func printHeader(headerText string) {
	headerBorderStr := strings.Repeat("=", len(headerText))
	fmt.Printf(
		"\n\n%s\n%s\n%s\n",
		headerBorderStr,
		headerText,
		headerBorderStr,
	)
}

func main() {

	config := Config{}

	config.handleFlagsConfig()

	// Display application branding info and exit
	if config.EmitBranding {
		fmt.Println(Branding())
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

	// Anything from the specified file that couldn't be coverted to a
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
		cfg := tls.Config{}
		conn, err := tls.Dial("tcp", server, &cfg)
		if err != nil {
			log.Error().Err(err).Msgf("error connecting to server")
			os.Exit(1)
		}
		log.Debug().Msg("Connected")

		// certificate chain presented by remote peer
		certChain = conn.ConnectionState().PeerCertificates

		certChainSource = fmt.Sprintf(
			"service running on %s at port %d",
			config.Server,
			config.Port,
		)

	}

	certsTotal := len(certChain)

	printHeader("CERTIFICATES | SUMMARY")

	if certsTotal < 0 {
		errMsg := fmt.Errorf("no certificates found")
		log.Err(errMsg).Msg("")
		os.Exit(1)
	}

	fmt.Printf(
		"\n- OK: %d certs found for %s\n",
		certsTotal,
		certChainSource,
	)

	if config.Server != "" {

		if len(certChain) > 0 {
			// verify leaf certificate is valid for the provided server FQDN
			if err := certChain[0].VerifyHostname(config.Server); err != nil {
				log.Warn().Err(err).Msgf(
					"provided hostname %q does not match server certificate",
					config.Server,
				)
			} else {
				fmt.Println("- OK: Provided hostname matches discovered certificate")
			}
		}

	}

	if expired, count := certs.HasExpiredCert(certChain); expired {
		fmt.Printf("- WARNING: %d certificates expired", count)
	}

	// TODO: Add IsExpiringSoon() function and emit results of the check here

	printHeader("CERTIFICATES | CHAIN DETAILS")

	certsExpireAgeWarning := time.Now().Add(time.Hour * 24 * time.Duration(config.AgeWarning))
	certsExpireAgeCritical := time.Now().Add(time.Hour * 24 * time.Duration(config.AgeCritical))

	for idx, certificate := range certChain {

		certPosition := certs.ChainPosition(certificate)

		expiresText := certs.ExpirationStatus(
			certificate,
			certsExpireAgeCritical,
			certsExpireAgeWarning,
		)

		fmt.Printf(
			"\nCertificate %d of %d (%s):\n\tName: %s\n\tKeyID: %v\n\tSANs entries: %s\n\tIssuer: %s\n\tIssuerKeyID: %v\n\tSerial: %s\n\tExpiration: %s\n\tStatus: %s\n",
			idx+1,
			certsTotal,
			certPosition,
			certificate.Subject,
			certs.ConvertKeyIdToHexStr(certificate.SubjectKeyId),
			certificate.DNSNames,
			certificate.Issuer,
			certs.ConvertKeyIdToHexStr(certificate.AuthorityKeyId),
			certificate.SerialNumber,
			certificate.NotAfter.String(),
			expiresText,
		)

	}

	if config.EmitCertText {
		printHeader("CERTIFICATES | OpenSSL Text Format")

		for idx, certificate := range certChain {

			// generate text version of the certificate
			certText, err := certinfo.CertificateText(certificate)
			if err != nil {
				certText = err.Error()
			}

			fmt.Printf(
				"\nCertificate %d of %d:\n%s\n",
				idx+1,
				certsTotal,
				certText,
			)

		}

	}

	if len(parseAttemptLeftovers) > 0 {
		printHeader("CERTIFICATES | UNKNOWN text in cert file")

		fmt.Printf("The following text was found in the %q file"+
			" and is provided here in case it is useful for"+
			" troubleshooting purposes.\n\n",
			config.Filename,
		)

		fmt.Println(string(parseAttemptLeftovers))
	}

}
