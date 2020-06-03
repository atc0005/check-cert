// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"crypto/tls"
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/grantae/certinfo"

	"github.com/atc0005/check-certs/internal/certs"
	"github.com/atc0005/check-certs/internal/logging"
)

func main() {

	config := Config{}

	config.handleFlagsConfig()

	// Display application branding info and exit
	if config.EmitBranding {
		Branding()
		os.Exit(0)
	}

	if err := config.Validate(); err != nil {
		log.Err(err).Msg("Error validating configuration")
	}

	// Set common fields here so that we don't have to repeat them explicitly
	// later. This will hopefully help to standardize the log messages to make
	// them easier to search through later when troubleshooting.
	log := zerolog.New(os.Stderr).With().Caller().
		Str("version", version).
		Str("logging_level", config.LoggingLevel).
		Str("server", config.Server).
		Int("port", config.Port).Logger()

	if err := logging.SetLoggingLevel(config.LoggingLevel); err != nil {
		log.Err(err).Msg("configuring logging level")
	}

	server := fmt.Sprintf("%s:%d", config.Server, config.Port)

	log.Debug().Msg("Connecting to remote server")
	cfg := tls.Config{}
	conn, err := tls.Dial("tcp", server, &cfg)
	if err != nil {
		log.Error().Err(err).Msgf("error connecting to server")
		os.Exit(1)
	}
	log.Debug().Msg("Connected")

	// certificate chain presented by remote peer
	certChain := conn.ConnectionState().PeerCertificates
	certsTotal := len(certChain)

	fmt.Printf(
		"\n%d certs found for service running on %s at port %d\n",
		certsTotal,
		config.Server,
		config.Port,
	)

	if certsTotal > 0 {
		// verify leaf certificate is valid for the provided server FQDN
		if err := certChain[0].VerifyHostname(config.Server); err != nil {
			log.Warn().Err(err).Msgf(
				"provided hostname %q does not match server certificate",
				config.Server,
			)
		} else {
			fmt.Println("OK: Provided hostname matches discovered certificate")
		}
	}

	fmt.Printf("\nCERTIFICATES | SUMMARY\n")

	var certPosition string
	for idx, certificate := range certChain {

		switch {
		case idx == 0:
			certPosition = "leaf"
		case certificate.Issuer.String() == certificate.Subject.String():
			certPosition = "root"
		default:
			certPosition = "intermediate"
		}

		fmt.Printf(
			"\nCertificate %d of %d (%s):\n\tName: %s\n\tKeyID: %v\n\tSANs entries: %s\n\tIssuer: %s\n\tIssuerKeyID: %v\n\tSerial: %s\n\tExpires: %v\n",
			idx+1,
			certsTotal,
			certPosition,
			certificate.Subject,
			certs.ConvertKeyIdToHexStr(certificate.SubjectKeyId),
			certificate.DNSNames,
			certificate.Issuer,
			certs.ConvertKeyIdToHexStr(certificate.AuthorityKeyId),
			certificate.SerialNumber,
			certificate.NotAfter,
		)

		if config.EmitCertText {
			fmt.Printf("\nCERTIFICATES | DETAILS\n")

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

	}

}
