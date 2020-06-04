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
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/atc0005/check-certs/internal/certs"
	"github.com/atc0005/check-certs/internal/logging"
	"github.com/atc0005/go-nagios"
)

func main() {

	// Setup configuration by parsing user-provided flags
	config := Config{}
	config.handleFlagsConfig()

	// Set initial "state" as valid, adjust as we go.
	var nagiosExitState = NagiosExitState{
		LastError:      nil,
		ExitStatusCode: nagios.StateOK,
	}

	if err := config.Validate(); err != nil {
		nagiosExitState.ServiceOutput = "CRITICAL: Error validating configuration"
		nagiosExitState.LastError = err
		nagiosExitState.ExitStatusCode = nagios.StateCRITICAL
		log.Err(err).Msg("Error validating configuration")
		nagiosExitState.ReturnCheckResults()
	}

	if config.EmitBranding {
		// If enabled, show application details at end of notification
		nagiosExitState.BrandingCallback = Branding
	}

	// Use provided threshold values to calculate the expiration times that
	// should trigger either a WARNING or CRITICAL state.
	certsExpireAgeWarning := time.Now().Add(time.Hour * 24 * time.Duration(config.AgeWarning))
	certsExpireAgeCritical := time.Now().Add(time.Hour * 24 * time.Duration(config.AgeCritical))

	// Note: Nagios doesn't look at stderr, only stdout. We have to make sure
	// that only whatever output is meant for consumption is emitted to stdout
	// and whatever is meant for troubleshooting is sent to stderr. To help
	// keep these two goals separate (and because Nagios doesn't really do
	// anything special with JSON output from plugins), we use stdlib fmt
	// package output functions for Nagios via stdout and logging package for
	// troubleshooting via stderr.
	//
	// Also, set common fields here so that we don't have to repeat them
	// explicitly later. This will hopefully help to standardize the log
	// messages to make them easier to search through later when
	// troubleshooting.
	log := zerolog.New(os.Stderr).With().Caller().
		Str("version", version).
		Str("logging_level", config.LoggingLevel).
		Str("server", config.Server).
		Int("port", config.Port).
		Int("age_warning", config.AgeWarning).
		Int("age_critical", config.AgeCritical).
		Str("expected_sans_entries", config.SANsEntries.String()).Logger()

	if err := logging.SetLoggingLevel(config.LoggingLevel); err != nil {
		nagiosExitState.LastError = err
		nagiosExitState.ServiceOutput = "CRITICAL: Error configuring logging level"
		nagiosExitState.ExitStatusCode = nagios.StateCRITICAL
		log.Err(err).Msg("configuring logging level")
		nagiosExitState.ReturnCheckResults()
	}

	server := fmt.Sprintf("%s:%d", config.Server, config.Port)

	log.Debug().Msg("Connecting to remote server")
	cfg := tls.Config{
		// Allow insecure connection so that we can check not only the initial
		// certificate (which may be expired), but others in the chain also to
		// potentially catch any intermediates which may also be expired.
		// Also, ignore security (gosec) linting warnings re this choice.
		// nosec
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", server, &cfg)
	if err != nil {
		nagiosExitState.LastError = err
		nagiosExitState.ServiceOutput = "Error connecting to " + server
		nagiosExitState.ExitStatusCode = nagios.StateCRITICAL
		log.Error().Err(err).Str("server", server).Msg("error connecting to server")
		nagiosExitState.ReturnCheckResults()
	}
	log.Debug().Msg("Connected")

	// certificate chain presented by remote peer
	certChain := conn.ConnectionState().PeerCertificates
	certsTotal := len(certChain)

	if certsTotal == 0 {
		nagiosExitState.LastError = fmt.Errorf("no certificates found")
		nagiosExitState.ServiceOutput = "0 certificates found at " + server
		nagiosExitState.ExitStatusCode = nagios.StateCRITICAL
		log.Error().Err(err).Str("server", server).Msg("no certificates found")
		nagiosExitState.ReturnCheckResults()
	}

	if certsTotal > 0 {
		// verify leaf certificate is valid for the provided server FQDN
		if err := certChain[0].VerifyHostname(config.Server); err != nil {
			nagiosExitState.LastError = err
			nagiosExitState.ServiceOutput = fmt.Sprintf(
				"hostname %q does not match first cert in chain %q",
				config.Server,
				certChain[0].Subject.CommonName,
			)
			nagiosExitState.ExitStatusCode = nagios.StateCRITICAL
			log.Error().
				Err(err).
				Str("hostname", config.Server).
				Str("cert_cn", certChain[0].Subject.CommonName).
				Msg("hostname does not match first cert in chain")
			nagiosExitState.ReturnCheckResults()

		}

		log.Debug().
			Str("hostname", config.Server).
			Str("cert_cn", certChain[0].Subject.CommonName).
			Msg("provided hostname %q matches server certificate")

	}

	hasExpiredCerts, expiredCertsCount := certs.HasExpiredCert(certChain)
	hasExpiringCerts, expiringCertsCount := certs.HasExpiringCert(
		certChain,
		certsExpireAgeCritical,
		certsExpireAgeWarning,
	)
	validCertsCount := certsTotal - expiredCertsCount - expiringCertsCount

	certsSummary := fmt.Sprintf(
		"[EXPIRED: %d, EXPIRING: %d, OK: %d]",
		expiredCertsCount,
		expiringCertsCount,
		validCertsCount,
	)

	if hasExpiredCerts || hasExpiringCerts {

		nagiosExitState.LastError = fmt.Errorf(
			"%d certificates expired or expiring",
			expiredCertsCount+expiringCertsCount,
		)
		nagiosExitState.LongServiceOutput = certs.GenerateCertsReport(
			certChain,
			certsExpireAgeCritical,
			certsExpireAgeWarning,
		)

		certValidationFailureTmpl := "%s: Invalid certificate chain for %q %s"

		if hasExpiringCerts {
			nagiosExitState.ServiceOutput = fmt.Sprintf(
				certValidationFailureTmpl,
				"WARNING",
				config.Server,
				certsSummary,
			)
			nagiosExitState.ExitStatusCode = nagios.StateWARNING
			log.Warn().
				Err(nagiosExitState.LastError).
				Int("expiring_certs", expiringCertsCount).
				Msg("expired certs present in chain")
		}

		// intentionally overwrite/override "warning" status from the last
		// check; expired certs are more of a concern than expiring certs
		if hasExpiredCerts {
			nagiosExitState.ServiceOutput = fmt.Sprintf(
				certValidationFailureTmpl,
				"CRITICAL",
				config.Server,
				certsSummary,
			)
			nagiosExitState.ExitStatusCode = nagios.StateCRITICAL
			log.Error().
				Err(nagiosExitState.LastError).
				Int("expired_certs", expiredCertsCount).
				Msg("expired certs present in chain")
		}

		nagiosExitState.ReturnCheckResults()

	}

	// Give the all clear: no issues found
	nagiosExitState.LastError = nil
	nagiosExitState.ServiceOutput = "OK: " + certsSummary
	nagiosExitState.ExitStatusCode = nagios.StateOK
	log.Debug().Msg("No problems with certificate chain detected")
	nagiosExitState.ReturnCheckResults()

}
