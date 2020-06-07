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
	"strings"
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

	// Display application info and exit
	if config.ShowVersion {
		fmt.Println(Version())
		os.Exit(0)
	}

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
		nagiosExitState.BrandingCallback = Branding("Notification generated by ")
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
		// nolint:gosec
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

	// NOTE: Not sure this would ever be reached due to expectations of
	// tls.Dial() that a certificate is present for the connection
	if certsTotal == 0 {
		nagiosExitState.LastError = fmt.Errorf("no certificates found")
		nagiosExitState.ServiceOutput = "0 certificates found at " + server
		nagiosExitState.ExitStatusCode = nagios.StateCRITICAL
		log.Error().Err(err).Str("server", server).Msg("no certificates found")
		nagiosExitState.ReturnCheckResults()
	}

	if certsTotal > 0 {

		hostnameValue := config.Server

		// Allow user to explicitly specify which hostname should be used
		// for comparison against the leaf certificate.
		if config.DNSName != "" {
			hostnameValue = config.DNSName
		}

		// verify leaf certificate is valid for the provided server FQDN
		// NOTE: We make the assumption that the leaf certificate is ALWAYS in
		// position 0 of the chain. Not having the cert in that position is
		// treated as an error condition.
		if err := certChain[0].VerifyHostname(hostnameValue); err != nil {
			nagiosExitState.LastError = err
			nagiosExitState.ServiceOutput = fmt.Sprintf(
				"hostname %q does not match first cert in chain %q",
				hostnameValue,
				certChain[0].Subject.CommonName,
			)
			nagiosExitState.ExitStatusCode = nagios.StateCRITICAL
			log.Error().
				Err(err).
				Str("server", config.Server).
				Str("dns_name", config.DNSName).
				Str("cert_cn", certChain[0].Subject.CommonName).
				Str("sans_entries", fmt.Sprintf("%s", certChain[0].DNSNames)).
				Msg("hostname does not match first cert in chain")
			nagiosExitState.ReturnCheckResults()

		}

		log.Debug().
			Str("hostname", config.Server).
			Str("cert_cn", certChain[0].Subject.CommonName).
			Msg("provided hostname %q matches server certificate")

	}

	// check SANS entries if provided via command-line
	if len(config.SANsEntries) > 0 {

		// Check for special keyword, skip SANs entry checks if provided
		firstSANsEntry := strings.ToLower(strings.TrimSpace(config.SANsEntries[0]))
		if firstSANsEntry != SkipSANSCheckKeyword {

			if mismatched, err := certs.CheckSANsEntries(certChain[0], config.SANsEntries); err != nil {

				nagiosExitState.LastError = err

				nagiosExitState.LongServiceOutput = certs.GenerateCertsReport(
					certChain,
					certsExpireAgeCritical,
					certsExpireAgeWarning,
				)

				nagiosExitState.ServiceOutput = fmt.Sprintf(
					"CRITICAL: Mismatch of %d SANs entries for certificate %q",
					mismatched,
					config.Server,
				)

				nagiosExitState.ExitStatusCode = nagios.StateWARNING
				log.Warn().
					Err(nagiosExitState.LastError).
					Int("sans_entries_requested", len(config.SANsEntries)).
					Int("sans_entries_found", len(certChain)).
					Msg("SANs entries mismatch")
				nagiosExitState.ReturnCheckResults()

			}
		}
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

	// Give the all clear: no issues found. Do go ahead and mention the next
	// expiration date in the chain for quick reference however.
	nextCertToExpire := certs.NextToExpire(certChain)

	nagiosExitState.LastError = nil
	nagiosExitState.ServiceOutput = fmt.Sprintf(
		"%s: %s cert %q expires next on %s",
		"OK",
		certs.ChainPosition(nextCertToExpire),
		nextCertToExpire.Subject.CommonName,
		nextCertToExpire.NotAfter.Format("2006-01-02 15:04:05 -0700 MST"),
	)
	nagiosExitState.LongServiceOutput = certs.GenerateCertsReport(
		certChain,
		certsExpireAgeCritical,
		certsExpireAgeWarning,
	)
	nagiosExitState.ExitStatusCode = nagios.StateOK
	log.Debug().Msg("No problems with certificate chain detected")
	nagiosExitState.ReturnCheckResults()

}
