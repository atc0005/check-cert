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

	"github.com/rs/zerolog"

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

		// We make some assumptions when setting up our logger as we do not
		// have a working configuration based on sysadmin-specified choices.
		consoleWriter := zerolog.ConsoleWriter{Out: os.Stderr}
		logger := zerolog.New(consoleWriter).With().Timestamp().Caller().Logger()

		logger.Err(cfgErr).Msg("Error initializing application")

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
				"Error parsing certificates file")
			os.Exit(config.ExitCodeCatchall)
		}

		certChainSource = cfg.Filename

	case cfg.Server != "":

		log.Debug().Msg("Expanding given host pattern in order to obtain IP Address")
		expandedHost, expandErr := netutils.ExpandHost(cfg.Server)
		switch {
		case expandErr != nil:
			log.Error().Err(expandErr).Msg(
				"Error expanding given host pattern")
			os.Exit(config.ExitCodeCatchall)

		// Fail early for IP Ranges. While we could just grab the first
		// expanded IP Address, this may be a potential source of confusion
		// best avoided.
		case expandedHost.Range:
			log.Error().Msgf(
				"Given host pattern invalid; " +
					"host pattern is a CIDR or partial IP range",
			)
			os.Exit(config.ExitCodeCatchall)

		case len(expandedHost.Expanded) == 0:
			log.Error().Msg(
				"Failed to expand given host value to IP Address")
			os.Exit(config.ExitCodeCatchall)

		case len(expandedHost.Expanded) > 1:

			ipAddrs := zerolog.Arr()
			for _, ip := range expandedHost.Expanded {
				ipAddrs.Str(ip)
			}

			log.Debug().
				Int("num_ip_addresses", len(expandedHost.Expanded)).
				Array("ip_addresses", ipAddrs).
				Msg("Multiple IP Addresses resolved from given host pattern")
			log.Debug().Msg("Using first IP Address, ignoring others")

		}

		// Grab first IP Address from the resolved collection. We'll
		// explicitly use it for cert retrieval and note it in the report
		// output.
		ipAddr := expandedHost.Expanded[0]

		// Server Name Indication (SNI) support is used to request a specific
		// certificate chain from a remote server.
		//
		// We use the value specified by the server flag to open a connection
		// to the remote server. If available, we use the DNS Name value
		// specified by the DNS Name flag as our host value, otherwise we
		// fallback to using the value specified by the server flag as our
		// host value.
		//
		// For a service with only one certificate chain the host value is
		// less important, but for a host with multiple certificate chains
		// having the correct host value is crucial.
		var hostVal string
		switch {

		// We have a resolved IP Address and a sysadmin-specified DNS Name
		// value to use for a SNI-enabled certificate retrieval attempt.
		case expandedHost.Resolved && cfg.DNSName != "":
			hostVal = cfg.DNSName
			certChainSource = fmt.Sprintf(
				"service running on %s (%s) at port %d using host value %q",
				expandedHost.Given,
				ipAddr,
				cfg.Port,
				hostVal,
			)

		// We have a resolved IP Address, but not a sysadmin-specified DNS
		// Name value. We'll use the resolvable name/FQDN for a SNI-enabled
		// certificate retrieval attempt.
		case expandedHost.Resolved && cfg.DNSName == "":
			hostVal = expandedHost.Given
			certChainSource = fmt.Sprintf(
				"service running on %s (%s) at port %d using host value %q",
				expandedHost.Given,
				ipAddr,
				cfg.Port,
				expandedHost.Given,
			)
		default:
			certChainSource = fmt.Sprintf(
				"service running on %s at port %d",
				ipAddr,
				cfg.Port,
			)
		}

		log.Debug().
			Str("server", cfg.Server).
			Str("dns_name", cfg.DNSName).
			Str("ip_address", ipAddr).
			Str("host_value", hostVal).
			Int("port", cfg.Port).
			Msg("Retrieving certificate chain")
		var certFetchErr error
		certChain, certFetchErr = netutils.GetCerts(
			hostVal,
			ipAddr,
			cfg.Port,
			cfg.Timeout(),
			log,
		)
		if certFetchErr != nil {
			log.Error().Err(certFetchErr).Msg(
				"Error fetching certificates chain")
			os.Exit(config.ExitCodeCatchall)
		}

	}

	textutils.PrintHeader("CERTIFICATES | SUMMARY")

	switch {
	case len(certChain) == 0:
		log.Err(certs.ErrNoCertsFound).Msg("")
		os.Exit(config.ExitCodeCatchall)

	default:
		// If a certificate chain was pulled from a file, we "found" it, if it
		// was pulled from a server we "retrieved" it.
		var template string
		switch {
		case cfg.Filename != "":
			template = "- %s: %d certs found in %s\n"
		default:
			template = "- %s: %d certs retrieved for %s\n"
		}

		fmt.Printf(
			template,
			nagios.StateOKLabel,
			len(certChain),
			certChainSource,
		)
	}

	hostnameValidationResult := certs.ValidateHostname(
		certChain,
		cfg.Server,
		cfg.DNSName,
		cfg.ApplyCertHostnameValidationResults(),
		cfg.IgnoreHostnameVerificationFailureIfEmptySANsList,
		config.IgnoreHostnameVerificationFailureIfEmptySANsListFlag,
	)

	switch {
	case hostnameValidationResult.IsFailed():
		log.Debug().
			Err(hostnameValidationResult.Err()).
			Msgf("%s validation failure", hostnameValidationResult.CheckName())

		fmt.Printf(
			"- %s: %s %s\n",
			hostnameValidationResult.ServiceState().Label,
			hostnameValidationResult.Status(),
			hostnameValidationResult.Overview(),
		)

	case hostnameValidationResult.IsIgnored():
		log.Debug().
			Msgf("%s validation ignored", hostnameValidationResult.CheckName())

		fmt.Printf(
			"- %s: %s %s\n",
			hostnameValidationResult.ServiceState().Label,
			hostnameValidationResult.Status(),
			hostnameValidationResult.Overview(),
		)

	default:
		log.Debug().Msg("Hostname validation successful")

		fmt.Printf(
			"- %s: %s %s\n",
			hostnameValidationResult.ServiceState().Label,
			hostnameValidationResult.Status(),
			hostnameValidationResult.Overview(),
		)
	}

	sansValidationResult := certs.ValidateSANsList(
		certChain,
		cfg.ApplyCertSANsListValidationResults(),
		cfg.DNSName,
		cfg.SANsEntries,
	)
	switch {
	case sansValidationResult.IsFailed():
		log.Debug().
			Err(sansValidationResult.Err()).
			Int("sans_entries_requested", sansValidationResult.NumExpected()).
			Int("sans_entries_found", sansValidationResult.NumMatched()).
			Int("sans_entries_mismatched", sansValidationResult.NumMismatched()).
			Msg("SANs entries mismatch")

		fmt.Printf(
			"- %s: %s\n",
			sansValidationResult.ServiceState().Label,
			sansValidationResult.String(),
		)

	case sansValidationResult.IsIgnored():
		log.Debug().
			Msgf("%s validation ignored", sansValidationResult.CheckName())

		fmt.Printf(
			"- %s: %s\n",
			sansValidationResult.ServiceState().Label,
			sansValidationResult.String(),
		)

	default:
		log.Debug().
			Int("sans_entries_requested", sansValidationResult.NumExpected()).
			Int("sans_entries_found", sansValidationResult.NumMatched()).
			Msgf("%s validation successful", sansValidationResult.CheckName())

		fmt.Printf(
			"- %s: %s\n",
			sansValidationResult.ServiceState().Label,
			sansValidationResult.String(),
		)
	}

	expirationValidationResult := certs.ValidateExpiration(
		certChain,
		cfg.AgeCritical,
		cfg.AgeWarning,
		cfg.ApplyCertExpirationValidationResults(),
		cfg.VerboseOutput,
	)
	switch {
	case expirationValidationResult.IsFailed():
		log.Debug().
			Err(expirationValidationResult.Err()).
			Int("total_certificates", expirationValidationResult.TotalCerts()).
			Int("expired_certificates", expirationValidationResult.NumExpiredCerts()).
			Int("expiring_certificates", expirationValidationResult.NumExpiringCerts()).
			Int("valid_certificates", expirationValidationResult.NumValidCerts()).
			Str("threshold_expires_warning", expirationValidationResult.WarningDateThreshold()).
			Str("threshold_expires_critical", expirationValidationResult.CriticalDateThreshold()).
			Msgf("%s validation failure", expirationValidationResult.CheckName())

		fmt.Printf(
			"- %s: %s %s\n",
			expirationValidationResult.ServiceState().Label,
			expirationValidationResult.Status(),
			expirationValidationResult.Overview(),
		)

	case expirationValidationResult.IsIgnored():
		log.Debug().
			Msgf("%s validation ignored", expirationValidationResult.CheckName())

		fmt.Printf(
			"- %s: %s\n",
			expirationValidationResult.ServiceState().Label,
			expirationValidationResult.String(),
		)

	default:
		log.Debug().
			Int("total_certificates", expirationValidationResult.TotalCerts()).
			Int("expired_certificates", expirationValidationResult.NumExpiredCerts()).
			Int("expiring_certificates", expirationValidationResult.NumExpiringCerts()).
			Int("valid_certificates", expirationValidationResult.NumValidCerts()).
			Str("threshold_expires_warning", expirationValidationResult.WarningDateThreshold()).
			Str("threshold_expires_critical", expirationValidationResult.CriticalDateThreshold()).
			Msgf("%s validation successful", expirationValidationResult.CheckName())

		fmt.Printf(
			"- %s: %s %s\n",
			expirationValidationResult.ServiceState().Label,
			expirationValidationResult.Status(),
			expirationValidationResult.Overview(),
		)

	}

	textutils.PrintHeader("CERTIFICATES | CHAIN DETAILS")

	// We request these details even if the user opted to disable expiration
	// validation since this info provides an overview of the certificate
	// chain evaluated.
	fmt.Println(expirationValidationResult.StatusDetail())

	// Generate text version of the certificate if requested.
	if cfg.EmitCertText {
		textutils.PrintHeader("CERTIFICATES | OpenSSL Text Format")

		for idx, certificate := range certChain {
			certText, err := certinfo.CertificateText(certificate)
			if err != nil {
				certText = err.Error()
			}

			fmt.Printf(
				"\nCertificate %d of %d:\n%s\n",
				idx+1,
				len(certChain),
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
