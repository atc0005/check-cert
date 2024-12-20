// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

//go:generate go-winres make --product-version=git-tag --file-version=git-tag

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
)

// Lead-in or prefix markers for listed summary items. These are intended to
// help the sysadmin tell at a glance whether a valid result was a positive,
// neutral or negative outcome.
//
// NOTE: All of these fit within the UTF8MB3 character set and should be safe
// for consumption by older MySQL "UTF8" databases (which lack the more
// complete UTF8 character set implementation used by newer MySQL/MariaDB
// versions).
const (
	PrefixStateOK       string = "✅"
	PrefixStateIgnored  string = "➖"
	PrefixStateWarning  string = "⚠️"
	PrefixStateCritical string = "❌"
	PrefixStateUnknown  string = "❔"
	PrefixAdviceEntry   string = "➡️"
)

// NOTE: These seem to work fairly well for plaintext, Windows 10 compatible
// output.
//
// const (
// 	PrefixStateOK       string = "OK   :"
// 	PrefixStateIgnored  string = "IGN  :"
// 	PrefixStateWarning  string = "WARN :"
// 	PrefixStateCritical string = "FAIL :"
// 	PrefixStateUnknown  string = "??   :"
// 	PrefixAdviceEntry   string = "**"
// )

// NOTE: Seems too noisy to include the parenthesis.
//
// const (
// 	PrefixStateOK       string = "(✅)"
// 	PrefixStateIgnored  string = "(➖)"
// 	PrefixStateWarning  string = "(❌)"
// 	PrefixStateCritical string = "(❌)"
// 	PrefixStateUnknown  string = "(❌)"
// )

// NOTE: An attempt to blend the two for "fallback" behavior. Seems too noisy.
//
// const (
// 	PrefixStateOK       string = "✅ (OK)"
// 	PrefixStateIgnored  string = "➖ (--)"
// 	PrefixStateWarning  string = "❌ (!!)"
// 	PrefixStateCritical string = "❌ (!!)"
// 	PrefixStateUnknown  string = "❌ (!!)"
// )

// NOTE: Not supported on Windows 10.
//
// const (
// 	PrefixStateOK       string = "✅"
// 	PrefixStateIgnored  string = "➖"
// 	PrefixStateWarning  string = "❌"
// 	PrefixStateCritical string = "❌"
// 	PrefixStateUnknown  string = "❌"
// )

func stateToPrefix(ccvr certs.CertChainValidationResult) string {
	switch {
	case ccvr.IsSucceeded():
		return PrefixStateOK
	case ccvr.IsIgnored():
		return PrefixStateIgnored
	case ccvr.IsWarningState():
		return PrefixStateWarning
	case ccvr.IsCriticalState():
		return PrefixStateCritical
	default:
		return PrefixStateUnknown
	}
}

func main() {

	// Setup configuration by parsing user-provided flags.
	cfg, cfgErr := config.New(config.AppType{Inspector: true})
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
	case cfg.InputFilename != "":

		log.Debug().Msg("Attempting to retrieve certificates from file")

		var err error
		certChain, parseAttemptLeftovers, err = certs.GetCertsFromFile(cfg.InputFilename)
		if err != nil {
			log.Error().Err(err).Msg(
				"Error parsing certificates file")
			os.Exit(config.ExitCodeCatchall)
		}

		certChainSource = cfg.InputFilename

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

		// We have a valid IP Address to use for opening the connection and a
		// sysadmin-specified DNS Name value to use for a SNI-enabled
		// certificate retrieval attempt.
		case cfg.DNSName != "":
			hostVal = cfg.DNSName
			certChainSource = fmt.Sprintf(
				"service running on %s at port %d using host value %q",
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

	textutils.PrintHeader("CERTIFICATE CHAIN | SUMMARY")

	switch {
	case len(certChain) == 0:
		log.Err(certs.ErrNoCertsFound).Msg("")
		os.Exit(config.ExitCodeCatchall)

	default:
		// If a certificate chain was pulled from a file, we "found" it, if it
		// was pulled from a server we "retrieved" it.
		var template string
		switch {
		case cfg.InputFilename != "":
			template = "\n%s %d certs found in %s\n"
		default:
			template = "\n%s %d certs retrieved for %s\n"
		}

		fmt.Printf(
			template,
			PrefixStateOK,
			len(certChain),
			certChainSource,
		)
	}

	// Create "bucket" to collect validation results. The initial size is
	// close to the number of planned validation checks.
	validationResults := make(certs.CertChainValidationResults, 0, 5)

	// The check_cert plugin "turns on" validation checks based on
	// configurable flag values. This application lacks many of those knobs;
	// instead of relying on default values we explicitly enable the checks
	// (using `certs.CertChainValidationOptions`) if equivalent flag values
	// for those checks can be inferred using from values that are available
	// (e.g., we enable SANs List validation if SANs entries are specified).

	hasLeafCert := certs.HasLeafCert(certChain)
	hostnameValidationResult := certs.ValidateHostname(
		certChain,
		cfg.Server,
		cfg.DNSName,
		config.IgnoreHostnameVerificationFailureIfEmptySANsListFlag,
		certs.CertChainValidationOptions{
			// IgnoreHostnameVerificationFailureIfEmptySANsList: cfg.IgnoreHostnameVerificationFailureIfEmptySANsList,
			IgnoreHostnameVerificationFailureIfEmptySANsList: false,
			IgnoreValidationResultHostname:                   !hasLeafCert || cfg.DNSName == "",
		},
	)
	validationResults.Add(hostnameValidationResult)

	switch {
	case hostnameValidationResult.IsFailed():
		log.Debug().
			Err(hostnameValidationResult.Err()).
			Msgf("%s validation failure", hostnameValidationResult.CheckName())

		fmt.Printf(
			"\n%s %s %s\n",
			stateToPrefix(hostnameValidationResult),
			hostnameValidationResult.Status(),
			hostnameValidationResult.Overview(),
		)

	case hostnameValidationResult.IsIgnored():
		log.Debug().
			Msgf("%s validation ignored", hostnameValidationResult.CheckName())

		fmt.Printf(
			"\n%s %s %s%s\n",
			stateToPrefix(hostnameValidationResult),
			hostnameValidationResult.Status(),
			hostnameValidationResult.Overview(),
			func() string {
				switch {
				case hasLeafCert:
					return fmt.Sprintf(
						"(use %q flag to force evaluation)",
						config.DNSNameFlagLong,
					)
				default:
					return "(not supported for this cert type)"
				}
			}(),
		)

	default:
		log.Debug().Msg("Hostname validation successful")

		fmt.Printf(
			"\n%s %s %s\n",
			stateToPrefix(hostnameValidationResult),
			hostnameValidationResult.Status(),
			hostnameValidationResult.Overview(),
		)
	}

	sansValidationResult := certs.ValidateSANsList(
		certChain,
		cfg.SANsEntries,
		certs.CertChainValidationOptions{
			// IgnoreValidationResultSANs: !cfg.ApplyCertSANsListValidationResults(),
			IgnoreValidationResultSANs: len(cfg.SANsEntries) == 0,
		},
	)
	validationResults.Add(sansValidationResult)

	switch {
	case sansValidationResult.IsFailed():
		log.Debug().
			Err(sansValidationResult.Err()).
			Int("sans_entries_requested", sansValidationResult.NumExpected()).
			Int("sans_entries_found", sansValidationResult.NumMatched()).
			Int("sans_entries_mismatched", sansValidationResult.NumMismatched()).
			Msg("SANs entries mismatch")

		fmt.Printf(
			"\n%s %s\n",
			stateToPrefix(sansValidationResult),
			sansValidationResult.String(),
		)

	case sansValidationResult.IsIgnored():
		log.Debug().
			Msgf("%s validation ignored", sansValidationResult.CheckName())

		fmt.Printf(
			"\n%s %s\n",
			stateToPrefix(sansValidationResult),
			sansValidationResult.String(),
		)

	default:
		log.Debug().
			Int("sans_entries_requested", sansValidationResult.NumExpected()).
			Int("sans_entries_found", sansValidationResult.NumMatched()).
			Msgf("%s validation successful", sansValidationResult.CheckName())

		fmt.Printf(
			"\n%s %s\n",
			stateToPrefix(sansValidationResult),
			sansValidationResult.String(),
		)
	}

	expirationValidationResult := certs.ValidateExpiration(
		certChain,
		cfg.AgeCritical,
		cfg.AgeWarning,
		cfg.VerboseOutput,
		cfg.OmitSANsEntries,
		certs.CertChainValidationOptions{
			// IgnoreExpiredIntermediateCertificates: cfg.IgnoreExpiredIntermediateCertificates,
			// IgnoreExpiredRootCertificates:         cfg.IgnoreExpiredRootCertificates,
			// IgnoreValidationResultExpiration:      !cfg.ApplyCertExpirationValidationResults(),
			IgnoreExpiredIntermediateCertificates: false,
			IgnoreExpiredRootCertificates:         false,
			IgnoreValidationResultExpiration:      false,
		},
	)

	// We intentionally do not add this to the collection as we call it
	// explicitly later.
	//
	// validationResults.Add(expirationValidationResult)

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
			"\n%s %s %s\n",
			stateToPrefix(expirationValidationResult),
			expirationValidationResult.Status(),
			expirationValidationResult.Overview(),
		)

	case expirationValidationResult.IsIgnored():
		log.Debug().
			Msgf("%s validation ignored", expirationValidationResult.CheckName())

		fmt.Printf(
			"\n%s %s\n",
			stateToPrefix(expirationValidationResult),
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
			"\n%s %s %s\n",
			stateToPrefix(expirationValidationResult),
			expirationValidationResult.Status(),
			expirationValidationResult.Overview(),
		)

	}

	chainOrderValidationResult := certs.ValidateChainOrder(
		certChain,
		cfg.VerboseOutput,
		certs.CertChainValidationOptions{
			// IgnoreValidationResultChainOrder: !cfg.ApplyCertChainOrderValidationResults(),
			IgnoreValidationResultChainOrder: false,
		},
	)
	validationResults.Add(chainOrderValidationResult)

	switch {
	case chainOrderValidationResult.IsFailed():
		log.Debug().
			Err(chainOrderValidationResult.Err()).
			Int("chain_entries_ordered", chainOrderValidationResult.NumOrderedCerts()).
			Int("chain_entries_misordered", chainOrderValidationResult.NumMisorderedCerts()).
			Int("chain_entries_total", chainOrderValidationResult.TotalCerts()).
			Msg("Chain misordered")

		fmt.Printf(
			"\n%s %s\n",
			stateToPrefix(chainOrderValidationResult),
			chainOrderValidationResult.String(),
		)

	case chainOrderValidationResult.IsIgnored():
		log.Debug().
			Msgf("%s validation ignored", chainOrderValidationResult.CheckName())

		fmt.Printf(
			"\n%s %s\n",
			stateToPrefix(chainOrderValidationResult),
			chainOrderValidationResult.String(),
		)

	default:
		log.Debug().
			Int("chain_entries_ordered", chainOrderValidationResult.NumOrderedCerts()).
			Int("chain_entries_misordered", chainOrderValidationResult.NumMisorderedCerts()).
			Msgf("%s validation successful", chainOrderValidationResult.CheckName())

		fmt.Printf(
			"\n%s %s\n",
			stateToPrefix(chainOrderValidationResult),
			chainOrderValidationResult.String(),
		)
	}

	rootValidationResult := certs.ValidateRoot(
		certChain,
		cfg.VerboseOutput,
		certs.CertChainValidationOptions{
			// IgnoreValidationResultRoot: !cfg.ApplyCertRootValidationResults(),
			IgnoreValidationResultRoot: false,
		},
	)
	validationResults.Add(rootValidationResult)

	switch {
	case rootValidationResult.IsFailed():
		log.Debug().
			Err(rootValidationResult.Err()).
			Int("root_certs", rootValidationResult.NumRootCerts()).
			Int("total_certs", rootValidationResult.TotalCerts()).
			Int("chain_entries_total", rootValidationResult.TotalCerts()).
			Msg("Chain misordered")

		fmt.Printf(
			"\n%s %s\n",
			stateToPrefix(rootValidationResult),
			rootValidationResult.String(),
		)

	case rootValidationResult.IsIgnored():
		log.Debug().
			Msgf("%s validation ignored", rootValidationResult.CheckName())

		fmt.Printf(
			"\n%s %s\n",
			stateToPrefix(rootValidationResult),
			rootValidationResult.String(),
		)

	default:
		log.Debug().
			Int("root_certs", rootValidationResult.NumRootCerts()).
			Int("total_certs", rootValidationResult.TotalCerts()).
			Msgf("%s validation successful", rootValidationResult.CheckName())

		fmt.Printf(
			"\n%s %s\n",
			stateToPrefix(rootValidationResult),
			rootValidationResult.String(),
		)
	}

	textutils.PrintHeader("CERTIFICATE CHAIN | DETAILS")

	// We request these details even if the user opted to disable expiration
	// validation since this info provides an overview of the certificate
	// chain evaluated.
	fmt.Println(expirationValidationResult.StatusDetail())

	// Generate text version of the certificate if requested.
	if cfg.EmitCertText {
		textutils.PrintHeader("CERTIFICATE CHAIN | OpenSSL Text Format")

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
		textutils.PrintHeader("CERTIFICATE CHAIN | UNKNOWN data in cert file")

		fmt.Printf(
			"The following data (converted to text) was found in the %q input"+
				" file and is provided here in case it is useful for"+
				" troubleshooting purposes.\n\n",
			cfg.InputFilename,
		)

		fmt.Println(string(parseAttemptLeftovers))
	}

	if validationResults.Errs(true) != nil && validationResults.HasFailed() {
		textutils.PrintHeader("CERTIFICATE CHAIN | ADDITIONAL INFO")

		validationResults.Sort()

		for _, validationResult := range validationResults {
			switch {
			case validationResult.Err() != nil && !validationResult.IsIgnored():
				details := validationResult.StatusDetail()
				if details == "" {
					details = validationResult.Err().Error()
				}

				fmt.Printf(
					"%s %s\n\n%s\n\n",
					PrefixAdviceEntry,
					validationResult.CheckName(),
					details,
				)

			default:
				// nothing for now
			}

		}
	}

}
