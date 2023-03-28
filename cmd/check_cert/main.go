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

	"github.com/atc0005/check-cert/internal/certs"
	"github.com/atc0005/check-cert/internal/config"
	"github.com/atc0005/check-cert/internal/netutils"
	"github.com/atc0005/go-nagios"
)

func main() {

	plugin := nagios.NewPlugin()

	// Override default section headers with our custom values.
	plugin.SetErrorsLabel("VALIDATION ERRORS")
	plugin.SetDetailedInfoLabel("VALIDATION CHECKS REPORT")

	// defer this from the start so it is the last deferred function to run
	defer plugin.ReturnCheckResults()

	// Setup configuration by parsing user-provided flags.
	cfg, cfgErr := config.New(config.AppType{Plugin: true})
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

		plugin.ServiceOutput = fmt.Sprintf(
			"%s: Error initializing application",
			nagios.StateUNKNOWNLabel,
		)
		plugin.AddError(cfgErr)
		plugin.ExitStatusCode = nagios.StateUNKNOWNExitCode

		return
	}

	// Collect last minute details just before ending plugin execution.
	defer func(plugin *nagios.Plugin, logger zerolog.Logger) {
		// Annotate errors (if applicable) with additional context to aid in
		// troubleshooting.
		plugin.Errors = annotateError(logger, plugin.Errors...)
	}(plugin, cfg.Log)

	if cfg.EmitBranding {
		// If enabled, show application details at end of notification
		plugin.BrandingCallback = config.Branding("Notification generated by ")
	}

	log := cfg.Log.With().
		Str("expected_sans_entries", cfg.SANsEntries.String()).
		Logger()

	var certChain []*x509.Certificate

	var certChainSource string

	// Honor request to parse filename first
	switch {
	case cfg.Filename != "":

		log.Debug().Msg("Attempting to parse certificate file")

		// Anything from the specified file that couldn't be converted to a
		// certificate chain. While likely not of high value by itself,
		// failure to parse a certificate file indicates a likely source of
		// trouble. We consider this scenario to be a CRITICAL state.
		var parseAttemptLeftovers []byte

		var err error
		certChain, parseAttemptLeftovers, err = certs.GetCertsFromFile(cfg.Filename)
		if err != nil {
			log.Error().Err(err).Msg(
				"Error parsing certificates file")

			plugin.AddError(err)
			plugin.ServiceOutput = fmt.Sprintf(
				"%s: Error parsing certificates file %q",
				nagios.StateCRITICALLabel,
				cfg.Filename,
			)
			plugin.ExitStatusCode = nagios.StateCRITICALExitCode

			return
		}

		certChainSource = cfg.Filename

		log.Debug().Msg("Certificate file parsed")

		if len(parseAttemptLeftovers) > 0 {
			log.Error().Err(err).Msg(
				"Unknown data encountered while parsing certificates file")

			plugin.AddError(fmt.Errorf(
				"%d unknown/unparsed bytes remaining at end of cert file %q",
				len(parseAttemptLeftovers),
				cfg.Filename,
			))
			plugin.ServiceOutput = fmt.Sprintf(
				"%s: Unknown data encountered while parsing certificates file %q",
				nagios.StateWARNINGLabel,
				cfg.Filename,
			)

			plugin.LongServiceOutput = fmt.Sprintf(
				"The following text from the %q certificate file failed to parse"+
					" and is provided here for troubleshooting purposes:%s%s%s",
				cfg.Filename,
				nagios.CheckOutputEOL,
				nagios.CheckOutputEOL,
				string(parseAttemptLeftovers),
			)
			plugin.ExitStatusCode = nagios.StateWARNINGExitCode

			return
		}

	case cfg.Server != "":

		log.Debug().Msg("Expanding given host pattern in order to obtain IP Address")
		expandedHost, expandErr := netutils.ExpandHost(cfg.Server)
		switch {
		case expandErr != nil:
			log.Error().Err(expandErr).Msg(
				"Error expanding given host pattern")

			plugin.AddError(expandErr)
			plugin.ServiceOutput = fmt.Sprintf(
				"%s: Error expanding given host pattern %q to target IP Address",
				nagios.StateCRITICALLabel,
				cfg.Server,
			)
			plugin.ExitStatusCode = nagios.StateCRITICALExitCode

			// no need to go any further, we *want* to exit right away; we don't
			// have a connection to the remote server and there isn't anything
			// further we can do
			return

		// Fail early for IP Ranges. While we could just grab the first
		// expanded IP Address, this may be a potential source of confusion
		// best avoided.
		case expandedHost.Range:
			invalidHostPatternErr := errors.New("invalid host pattern")
			msg := fmt.Sprintf(
				"Given host pattern invalid; " +
					"host pattern is a CIDR or partial IP range",
			)
			log.Error().Err(invalidHostPatternErr).Msg(msg)

			plugin.AddError(invalidHostPatternErr)
			plugin.ServiceOutput = fmt.Sprintf(
				"%s: %s",
				nagios.StateCRITICALLabel,
				msg,
			)
			plugin.ExitStatusCode = nagios.StateCRITICALExitCode

			// no need to go any further, we *want* to exit right away; we don't
			// have a connection to the remote server and there isn't anything
			// further we can do
			return

		case len(expandedHost.Expanded) == 0:
			expandHostErr := errors.New("host pattern expansion failed")
			msg := "Error expanding given host value to IP Address"

			log.Error().Err(expandHostErr).Msg(msg)

			plugin.AddError(expandHostErr)
			plugin.ServiceOutput = fmt.Sprintf(
				"%s: %s",
				nagios.StateCRITICALLabel,
				msg,
			)
			plugin.ExitStatusCode = nagios.StateCRITICALExitCode

			// no need to go any further, we *want* to exit right away; we don't
			// have a connection to the remote server and there isn't anything
			// further we can do
			return

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
		// We use the value specified by the `server` flag to open a
		// connection to the remote server. If available, we use the DNS Name
		// value specified by the DNA Name flag as our host value, otherwise
		// we fallback to using the value specified by the server flag as our
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

			plugin.AddError(certFetchErr)
			plugin.ServiceOutput = fmt.Sprintf(
				"%s: Error fetching certificates from port %d on %s",
				nagios.StateCRITICALLabel,
				cfg.Port,
				cfg.Server,
			)
			plugin.ExitStatusCode = nagios.StateCRITICALExitCode

			// no need to go any further, we *want* to exit right away; we don't
			// have a connection to the remote server and there isn't anything
			// further we can do
			return

		}

	}

	// NOTE: Not sure this would ever be reached due to:
	//
	// - expectations of tls.Dial() that a certificate is present for the
	//   connection
	//
	// - file-based certificate retrieval asserting that at last one cert was
	//   retrieved
	//
	// but we check anyway to rule out the possibility.
	if len(certChain) == 0 {
		noCertsErr := fmt.Errorf("no certificates found")
		plugin.AddError(noCertsErr)
		plugin.ServiceOutput = fmt.Sprintf(
			"%s: 0 certificates found at port %d on %q",
			nagios.StateCRITICALLabel,
			cfg.Port,
			cfg.Server,
		)
		plugin.ExitStatusCode = nagios.StateCRITICALExitCode
		log.Error().Err(noCertsErr).Msg("No certificates found")

		return
	}

	// Prepend a baseline lead-in that summarizes the number of certificates
	// retrieved and from which target host/IP Address.
	defer func() {
		// If a certificate chain was pulled from a file, we "found" it, if it
		// was pulled from a server we "retrieved" it.
		//
		// TODO: Alternatively, we could use the world "evaluated" to cover
		// both cases?
		var template string
		switch {
		case cfg.Filename != "":
			template = "%d certs found in %s%s%s"
		default:
			template = "%d certs retrieved for %s%s%s"
		}

		plugin.LongServiceOutput = fmt.Sprintf(
			template,
			len(certChain),
			certChainSource,
			nagios.CheckOutputEOL,
			plugin.LongServiceOutput,
		)
	}()

	validationResults := runValidationChecks(cfg, certChain, log)

	// validationResults.Sort()
	for _, item := range validationResults {
		log.Debug().Msgf(
			"Name: %s, Priority: %d\n",
			item.CheckName(),
			item.Priority(),
		)
	}

	pd, perfDataErr := getPerfData(certChain, cfg.AgeCritical, cfg.AgeWarning)
	if perfDataErr != nil {
		log.Error().
			Err(perfDataErr).
			Msg("failed to generate performance data")

		// Surface the error in plugin output.
		plugin.AddError(perfDataErr)

		plugin.ExitStatusCode = nagios.StateUNKNOWNExitCode
		plugin.ServiceOutput = fmt.Sprintf(
			"%s: Failed to generate performance data metrics",
			nagios.StateUNKNOWNLabel,
		)

		return
	}

	if err := plugin.AddPerfData(false, pd...); err != nil {
		log.Error().
			Err(err).
			Msg("failed to add performance data")

		// Surface the error in plugin output.
		plugin.AddError(err)

		plugin.ExitStatusCode = nagios.StateUNKNOWNExitCode
		plugin.ServiceOutput = fmt.Sprintf(
			"%s: Failed to process performance data metrics",
			nagios.StateUNKNOWNLabel,
		)

		return
	}

	switch {
	case validationResults.HasFailed():

		if cfg.ListIgnoredValidationCheckResultErrors {
			plugin.AddError(validationResults.Errs(true)...)
		} else {
			plugin.AddError(validationResults.Errs(false)...)
		}

		plugin.ServiceOutput = validationResults.OneLineSummary()
		plugin.LongServiceOutput = validationResults.Report()

		plugin.ExitStatusCode = validationResults.ServiceState().ExitCode

		log.Error().
			Err(validationResults.Err()).
			Int("checks_total", validationResults.Total()).
			Int("checks_failed", validationResults.NumFailed()).
			Int("checks_ignored", validationResults.NumIgnored()).
			Int("checks_successful", validationResults.NumSucceeded()).
			Msg("validation checks failed for certificate chain")

	default:

		plugin.ServiceOutput = validationResults.OneLineSummary()
		plugin.LongServiceOutput = validationResults.Report()

		plugin.ExitStatusCode = nagios.StateOKExitCode
		log.Debug().
			Int("checks_total", validationResults.Total()).
			Int("checks_failed", validationResults.NumFailed()).
			Int("checks_ignored", validationResults.NumIgnored()).
			Int("checks_successful", validationResults.NumSucceeded()).
			Msg("No (non-ignored) problems with certificate chain detected")

	}

}
