// Copyright 2024 Adam Chalkley
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
	"github.com/atc0005/check-cert/internal/textutils"
	"github.com/atc0005/go-nagios"
)

func main() {
	// Setup configuration by parsing user-provided flags.
	cfg, cfgErr := config.New(config.AppType{Copier: true})
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

	// Emulate returning exit code from main function by "queuing up" a
	// default exit code that matches expectations, but allow explicitly
	// setting the exit code in such a way that is compatible with using
	// deferred function calls throughout the application.
	var appExitCode int
	defer func(code *int) {
		var exitCode int
		if code != nil {
			exitCode = *code
		}
		os.Exit(exitCode)
	}(&appExitCode)

	log := cfg.Log.With().Logger()

	var certChain []*x509.Certificate

	// Anything from the specified file that couldn't be converted to a
	// certificate chain. While likely not of high value, it could help
	// identify why a certificate isn't being properly trusted by a client
	// application, so emitting it may be useful to the user of this
	// application.
	var parseAttemptLeftovers []byte

	var certChainSource string

	switch {
	case cfg.InputFilename != "":

		log.Debug().Msg("Attempting to retrieve certificates from file")

		var err error
		certChain, parseAttemptLeftovers, err = certs.GetCertsFromFile(cfg.InputFilename)
		if err != nil {
			log.Error().Err(err).Msg(
				"Error parsing certificates file")
			appExitCode = config.ExitCodeCatchall
			return
		}

		certChainSource = cfg.InputFilename

	case cfg.Server != "":

		log.Debug().Msg("Expanding given host pattern in order to obtain IP Address")
		expandedHost, expandErr := netutils.ExpandHost(cfg.Server)
		switch {
		// Provide useful feedback here to cover the case of the INPUT_PATTERN
		// not existing as a file or resolving as a server value.
		case expandErr != nil && cfg.PosArgInputPattern != "":
			log.Error().Err(config.ErrInvalidPosArgPattern).Msgf(
				"Input pattern %q unrecognized as valid server value or filename",
				cfg.PosArgInputPattern,
			)
			appExitCode = config.ExitCodeCatchall
			return

		case expandErr != nil:
			log.Error().Err(expandErr).Msg(
				"Error expanding given host pattern")
			appExitCode = config.ExitCodeCatchall
			return

		// Fail early for IP Ranges. While we could just grab the first
		// expanded IP Address, this may be a potential source of confusion
		// best avoided.
		case expandedHost.Range:
			log.Error().Msgf(
				"Given host pattern invalid; " +
					"host pattern is a CIDR or partial IP range",
			)
			appExitCode = config.ExitCodeCatchall
			return

		case len(expandedHost.Expanded) == 0:
			log.Error().Msg(
				"Failed to expand given host value to IP Address")
			appExitCode = config.ExitCodeCatchall
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
			appExitCode = config.ExitCodeCatchall
			return
		}

	}

	// Abort immediately if we have nothing to work with.
	if len(certChain) == 0 {
		log.Err(certs.ErrNoCertsFound).Msg("")
		appExitCode = config.ExitCodeCatchall
		return
	}

	if len(parseAttemptLeftovers) > 0 {
		textutils.PrintHeader("CERTIFICATES | UNKNOWN data in cert file")

		fmt.Printf(
			"The following data (converted to text) was found in the %q input"+
				" file and is provided here in case it is useful for"+
				" troubleshooting purposes.\n\n",
			cfg.InputFilename,
		)

		fmt.Println(string(parseAttemptLeftovers))

		appExitCode = config.ExitCodeCatchall
		return
	}

	// If a certificate chain was pulled from a file, we "found" it, if it
	// was pulled from a server we "retrieved" it.
	var template string
	switch {
	case cfg.InputFilename != "":
		template = "%s: %d certs found in %s:\n"
	default:
		template = "%s: %d certs retrieved for %s:\n"
	}

	fmt.Printf(
		template,
		nagios.StateOKLabel,
		len(certChain),
		certChainSource,
	)

	if err := printCertChain(os.Stdout, certChain); err != nil {
		log.Err(err).Msg("failed to print certificate file")
		appExitCode = config.ExitCodeCatchall

		return
	}

	filteredCertChain := filterCertChain(cfg.CertTypesToKeep(), certChain)
	switch {
	case len(filteredCertChain) == 0:
		err := errors.New("all certificates in input chain excluded")
		log.Err(err).Msg("failed to create output certificate file")
		appExitCode = config.ExitCodeCatchall

		return
	case len(filteredCertChain) != len(certChain):
		fmt.Println("OK: Input certificate chain filtered as requested.")

		fmt.Println("\nNew certificate chain:")
		if err := printCertChain(os.Stdout, filteredCertChain); err != nil {
			log.Err(err).Msg("failed to print certificate file")
			appExitCode = config.ExitCodeCatchall

			return
		}
	default:
		fmt.Println("OK: Retaining input certificate chain as-is:")

		if err := printCertChain(os.Stdout, certChain); err != nil {
			log.Err(err).Msg("failed to print certificate file")
			appExitCode = config.ExitCodeCatchall

			return
		}
	}

	// Open the file to write the certificate chain
	outputFile, err := os.Create(cfg.OutputFilename)
	if err != nil {
		log.Err(err).Msg("failed to create output certificate file")
		appExitCode = config.ExitCodeCatchall
		return
	}

	defer func() {
		if err := outputFile.Close(); err != nil {
			log.Err(err).Msg("error occurred closing output file")
		}
	}()

	for _, cert := range filteredCertChain {
		err := certs.WriteCertToPEMFile(outputFile, cert)
		if err != nil {
			log.Err(err).Msg("failed to write certificate")

			appExitCode = config.ExitCodeCatchall
			return
		}
	}

	fmt.Printf(
		"\n%d of %d certs successfully written to %s\n",
		len(filteredCertChain),
		len(certChain),
		cfg.OutputFilename,
	)
}
