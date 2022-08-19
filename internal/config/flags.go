// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package config

import (
	"flag"
	"fmt"
	"os"
)

// supportedValuesFlagHelpText is a flag package helper function that combines
// base help text with a list of supported values for the flag.
func supportedValuesFlagHelpText(baseHelpText string, supportedValues []string) string {
	return fmt.Sprintf(
		"%s Supported values: %v",
		baseHelpText,
		supportedValues,
	)
}

// handleFlagsConfig handles toggling the exposure of specific configuration
// flags to the user. This behavior is controlled via the specified
// application type as set by each cmd. Based on the application type, a
// smaller subset of flags specific to each type are exposed along with a set
// common to all application types.
func (c *Config) handleFlagsConfig(appType AppType) {

	// Application specific template used for generating lead-in usage/help
	// text.
	var usageTextHeaderTmpl string

	var appDescription string

	// Flags specific to one application type or the other
	switch {
	case appType.Plugin:

		// Override the default Help output with a brief lead-in summary of
		// the expected syntax and project version.
		//
		// For this specific application type, flags are *required*.
		//
		// https://stackoverflow.com/a/36787811/903870
		// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html
		usageTextHeaderTmpl = "%s\n\nUsage:  %s <flags>\n\n%s\n\nFlags:\n"

		appDescription = "Nagios plugin used to monitor & perform validation checks of certificate chains."

		flag.BoolVar(&c.EmitBranding, BrandingFlag, defaultBranding, brandingFlagHelp)
		flag.BoolVar(
			&c.IgnoreHostnameVerificationFailureIfEmptySANsList,
			IgnoreHostnameVerificationFailureIfEmptySANsListFlag,
			defaultIgnoreHostnameVerificationIfEmptySANsList,
			ignoreHostnameVerificationFailureIfEmptySANsListFlagHelp,
		)

		flag.BoolVar(&c.VerboseOutput, VerboseFlagShort, defaultVerboseOutput, verboseOutputFlagHelp+" (shorthand)")
		flag.BoolVar(&c.VerboseOutput, VerboseFlagLong, defaultVerboseOutput, verboseOutputFlagHelp)

		flag.BoolVar(&c.ListIgnoredValidationCheckResultErrors, ListIgnoredErrorsFlag, defaultListIgnoredValidationCheckResultErrors, listIgnoredErrorsFlagHelp)

		flag.StringVar(&c.Filename, FilenameFlagLong, defaultFilename, filenameFlagHelp)

		flag.StringVar(&c.Server, ServerFlagShort, defaultServer, serverFlagHelp+" (shorthand)")
		flag.StringVar(&c.Server, ServerFlagLong, defaultServer, serverFlagHelp)

		flag.StringVar(&c.DNSName, DNSNameFlagShort, defaultDNSName, dnsNameFlagHelp+" (shorthand)")
		flag.StringVar(&c.DNSName, DNSNameFlagLong, defaultDNSName, dnsNameFlagHelp)

		flag.IntVar(&c.Port, PortFlagShort, defaultPort, portFlagHelp+" (shorthand)")
		flag.IntVar(&c.Port, PortFlagLong, defaultPort, portFlagHelp)

		flag.Var(
			&c.ignoreValidationResults,
			IgnoreValidationResultFlag,
			supportedValuesFlagHelpText(ignoreValidationResultsFlagHelp, supportedValidationCheckResultKeywords()),
		)

		flag.Var(
			&c.applyValidationResults,
			ApplyValidationResultFlag,
			supportedValuesFlagHelpText(applyValidationResultsFlagHelp, supportedValidationCheckResultKeywords()),
		)

	case appType.Inspecter:

		// Override the default Help output with a brief lead-in summary of
		// the expected syntax and project version.
		//
		// For this specific application type, flags are required unless the
		// host/url pattern is provided, at which point flags are optional.
		// Because I'm not sure how to specify this briefly, both are listed
		// as optional.
		//
		// https://stackoverflow.com/a/36787811/903870
		// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html
		usageTextHeaderTmpl = "%s\n\nUsage:  %s [flags] [pattern]\n\n%s\n\nFlags:\n"

		appDescription = "Used to generate a summary of certificate chain metadata and validation results for quick review."

		flag.BoolVar(&c.VerboseOutput, VerboseFlagShort, defaultVerboseOutput, verboseOutputFlagHelp+" (shorthand)")
		flag.BoolVar(&c.VerboseOutput, VerboseFlagLong, defaultVerboseOutput, verboseOutputFlagHelp)

		flag.StringVar(&c.Filename, FilenameFlagLong, defaultFilename, filenameFlagHelp)
		flag.BoolVar(&c.EmitCertText, EmitCertTextFlagLong, defaultEmitCertText, emitCertTextFlagHelp)

		flag.StringVar(&c.Server, ServerFlagShort, defaultServer, serverFlagHelp+" (shorthand)")
		flag.StringVar(&c.Server, ServerFlagLong, defaultServer, serverFlagHelp)

		flag.StringVar(&c.DNSName, DNSNameFlagShort, defaultDNSName, dnsNameFlagHelp)
		flag.StringVar(&c.DNSName, DNSNameFlagLong, defaultDNSName, dnsNameFlagHelp)

		flag.IntVar(&c.Port, PortFlagShort, defaultPort, portFlagHelp+" (shorthand)")
		flag.IntVar(&c.Port, PortFlagLong, defaultPort, portFlagHelp)

	case appType.Scanner:

		// Override the default Help output with a brief lead-in summary of
		// the expected syntax and project version.
		//
		// For this specific application type, flags are *required*.
		//
		// https://stackoverflow.com/a/36787811/903870
		// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html
		usageTextHeaderTmpl = "%s\n\nUsage:  %s <flags>\n\n%s\n\nFlags:\n"

		appDescription = "Scanner used for evaluating certificates in one or more given IP ranges or collection of name/FQDN values."

		flag.IntVar(&c.timeoutPortScan, TimeoutPortScanFlagLong, defaultPortScanTimeout, timeoutPortScanFlagHelp)
		flag.IntVar(&c.timeoutPortScan, TimeoutPortScanFlagShort, defaultPortScanTimeout, timeoutPortScanFlagHelp+" (shorthand)")

		flag.Var(&c.hosts, HostsFlagLong, hostsFlagHelp)
		flag.Var(&c.hosts, HostsFlagAlt, hostsFlagHelp+" (alt name)")

		flag.IntVar(&c.ScanRateLimit, ScanRateLimitFlagLong, defaultScanRateLimit, scanRateLimitFlagHelp)
		flag.IntVar(&c.ScanRateLimit, ScanRateLimitFlagShort, defaultScanRateLimit, scanRateLimitFlagHelp+" (shorthand)")

		flag.IntVar(&c.timeoutAppInactivity, AppTimeoutFlagLong, defaultAppTimeout, timeoutAppInactivityFlagHelp)
		flag.IntVar(&c.timeoutAppInactivity, AppTimeoutFlagShort, defaultAppTimeout, timeoutAppInactivityFlagHelp+" (shorthand)")

		flag.Var(&c.portsList, PortsFlagLong, portsListFlagHelp)
		flag.Var(&c.portsList, PortsFlagShort, portsListFlagHelp+" (shorthand)")

		flag.BoolVar(&c.ShowPortScanResults, ShowPortScanResultsFlagLong, defaultShowPortScanResults, showPortScanResultsFlagHelp)
		flag.BoolVar(&c.ShowPortScanResults, ShowPortScanResultsFlagShort, defaultShowPortScanResults, showPortScanResultsFlagHelp+" (shorthand)")

		flag.BoolVar(&c.ShowHostsWithClosedPorts, ShowHostsWithClosedPortsFlagLong, defaultShowHostsWithClosedPorts, showHostsWithClosedPortsFlagHelp)
		flag.BoolVar(&c.ShowHostsWithClosedPorts, ShowHostsWithClosedPortsFlagShort, defaultShowHostsWithClosedPorts, showHostsWithClosedPortsFlagHelp+" (shorthand)")

		flag.BoolVar(&c.ShowHostsWithValidCerts, ShowHostsWithValidCertsFlagLong, defaultShowHostsWithValidCerts, showHostsWithValidCertsFlagHelp)
		flag.BoolVar(&c.ShowHostsWithValidCerts, ShowHostsWithValidCertsFlagShort, defaultShowHostsWithValidCerts, showHostsWithValidCertsFlagHelp+" (shorthand)")

		flag.BoolVar(&c.ShowValidCerts, ShowValidCertsFlagLong, defaultShowValidCerts, showValidCertsFlagHelp)
		flag.BoolVar(&c.ShowValidCerts, ShowValidCertsFlagShort, defaultShowValidCerts, showValidCertsFlagHelp+" (shorthand)")

		flag.BoolVar(&c.ShowOverview, ShowOverviewFlagLong, defaultShowOverview, showOverviewFlagHelp)
		flag.BoolVar(&c.ShowOverview, ShowOverviewFlagShort, defaultShowOverview, showOverviewFlagHelp+" (shorthand)")

	}

	// Shared flags for all application type

	flag.Var(&c.SANsEntries, SANsEntriesFlagShort, sansEntriesFlagHelp+" (shorthand)")
	flag.Var(&c.SANsEntries, SANsEntriesFlagLong, sansEntriesFlagHelp)

	flag.IntVar(&c.AgeWarning, AgeWarningFlagShort, defaultCertExpireAgeWarning, certExpireAgeWarningFlagHelp+" (shorthand)")
	flag.IntVar(&c.AgeWarning, AgeWarningFlagLong, defaultCertExpireAgeWarning, certExpireAgeWarningFlagHelp)

	flag.IntVar(&c.AgeCritical, AgeCriticalFlagShort, defaultCertExpireAgeCritical, certExpireAgeCriticalFlagHelp+" (shorthand)")
	flag.IntVar(&c.AgeCritical, AgeCriticalFlagLong, defaultCertExpireAgeCritical, certExpireAgeCriticalFlagHelp)

	flag.IntVar(&c.timeout, TimeoutFlagShort, defaultConnectTimeout, timeoutConnectFlagHelp+" (shorthand)")
	flag.IntVar(&c.timeout, TimeoutFlagLong, defaultConnectTimeout, timeoutConnectFlagHelp)

	flag.StringVar(
		&c.LoggingLevel,
		LogLevelFlagShort,
		defaultLogLevel,
		supportedValuesFlagHelpText(logLevelFlagHelp, supportedLogLevels())+" (shorthand)",
	)
	flag.StringVar(
		&c.LoggingLevel,
		LogLevelFlagLong,
		defaultLogLevel,
		supportedValuesFlagHelpText(logLevelFlagHelp, supportedLogLevels()),
	)

	flag.BoolVar(&c.ShowVersion, VersionFlagLong, defaultDisplayVersionAndExit, versionFlagHelp)

	// Prepend a brief lead-in summary of the expected syntax and project
	// version before emitting the default Help output.
	//
	// https://stackoverflow.com/a/36787811/903870
	// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html
	flag.Usage = func() {
		headerText := fmt.Sprintf(
			usageTextHeaderTmpl,
			Version(),
			os.Args[0],
			appDescription,
		)

		footerText := fmt.Sprintf(
			"\nSee project README at %s for examples and additional details.\n",
			myAppURL,
		)

		// Override default of stderr as destination for help output. This
		// allows Nagios XI and similar monitoring systems to call plugins
		// with the `--help` flag and have it display within the Admin web UI.
		flag.CommandLine.SetOutput(os.Stdout)

		fmt.Fprintln(flag.CommandLine.Output(), headerText)
		flag.PrintDefaults()
		fmt.Fprintln(flag.CommandLine.Output(), footerText)
	}

	// parse flag definitions from the argument list
	flag.Parse()

}
