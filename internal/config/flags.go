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

	// Flags specific to one application type or the other
	switch {
	case appType.Plugin:
		flag.BoolVar(&c.EmitBranding, BrandingFlag, defaultBranding, brandingFlagHelp)
		flag.BoolVar(
			&c.IgnoreHostnameVerificationFailureIfEmptySANsList,
			IgnoreHostnameVerificationFailureIfEmptySANsListFlag,
			defaultIgnoreHostnameVerificationIfEmptySANsList,
			ignoreHostnameVerificationFailureIfEmptySANsListFlagHelp,
		)

		// DEPRECATED flag support. This is an alias for a previous stable
		// release. Slated for removal in v0.9.0 release per GH-356.
		flag.BoolVar(
			&c.IgnoreHostnameVerificationFailureIfEmptySANsList,
			DisableHostnameVerificationFailureIfEmptySANsListFlag,
			defaultIgnoreHostnameVerificationIfEmptySANsList,
			disableHostnameVerificationFailureIfEmptySANsListFlagHelp,
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

	// Allow our function to override the default Help output
	flag.Usage = Usage

	// parse flag definitions from the argument list
	flag.Parse()

}
