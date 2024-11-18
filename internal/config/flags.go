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

	var (
		// Application specific template used for generating lead-in
		// usage/help text.
		usageTextHeaderTmpl string

		// Additional requirements for using positional arguments. May not
		// apply to all application types.
		positionalArgRequirements string

		// A human readable description of the specific application.
		appDescription string
	)

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

		flag.BoolVar(&c.EmitPayload, PayloadFlag, defaultPayload, payloadFlagHelp)
		flag.BoolVar(&c.EmitPayloadWithFullChain, PayloadWithFullChainFlag, defaultPayloadWithFullChain, payloadWithFullChainFlagHelp)
		flag.IntVar(&c.PayloadFormatVersion, PayloadFormatVersionFlag, defaultPayloadFormatVersion, payloadFormatVersionFlagHelp)

		flag.BoolVar(&c.EmitBranding, BrandingFlag, defaultBranding, brandingFlagHelp)
		flag.BoolVar(
			&c.IgnoreHostnameVerificationFailureIfEmptySANsList,
			IgnoreHostnameVerificationFailureIfEmptySANsListFlag,
			defaultIgnoreHostnameVerificationIfEmptySANsList,
			ignoreHostnameVerificationFailureIfEmptySANsListFlagHelp,
		)

		flag.BoolVar(
			&c.IgnoreExpiredIntermediateCertificates,
			IgnoreExpiredIntermediateCertificatesFlag,
			defaultIgnoreExpiredIntermediateCertificates,
			ignoreExpiredIntermediateCertificatesFlagHelp,
		)

		flag.BoolVar(
			&c.IgnoreExpiredRootCertificates,
			IgnoreExpiredRootCertificatesFlag,
			defaultIgnoreExpiredRootCertificates,
			ignoreExpiredRootCertificatesFlagHelp,
		)

		flag.BoolVar(
			&c.IgnoreExpiringIntermediateCertificates,
			IgnoreExpiringIntermediateCertificatesFlag,
			defaultIgnoreExpiringIntermediateCertificates,
			ignoreExpiringIntermediateCertificatesFlagHelp,
		)

		flag.BoolVar(
			&c.IgnoreExpiringRootCertificates,
			IgnoreExpiringRootCertificatesFlag,
			defaultIgnoreExpiringRootCertificates,
			ignoreExpiringRootCertificatesFlagHelp,
		)

		flag.BoolVar(&c.OmitSANsEntries, OmitSANsEntriesFlagLong, defaultOmitSANsEntriesList, omitSANsEntriesFlagHelp)
		flag.BoolVar(&c.OmitSANsEntries, OmitSANsListFlagLong, defaultOmitSANsEntriesList, omitSANsListFlagHelp)

		flag.BoolVar(&c.VerboseOutput, VerboseFlagShort, defaultVerboseOutput, verboseOutputFlagHelp+shorthandFlagSuffix)
		flag.BoolVar(&c.VerboseOutput, VerboseFlagLong, defaultVerboseOutput, verboseOutputFlagHelp)

		flag.BoolVar(&c.ListIgnoredValidationCheckResultErrors, ListIgnoredErrorsFlag, defaultListIgnoredValidationCheckResultErrors, listIgnoredErrorsFlagHelp)

		flag.StringVar(&c.InputFilename, FilenameFlagLong, defaultFilename, inputFilenameFlagHelp)

		flag.StringVar(&c.Server, ServerFlagShort, defaultServer, serverFlagHelp+shorthandFlagSuffix)
		flag.StringVar(&c.Server, ServerFlagLong, defaultServer, serverFlagHelp)

		flag.StringVar(&c.DNSName, DNSNameFlagShort, defaultDNSName, dnsNameFlagHelp+shorthandFlagSuffix)
		flag.StringVar(&c.DNSName, DNSNameFlagLong, defaultDNSName, dnsNameFlagHelp)

		flag.IntVar(&c.Port, PortFlagShort, defaultPort, portFlagHelp+shorthandFlagSuffix)
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

		flag.IntVar(&c.AgeWarning, AgeWarningFlagShort, defaultCertExpireAgeWarning, certExpireAgeWarningFlagHelp+shorthandFlagSuffix)
		flag.IntVar(&c.AgeWarning, AgeWarningFlagLong, defaultCertExpireAgeWarning, certExpireAgeWarningFlagHelp)

		flag.IntVar(&c.AgeCritical, AgeCriticalFlagShort, defaultCertExpireAgeCritical, certExpireAgeCriticalFlagHelp+shorthandFlagSuffix)
		flag.IntVar(&c.AgeCritical, AgeCriticalFlagLong, defaultCertExpireAgeCritical, certExpireAgeCriticalFlagHelp)

	case appType.Inspector:

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

		positionalArgRequirements = fmt.Sprintf(
			"\nPositional Argument (\"pattern\") Requirements:\n\n"+
				"- if the %q or %q"+
				" flags are specified, the URL pattern is ignored"+
				"\n- if the %q flag is specified, its value will be"+
				" ignored if a port is provided in the given URL pattern",
			ServerFlagLong,
			FilenameFlagLong,
			PortFlagLong,
		)

		appDescription = "Used to generate a summary of certificate chain metadata and validation results for quick review."

		flag.BoolVar(&c.OmitSANsEntries, OmitSANsEntriesFlagLong, defaultOmitSANsEntriesList, omitSANsEntriesFlagHelp)
		flag.BoolVar(&c.OmitSANsEntries, OmitSANsListFlagLong, defaultOmitSANsEntriesList, omitSANsListFlagHelp)

		flag.BoolVar(&c.VerboseOutput, VerboseFlagShort, defaultVerboseOutput, verboseOutputFlagHelp+shorthandFlagSuffix)
		flag.BoolVar(&c.VerboseOutput, VerboseFlagLong, defaultVerboseOutput, verboseOutputFlagHelp)

		flag.StringVar(&c.InputFilename, FilenameFlagLong, defaultInputFilename, inputFilenameFlagHelp)
		flag.BoolVar(&c.EmitCertText, EmitCertTextFlagLong, defaultEmitCertText, emitCertTextFlagHelp)

		flag.StringVar(&c.Server, ServerFlagShort, defaultServer, serverFlagHelp+shorthandFlagSuffix)
		flag.StringVar(&c.Server, ServerFlagLong, defaultServer, serverFlagHelp)

		flag.StringVar(&c.DNSName, DNSNameFlagShort, defaultDNSName, dnsNameFlagHelp)
		flag.StringVar(&c.DNSName, DNSNameFlagLong, defaultDNSName, dnsNameFlagHelp)

		flag.IntVar(&c.Port, PortFlagShort, defaultPort, portFlagHelp+shorthandFlagSuffix)
		flag.IntVar(&c.Port, PortFlagLong, defaultPort, portFlagHelp)

		flag.IntVar(&c.AgeWarning, AgeWarningFlagShort, defaultCertExpireAgeWarning, certExpireAgeWarningFlagHelp+shorthandFlagSuffix)
		flag.IntVar(&c.AgeWarning, AgeWarningFlagLong, defaultCertExpireAgeWarning, certExpireAgeWarningFlagHelp)

		flag.IntVar(&c.AgeCritical, AgeCriticalFlagShort, defaultCertExpireAgeCritical, certExpireAgeCriticalFlagHelp+shorthandFlagSuffix)
		flag.IntVar(&c.AgeCritical, AgeCriticalFlagLong, defaultCertExpireAgeCritical, certExpireAgeCriticalFlagHelp)

	case appType.Copier:

		// Override the default Help output with a brief lead-in summary of
		// the expected syntax and project version.
		//
		// For this specific application type, flags are required unless the
		// host/url input and output filename patterns are provided, at which
		// point flags are optional. Because I'm not sure how to specify this
		// briefly, all three are listed as optional.
		//
		// https://stackoverflow.com/a/36787811/903870
		// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html
		usageTextHeaderTmpl = "%s\n\nUsage:  %s [flags] [input_pattern] [output_file]\n\n%s\n\nFlags:\n"

		positionalArgRequirements = fmt.Sprintf(
			"\nPositional Argument (\"input_pattern\" or \"output_pattern\") Requirements:\n\n"+
				"- specifying the %q, %q or %q flags together with positional"+
				" arguments is unsupported"+
				"\n- if the %q flag is specified, its value will be"+
				" ignored if a port is provided in the given URL pattern",
			ServerFlagLong,
			InputFilenameFlagLong,
			OutputFilenameFlagLong,
			PortFlagLong,
		)

		appDescription = "Used to copy and manipulate certificates."

		flag.BoolVar(&c.VerboseOutput, VerboseFlagShort, defaultVerboseOutput, verboseOutputFlagHelp+shorthandFlagSuffix)
		flag.BoolVar(&c.VerboseOutput, VerboseFlagLong, defaultVerboseOutput, verboseOutputFlagHelp)

		flag.StringVar(&c.InputFilename, InputFilenameFlagShort, defaultInputFilename, inputFilenameFlagHelp+shorthandFlagSuffix)
		flag.StringVar(&c.InputFilename, InputFilenameFlagLong, defaultInputFilename, inputFilenameFlagHelp)

		flag.StringVar(&c.OutputFilename, OutputFilenameFlagShort, defaultOutputFilename, outputFilenameFlagHelp+shorthandFlagSuffix)
		flag.StringVar(&c.OutputFilename, OutputFilenameFlagLong, defaultOutputFilename, outputFilenameFlagHelp)

		flag.Var(
			&c.certTypesToKeep,
			CertTypesToKeepFlagLong,
			supportedValuesFlagHelpText(certTypesToKeepFlagHelp, supportedCertTypeFilterKeywords()),
		)

		flag.StringVar(&c.Server, ServerFlagShort, defaultServer, serverFlagHelp+shorthandFlagSuffix)
		flag.StringVar(&c.Server, ServerFlagLong, defaultServer, serverFlagHelp)

		flag.StringVar(&c.DNSName, DNSNameFlagShort, defaultDNSName, dnsNameFlagHelp)
		flag.StringVar(&c.DNSName, DNSNameFlagLong, defaultDNSName, dnsNameFlagHelp)

		flag.IntVar(&c.Port, PortFlagShort, defaultPort, portFlagHelp+shorthandFlagSuffix)
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
		flag.IntVar(&c.timeoutPortScan, TimeoutPortScanFlagShort, defaultPortScanTimeout, timeoutPortScanFlagHelp+shorthandFlagSuffix)

		flag.Var(&c.hosts, HostsFlagLong, hostsFlagHelp)
		flag.Var(&c.hosts, HostsFlagAlt, hostsFlagHelp+" (alt name)")

		flag.IntVar(&c.ScanRateLimit, ScanRateLimitFlagLong, defaultScanRateLimit, scanRateLimitFlagHelp)
		flag.IntVar(&c.ScanRateLimit, ScanRateLimitFlagShort, defaultScanRateLimit, scanRateLimitFlagHelp+shorthandFlagSuffix)

		flag.IntVar(&c.timeoutAppInactivity, AppTimeoutFlagLong, defaultAppTimeout, timeoutAppInactivityFlagHelp)
		flag.IntVar(&c.timeoutAppInactivity, AppTimeoutFlagShort, defaultAppTimeout, timeoutAppInactivityFlagHelp+shorthandFlagSuffix)

		flag.Var(&c.portsList, PortsFlagLong, portsListFlagHelp)
		flag.Var(&c.portsList, PortsFlagShort, portsListFlagHelp+shorthandFlagSuffix)

		flag.BoolVar(&c.ShowPortScanResults, ShowPortScanResultsFlagLong, defaultShowPortScanResults, showPortScanResultsFlagHelp)
		flag.BoolVar(&c.ShowPortScanResults, ShowPortScanResultsFlagShort, defaultShowPortScanResults, showPortScanResultsFlagHelp+shorthandFlagSuffix)

		flag.BoolVar(&c.ShowHostsWithClosedPorts, ShowHostsWithClosedPortsFlagLong, defaultShowHostsWithClosedPorts, showHostsWithClosedPortsFlagHelp)
		flag.BoolVar(&c.ShowHostsWithClosedPorts, ShowHostsWithClosedPortsFlagShort, defaultShowHostsWithClosedPorts, showHostsWithClosedPortsFlagHelp+shorthandFlagSuffix)

		flag.BoolVar(&c.ShowHostsWithValidCerts, ShowHostsWithValidCertsFlagLong, defaultShowHostsWithValidCerts, showHostsWithValidCertsFlagHelp)
		flag.BoolVar(&c.ShowHostsWithValidCerts, ShowHostsWithValidCertsFlagShort, defaultShowHostsWithValidCerts, showHostsWithValidCertsFlagHelp+shorthandFlagSuffix)

		flag.BoolVar(&c.ShowValidCerts, ShowValidCertsFlagLong, defaultShowValidCerts, showValidCertsFlagHelp)
		flag.BoolVar(&c.ShowValidCerts, ShowValidCertsFlagShort, defaultShowValidCerts, showValidCertsFlagHelp+shorthandFlagSuffix)

		flag.BoolVar(&c.ShowOverview, ShowOverviewFlagLong, defaultShowOverview, showOverviewFlagHelp)
		flag.BoolVar(&c.ShowOverview, ShowOverviewFlagShort, defaultShowOverview, showOverviewFlagHelp+shorthandFlagSuffix)

		flag.IntVar(&c.AgeWarning, AgeWarningFlagShort, defaultCertExpireAgeWarning, certExpireAgeWarningFlagHelp+shorthandFlagSuffix)
		flag.IntVar(&c.AgeWarning, AgeWarningFlagLong, defaultCertExpireAgeWarning, certExpireAgeWarningFlagHelp)

		flag.IntVar(&c.AgeCritical, AgeCriticalFlagShort, defaultCertExpireAgeCritical, certExpireAgeCriticalFlagHelp+shorthandFlagSuffix)
		flag.IntVar(&c.AgeCritical, AgeCriticalFlagLong, defaultCertExpireAgeCritical, certExpireAgeCriticalFlagHelp)

	}

	// Shared flags for all application type

	flag.Var(&c.SANsEntries, SANsEntriesFlagShort, sansEntriesFlagHelp+shorthandFlagSuffix)
	flag.Var(&c.SANsEntries, SANsEntriesFlagLong, sansEntriesFlagHelp)

	flag.IntVar(&c.timeout, TimeoutFlagShort, defaultConnectTimeout, timeoutConnectFlagHelp+shorthandFlagSuffix)
	flag.IntVar(&c.timeout, TimeoutFlagLong, defaultConnectTimeout, timeoutConnectFlagHelp)

	flag.StringVar(
		&c.LoggingLevel,
		LogLevelFlagShort,
		defaultLogLevel,
		supportedValuesFlagHelpText(logLevelFlagHelp, supportedLogLevels())+shorthandFlagSuffix,
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

		_, _ = fmt.Fprintln(flag.CommandLine.Output(), headerText)
		flag.PrintDefaults()
		_, _ = fmt.Fprintln(flag.CommandLine.Output(), positionalArgRequirements)
		_, _ = fmt.Fprintln(flag.CommandLine.Output(), footerText)
	}

	// parse flag definitions from the argument list
	flag.Parse()

}
