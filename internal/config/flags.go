// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package config

import "flag"

// handleFlagsConfig handles toggling the exposure of specific configuration
// flags to the user. This behavior is controlled via the specified
// application type as set by each cmd. Based on the application type, a
// smaller subset of flags specific to each type are exposed along with a set
// common to all application types.
func (c *Config) handleFlagsConfig(appType AppType) {

	// Flags specific to one application type or the other
	switch {
	case appType.Plugin:
		flag.BoolVar(&c.EmitBranding, "branding", defaultBranding, brandingFlagHelp)

		flag.StringVar(&c.Server, "s", defaultServer, serverFlagHelp+" (shorthand)")
		flag.StringVar(&c.Server, "server", defaultServer, serverFlagHelp)

		flag.StringVar(&c.DNSName, "dn", defaultDNSName, dnsNameFlagHelp)
		flag.StringVar(&c.DNSName, "dns-name", defaultDNSName, dnsNameFlagHelp)

		flag.IntVar(&c.Port, "p", defaultPort, portFlagHelp+" (shorthand)")
		flag.IntVar(&c.Port, "port", defaultPort, portFlagHelp)

	case appType.Inspecter:
		flag.StringVar(&c.Filename, "filename", defaultFilename, filenameFlagHelp)
		flag.BoolVar(&c.EmitCertText, "text", defaultEmitCertText, emitCertTextFlagHelp)

		flag.StringVar(&c.Server, "s", defaultServer, serverFlagHelp+" (shorthand)")
		flag.StringVar(&c.Server, "server", defaultServer, serverFlagHelp)

		flag.StringVar(&c.DNSName, "dn", defaultDNSName, dnsNameFlagHelp)
		flag.StringVar(&c.DNSName, "dns-name", defaultDNSName, dnsNameFlagHelp)

		flag.IntVar(&c.Port, "p", defaultPort, portFlagHelp+" (shorthand)")
		flag.IntVar(&c.Port, "port", defaultPort, portFlagHelp)

	case appType.Scanner:
		flag.IntVar(&c.timeoutPortScan, "scan-timeout", defaultPortScanTimeout, timeoutPortScanFlagHelp)
		flag.IntVar(&c.timeoutPortScan, "st", defaultPortScanTimeout, timeoutPortScanFlagHelp+" (shorthand)")

		flag.Var(&c.CIDRRange, "cidr-ip-range", cidrRangeFlagHelp)
		flag.Var(&c.CIDRRange, "cir", cidrRangeFlagHelp+" (shorthand)")

		flag.IntVar(&c.PortScanRateLimit, "scan-rate-limit", defaultPortScanRateLimit, portScanRateLimitFlagHelp)
		flag.IntVar(&c.PortScanRateLimit, "srl", defaultPortScanRateLimit, portScanRateLimitFlagHelp+" (shorthand)")

		flag.Var(&c.portsList, "ports", portsListFlagHelp)
		flag.Var(&c.portsList, "p", portsListFlagHelp+" (shorthand)")

		flag.BoolVar(&c.ShowPortScanResults, "show-port-scan-results", defaultShowPortScanResults, showPortScanResultsFlagHelp)
		flag.BoolVar(&c.ShowPortScanResults, "spsr", defaultShowPortScanResults, showPortScanResultsFlagHelp+" (shorthand)")

		flag.BoolVar(&c.ShowHostsWithClosedPorts, "show-closed-ports", defaultShowHostsWithClosedPorts, showHostsWithClosedPortsFlagHelp)
		flag.BoolVar(&c.ShowHostsWithClosedPorts, "scp", defaultShowHostsWithClosedPorts, showHostsWithClosedPortsFlagHelp+" (shorthand)")

		flag.BoolVar(&c.ShowHostsWithValidCerts, "show-hosts-with-valid-certs", defaultShowHostsWithValidCerts, showHostsWithValidCertsFlagHelp)
		flag.BoolVar(&c.ShowHostsWithValidCerts, "shwvc", defaultShowHostsWithValidCerts, showHostsWithValidCertsFlagHelp+" (shorthand)")

		flag.BoolVar(&c.ShowValidCerts, "show-valid-certs", defaultShowValidCerts, showValidCertsFlagHelp)
		flag.BoolVar(&c.ShowValidCerts, "svc", defaultShowValidCerts, showValidCertsFlagHelp+" (shorthand)")

		flag.BoolVar(&c.ShowOverview, "show-overview", defaultShowOverview, showOverviewFlagHelp)
		flag.BoolVar(&c.ShowOverview, "so", defaultShowOverview, showOverviewFlagHelp+" (shorthand)")

	}

	// Shared flags for all application type

	flag.Var(&c.SANsEntries, "se", sansEntriesFlagHelp)
	flag.Var(&c.SANsEntries, "sans-entries", sansEntriesFlagHelp)

	flag.IntVar(&c.AgeWarning, "w", defaultCertExpireAgeWarning, certExpireAgeWarningFlagHelp)
	flag.IntVar(&c.AgeWarning, "age-warning", defaultCertExpireAgeWarning, certExpireAgeWarningFlagHelp)

	flag.IntVar(&c.AgeCritical, "c", defaultCertExpireAgeCritical, certExpireAgeCriticalFlagHelp)
	flag.IntVar(&c.AgeCritical, "age-critical", defaultCertExpireAgeCritical, certExpireAgeCriticalFlagHelp)

	flag.IntVar(&c.timeout, "t", defaultTimeout, timeoutFlagHelp)
	flag.IntVar(&c.timeout, "timeout", defaultTimeout, timeoutFlagHelp)

	flag.StringVar(&c.LoggingLevel, "ll", defaultLogLevel, logLevelFlagHelp)
	flag.StringVar(&c.LoggingLevel, "log-level", defaultLogLevel, logLevelFlagHelp)

	flag.BoolVar(&c.ShowVersion, "v", defaultDisplayVersionAndExit, versionFlagHelp)
	flag.BoolVar(&c.ShowVersion, "version", defaultDisplayVersionAndExit, versionFlagHelp)

	// Allow our function to override the default Help output
	flag.Usage = Usage

	// parse flag definitions from the argument list
	flag.Parse()

}
