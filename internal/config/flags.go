// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package config

import "flag"

// handleFlagsConfig handles toggling the exposure of specific configuration
// flags to the user. This behavior is controlled via a boolean value
// initially set by each cmd. If enabled, a smaller subset of flags specific
// to cmd binaries are exposed, otherwise the set of flags specific to a
// Nagios plugin are exposed and processed.
func (c *Config) handleFlagsConfig(isPlugin bool) {

	// Flags specific to one or the other
	switch {
	case isPlugin:
		flag.BoolVar(&c.EmitBranding, "branding", defaultBranding, brandingFlagHelp)
	case !isPlugin:
		flag.StringVar(&c.Filename, "filename", defaultFilename, filenameFlagHelp)
		flag.BoolVar(&c.EmitCertText, "text", defaultEmitCertText, emitCertTextFlagHelp)
	}

	// Shared flags

	flag.Var(&c.SANsEntries, "se", sansEntriesFlagHelp)
	flag.Var(&c.SANsEntries, "sans-entries", sansEntriesFlagHelp)

	flag.IntVar(&c.AgeWarning, "w", defaultCertExpireAgeWarning, certExpireAgeWarningFlagHelp)
	flag.IntVar(&c.AgeWarning, "age-warning", defaultCertExpireAgeWarning, certExpireAgeWarningFlagHelp)

	flag.IntVar(&c.AgeCritical, "c", defaultCertExpireAgeCritical, certExpireAgeCriticalFlagHelp)
	flag.IntVar(&c.AgeCritical, "age-critical", defaultCertExpireAgeCritical, certExpireAgeCriticalFlagHelp)

	flag.StringVar(&c.Server, "s", defaultServer, serverFlagHelp)
	flag.StringVar(&c.Server, "server", defaultServer, serverFlagHelp)

	flag.StringVar(&c.DNSName, "dn", defaultDNSName, dnsNameFlagHelp)
	flag.StringVar(&c.DNSName, "dns-name", defaultDNSName, dnsNameFlagHelp)

	flag.IntVar(&c.Port, "p", defaultPort, portFlagHelp)
	flag.IntVar(&c.Port, "port", defaultPort, portFlagHelp)

	flag.IntVar(&c.Timeout, "t", defaultTimeout, timeoutFlagHelp)
	flag.IntVar(&c.Timeout, "timeout", defaultTimeout, timeoutFlagHelp)

	flag.StringVar(&c.LoggingLevel, "ll", defaultLogLevel, logLevelFlagHelp)
	flag.StringVar(&c.LoggingLevel, "log-level", defaultLogLevel, logLevelFlagHelp)

	flag.BoolVar(&c.ShowVersion, "v", defaultDisplayVersionAndExit, versionFlagHelp)
	flag.BoolVar(&c.ShowVersion, "version", defaultDisplayVersionAndExit, versionFlagHelp)

	// Allow our function to override the default Help output
	flag.Usage = Usage

	// parse flag definitions from the argument list
	flag.Parse()

}
