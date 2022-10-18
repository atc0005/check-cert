// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package config

import (
	"strings"
	"time"

	"github.com/atc0005/check-cert/internal/netutils"
	"github.com/atc0005/check-cert/internal/textutils"
)

// Timeout converts the user-specified connection timeout value in
// seconds to an appropriate time duration value for use with setting
// net.Dial timeout.
func (c Config) Timeout() time.Duration {
	return time.Duration(c.timeout) * time.Second
}

// TimeoutPortScan converts the user-specified port scan timeout value in
// milliseconds to an appropriate time duration value for use with setting
// net.Dial timeout.
func (c Config) TimeoutPortScan() time.Duration {
	return time.Duration(c.timeoutPortScan) * time.Millisecond
}

// TimeoutAppInactivity converts the user-specified application inactivity
// timeout value in seconds to an appropriate time duration value for use with
// setting automatic context cancellation.
func (c Config) TimeoutAppInactivity() time.Duration {
	return time.Duration(c.timeoutAppInactivity) * time.Second
}

// CertPorts returns the user-specified list of ports to check for
// certificates or the default value if not specified.
func (c Config) CertPorts() []int {
	if c.portsList != nil {
		return c.portsList
	}

	return []int{defaultPortsListEntry}
}

// Hosts returns a list of individual IP Addresses expanded from any
// user-specified IP Addresses (single or ranges) and hostnames or FQDNs that
// passed name resolution checks.
func (c Config) Hosts() []netutils.HostPattern {
	if c.hosts.hostValues != nil {
		return c.hosts.hostValues
	}

	return []netutils.HostPattern{}
}

// ApplyCertHostnameValidationResults indicates whether hostname certificate
// hostname validation check results should be applied when performing final
// plugin state evaluation. Precedence is given for explicit request to ignore
// this validation result.
func (c Config) ApplyCertHostnameValidationResults() bool {

	ignoreRequested := textutils.InList(
		ValidationKeywordHostname, c.ignoreValidationResults, true,
	)

	applyRequested := textutils.InList(
		ValidationKeywordHostname, c.applyValidationResults, true,
	)

	switch {
	case ignoreRequested:
		return false
	case applyRequested:
		return true
	default:
		return defaultApplyCertHostnameValidationResults
	}
}

// ApplyCertExpirationValidationResults indicates whether certificate
// expiration check results should be applied when performing final plugin
// state evaluation. Precedence is given for explicit request to ignore this
// validation result.
func (c Config) ApplyCertExpirationValidationResults() bool {

	ignoreRequested := textutils.InList(
		ValidationKeywordExpiration, c.ignoreValidationResults, true,
	)

	applyRequested := textutils.InList(
		ValidationKeywordExpiration, c.applyValidationResults, true,
	)

	switch {
	case ignoreRequested:
		return false
	case applyRequested:
		return true
	default:
		return defaultApplyCertExpirationValidationResults
	}
}

// ApplyCertSANsListValidationResults indicates whether certificate SANs list
// validation check results should be applied when performing final plugin
// state evaluation. Precedence is given for explicit request to ignore this
// validation result.
func (c Config) ApplyCertSANsListValidationResults() bool {

	ignoreRequested := textutils.InList(
		ValidationKeywordSANsList, c.ignoreValidationResults, true,
	)

	applyRequested := textutils.InList(
		ValidationKeywordSANsList, c.applyValidationResults, true,
	)

	skipKeywordUsed := func() bool {
		if len(c.SANsEntries) > 0 {
			firstExpectedSANsEntry := strings.ToLower(strings.TrimSpace(c.SANsEntries[0]))
			skipKeyword := strings.ToLower(strings.TrimSpace(SkipSANSCheckKeyword))
			if firstExpectedSANsEntry == skipKeyword {
				return true
			}
		}

		return false
	}

	switch {

	// Handle explicit requests to ignore validation check results first.
	case ignoreRequested:
		return false

	// If the sysadmin specified the skip keyword, SANs validation check
	// results are ignored.
	case skipKeywordUsed():
		return false

	// Explicit requests to apply SANs list validation check results are
	// honored, but only after explicit ignore requests are processed first.
	//
	// NOTE: Config validation is expected to fail attempts to explicitly
	// apply SANs list validation if the sysadmin did not supply a list of
	// SANs entries to validate.
	case applyRequested:
		return true

	// If the sysadmin didn't specify a list of SANs entries to validate,
	// SANs validation check results are ignored.
	//
	// NOTE: Config validation asserts that this is not true if the sysadmin
	// explicitly requested SANs list validation.
	case len(c.SANsEntries) == 0:
		return false

	// Fallback to whatever the default setting if the sysadmin didn't specify
	// a value.
	default:
		return defaultApplyCertSANsListValidationResults
	}

}

// supportedValidationCheckResultKeywords returns a list of valid validation
// check keywords used by plugin type applications in this project.
func supportedValidationCheckResultKeywords() []string {
	return []string{
		ValidationKeywordHostname,
		ValidationKeywordExpiration,
		ValidationKeywordSANsList,
	}
}

// supportedLogLevels returns a list of valid log levels supported by tools in
// this project.
func supportedLogLevels() []string {
	return []string{
		LogLevelDisabled,
		LogLevelPanic,
		LogLevelFatal,
		LogLevelError,
		LogLevelWarn,
		LogLevelInfo,
		LogLevelDebug,
		LogLevelTrace,
	}
}
