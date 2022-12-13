// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package config

import (
	"fmt"
	"time"

	"github.com/atc0005/check-cert/internal/textutils"
)

// validate verifies all Config struct fields have been provided acceptable
// values.
func (c Config) validate(appType AppType) error {

	switch {
	case appType.Inspector:
		// User can specify one of filename or server, but not both (mostly in
		// order to keep the logic simpler)
		switch {
		case c.Filename == "" && c.Server == "":
			return fmt.Errorf(
				"one of %q or %q flags must be specified"+
					" or one of URL, FQDN or hostname provided"+
					" via positional argument",
				ServerFlagLong,
				FilenameFlagLong,
			)
		case c.Filename != "" && c.Server != "":
			return fmt.Errorf(
				"only one of %q or %q flags may be specified",
				ServerFlagLong,
				FilenameFlagLong,
			)
		}

	case appType.Plugin:
		// User can specify one of filename or server, but not both (mostly in
		// order to keep the logic simpler)
		switch {
		case c.Filename == "" && c.Server == "":
			return fmt.Errorf(
				"one of %q or %q flags must be specified",
				ServerFlagLong,
				FilenameFlagLong,
			)
		case c.Filename != "" && c.Server != "":
			return fmt.Errorf(
				"only one of %q or %q flags may be specified; if evaluating"+
					" certificate files use the %q flag instead of the %q"+
					" flag or opt to ignore hostname validation results"+
					" via the %q flag and %q keyword instead",
				ServerFlagLong,
				FilenameFlagLong,
				DNSNameFlagLong,
				ServerFlagLong,
				IgnoreValidationResultFlag,
				ValidationKeywordHostname,
			)
		}

		supportedValidationKeywords := supportedValidationCheckResultKeywords()

		// Validate the specified explicit "ignore" validation check results
		// keywords
		for _, specifiedKeyword := range c.ignoreValidationResults {
			if !textutils.InList(specifiedKeyword, supportedValidationKeywords, true) {
				return fmt.Errorf(
					"invalid ignore validation results keyword specified;"+
						" got %v, expected one of %v",
					specifiedKeyword,
					supportedValidationKeywords,
				)
			}
		}

		// Validate the specified explicit "apply" validation check results
		// keywords
		for _, specifiedKeyword := range c.applyValidationResults {
			if !textutils.InList(specifiedKeyword, supportedValidationKeywords, true) {
				return fmt.Errorf(
					"invalid apply validation results keyword specified;"+
						" got %v, expected one of %v",
					specifiedKeyword,
					supportedValidationKeywords,
				)
			}
		}

		// If we have explicit apply AND explicit ignore keywords ...
		if len(c.applyValidationResults) > 0 && len(c.ignoreValidationResults) > 0 {

			// Assert that the same keyword is not present in both explicit
			// apply and explicit ignore flag values.
			for _, keyword := range supportedValidationKeywords {
				if textutils.InList(keyword, c.applyValidationResults, true) &&
					textutils.InList(keyword, c.ignoreValidationResults, true) {
					return fmt.Errorf(
						"specified validation keyword %q was specified as"+
							" value for multiple flags;"+
							" keyword may be used with only one of %q or %q"+
							" flags",
						keyword,
						IgnoreValidationResultFlag,
						ApplyValidationResultFlag,
					)
				}
			}
		}

		// If the sysadmin explicitly requested that SANs list validation
		// check results be applied, but did not provide a SANs entries list
		// to use for validation we can't perform SANs list validation.
		//
		// The default behavior is to perform SANs list validation *if* a list
		// of SANs entries to validate is provided.
		if textutils.InList(ValidationKeywordSANsList, c.applyValidationResults, true) {
			if len(c.SANsEntries) == 0 {
				return fmt.Errorf(
					"unsupported setting for certificate SANs list validation;"+
						" providing SANs entries via the %q flag is required"+
						" when specifying the %q keyword via the %q flag",
					SANsEntriesFlagLong,
					ValidationKeywordSANsList,
					ApplyValidationResultFlag,
				)
			}
		}

	case appType.Scanner:

		// Use getter method in order to validate final ports list. Because we
		// have made this flag optional, we can't assert that the field value
		// itself is non-empty.
		if c.CertPorts() == nil {
			return fmt.Errorf("ports list (one or many) not provided")
		}

		// Use getter method here in order to validate conversion results.
		// Require that *at least* 1 ms be given as the timeout.
		if c.TimeoutPortScan() < (time.Duration(1) * time.Millisecond) {
			return fmt.Errorf(
				"invalid port check timeout value provided: %v (%v)",
				c.timeoutPortScan,
				fmt.Sprintf("%v", c.TimeoutPortScan()),
			)
		}

		// Use getter method here in order to validate conversion results.
		// Require that *at least* 2 seconds be given as the timeout.
		if c.TimeoutAppInactivity() < (time.Duration(2) * time.Second) {
			return fmt.Errorf(
				"invalid application timeout value provided: %v (%v)",
				c.timeoutAppInactivity,
				fmt.Sprintf("%v", c.TimeoutAppInactivity()),
			)
		}

		switch {
		case c.ScanRateLimit < 1:
			return fmt.Errorf(
				"invalid scan rate limit value provided: %d",
				c.ScanRateLimit,
			)

		// TODO: confirmed on Windows 10 WSLv1; may need to dynamically
		// determine the max value based on OS API query
		case c.ScanRateLimit >= 10000:
			return fmt.Errorf(
				"unreliable value provided; too high values result in 'too many open files' OS errors: %d",
				c.ScanRateLimit,
			)
		}

		if c.ScanRateLimit < 1 {
			return fmt.Errorf(
				"invalid port scan rate limit value provided: %d",
				c.ScanRateLimit,
			)
		}

		if c.Hosts() == nil {
			return fmt.Errorf("host values (one or many, single or IP Address ranges) not provided")
		}

		// TODO: Figure out how to (or if we need to) validate mix of boolean
		// value "show" flags
	}

	if c.Port < 0 {
		return fmt.Errorf("invalid TCP port number %d", c.Port)
	}

	if c.Timeout() < 0 {
		return fmt.Errorf("invalid timeout value %d provided", c.Timeout())
	}

	if c.AgeWarning < 1 {
		return fmt.Errorf(
			"invalid cert expiration WARNING threshold number: %d",
			c.AgeWarning,
		)
	}

	if c.AgeCritical < 1 {
		return fmt.Errorf(
			"invalid cert expiration CRITICAL threshold number: %d",
			c.AgeCritical,
		)
	}

	if c.AgeCritical > c.AgeWarning {
		return fmt.Errorf(
			"critical threshold set higher than warning threshold",
		)
	}

	if c.AgeCritical == c.AgeWarning {
		return fmt.Errorf(
			"critical threshold set equal to warning threshold",
		)
	}

	// Validate the specified logging level
	supportedLogLevels := supportedLogLevels()
	if !textutils.InList(c.LoggingLevel, supportedLogLevels, true) {
		return fmt.Errorf(
			"invalid logging level;"+
				" got %v, expected one of %v",
			c.LoggingLevel,
			supportedLogLevels,
		)
	}

	// Optimist
	return nil

}
