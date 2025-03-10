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

func validateAgeThresholds(c Config) error {
	switch {
	case c.AgeWarning < 1:
		return fmt.Errorf(
			"invalid cert expiration WARNING threshold number: %d",
			c.AgeWarning,
		)

	case c.AgeCritical < 1:
		return fmt.Errorf(
			"invalid cert expiration CRITICAL threshold number: %d",
			c.AgeCritical,
		)

	case c.AgeCritical > c.AgeWarning:
		return fmt.Errorf(
			"critical threshold set higher than warning threshold",
		)

	case c.AgeCritical == c.AgeWarning:
		return fmt.Errorf(
			"critical threshold set equal to warning threshold",
		)

	default:
		return nil
	}
}

func validatePort(c Config) error {
	// TCP Port 0 is used by server applications to indicate that they
	// should bind to an available port. Specifying port 0 for a client
	// application is not useful.
	if c.Port <= 0 {
		return fmt.Errorf(
			"invalid TCP port number; got %d,"+
				" expected value between %d and %d (e.g., 443, 636)",
			c.Port,
			tcpSystemPortStart,
			tcpDynamicPrivatePortEnd,
		)
	}

	return nil
}

func validatePayloadFormatVersion(c Config) error {
	// Format version 0 is valid, but anything less than that is not; in order
	// to have the value set to less than zero someone has to explicitly
	// choose that value (0 is the default).
	if c.PayloadFormatVersion < 0 {
		return fmt.Errorf(
			"invalid certificate metadata payload format version %d",
			c.PayloadFormatVersion,
		)
	}

	return nil
}

// validate verifies all Config struct fields have been set to an acceptable
// state. Positional argument handling AND validation is handled earlier in
// the configuration initialization process.
func (c Config) validate(appType AppType) error {

	switch {
	case appType.Inspector:
		switch {
		case c.InputFilename == "" && c.Server == "":
			return fmt.Errorf(
				"one of %q or %q flags must be specified"+
					" or one of URL, FQDN or hostname provided"+
					" via positional argument",
				ServerFlagLong,
				FilenameFlagLong,
			)
		case c.InputFilename != "" && c.Server != "":
			return fmt.Errorf(
				"only one of %q or %q flags may be specified",
				ServerFlagLong,
				FilenameFlagLong,
			)
		}

		if err := validatePort(c); err != nil {
			return err
		}

		if err := validateAgeThresholds(c); err != nil {
			return err
		}

	case appType.Copier:

		// User can specify one of input filename or server, but not both.
		if c.InputFilename != "" && c.Server != "" {
			return fmt.Errorf(
				"only one of %q OR %q flags may be specified: %w",
				ServerFlagLong,
				InputFilenameFlagLong,
				ErrUnsupportedOption,
			)
		}

		// NOTE:
		//
		// Checking for conflicts between positional arguments and equivalent
		// flags is currently handled by the handlePositionalArgs method and
		// any helper logic it may call.

		if err := validatePort(c); err != nil {
			return err
		}

		// Assert that only supported keywords are specified.
		supportedCertTypeFilterKeywords := supportedCertTypeFilterKeywords()
		for _, specifiedKeyword := range c.certTypesToKeep {
			if !textutils.InList(specifiedKeyword, supportedCertTypeFilterKeywords, true) {
				return fmt.Errorf(
					"invalid cert type filter keyword specified; got %v, "+
						"expected one of %v: %w",
					specifiedKeyword,
					supportedCertTypeFilterKeywords,
					ErrUnsupportedOption,
				)
			}
		}

		// Assert that only valid combinations of keywords are specified; if
		// CertTypeAll is specified no other (normally valid) keywords from
		// that set are permitted.
		if textutils.InList(CertTypeAll, c.certTypesToKeep, true) {
			if len(c.certTypesToKeep) > 1 {
				otherValidVals := func() []string {
					vals := make([]string, 0, len(supportedCertTypeFilterKeywords))
					for _, val := range supportedCertTypeFilterKeywords {
						if val != CertTypeAll {
							vals = append(vals, val)
						}
					}
					return vals
				}()

				return fmt.Errorf(
					"invalid keywords combination; got %v, "+
						"expected just %q or one of %v: %w",
					c.certTypesToKeep,
					CertTypeAll,
					otherValidVals,
					ErrUnsupportedOption,
				)
			}
		}

	case appType.Plugin:
		switch {
		case c.InputFilename == "" && c.Server == "":
			return fmt.Errorf(
				"one of %q or %q flags must be specified",
				ServerFlagLong,
				FilenameFlagLong,
			)
		case c.InputFilename != "" && c.Server != "":
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

		if err := validatePort(c); err != nil {
			return err
		}

		if err := validatePayloadFormatVersion(c); err != nil {
			return err
		}

		supportedValidationKeywords := supportedValidationCheckResultKeywords()

		// Validate the specified explicit "ignore" validation check results
		// keywords
		for _, specifiedKeyword := range c.ignoreValidationResults {
			if !textutils.InList(specifiedKeyword, supportedValidationKeywords, true) {
				return fmt.Errorf(
					"invalid ignore validation results keyword specified; got %v, expected one of %v",
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
					"invalid apply validation results keyword specified; got %v, expected one of %v",
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

		if err := validateAgeThresholds(c); err != nil {
			return err
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

		if err := validateAgeThresholds(c); err != nil {
			return err
		}

		// TODO: Figure out how to (or if we need to) validate mix of boolean
		// value "show" flags
	}

	if c.Timeout() < 0 {
		return fmt.Errorf("invalid timeout value %d provided", c.Timeout())
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
