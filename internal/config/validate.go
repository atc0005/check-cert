// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package config

import (
	"fmt"
	"strings"
)

// validate verifies all Config struct fields have been provided acceptable
// values.
func (c Config) validate(isPlugin bool) error {

	// Server or Filename verification, depending on whether we are validating
	// settings for a Nagios plugin.
	switch {

	case !isPlugin:
		// User can specify one of filename or server, but not both (mostly in
		// order to keep the logic simpler)
		switch {
		case c.Filename == "" && c.Server == "":
			return fmt.Errorf(
				"one of %q or %q flags must be specified",
				"server",
				"filename",
			)
		case c.Filename != "" && c.Server != "":
			return fmt.Errorf(
				"only one of %q or %q flags may be specified",
				"server",
				"filename",
			)
		}

	case isPlugin:
		// Always required, even if using the DNSName value for hostname
		// verification
		if c.Server == "" {
			return fmt.Errorf("server FQDN not provided")
		}
	}

	if c.Port < 0 {
		return fmt.Errorf("invalid TCP port number %d", c.Port)
	}

	if c.Timeout < 0 {
		return fmt.Errorf("invalid timeout value %d provided", c.Timeout)
	}

	if c.AgeWarning < 0 {
		return fmt.Errorf(
			"invalid cert expiration WARNING threshold number: %d",
			c.AgeWarning,
		)
	}

	if c.AgeCritical < 0 {
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

	requestedLoggingLevel := strings.ToLower(c.LoggingLevel)
	if _, ok := loggingLevels[requestedLoggingLevel]; !ok {
		return fmt.Errorf("invalid logging level %q", c.LoggingLevel)
	}

	// Optimist
	return nil

}
