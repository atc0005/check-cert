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
func (c Config) validate(appType AppType) error {

	switch {
	case appType.Inspecter:
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

	case appType.Plugin:
		// Always required, even if using the DNSName value for hostname
		// verification
		if c.Server == "" {
			return fmt.Errorf("server FQDN or IP Address not provided")
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
		if c.TimeoutPortScan() < 1 {
			return fmt.Errorf(
				"invalid port check timeout value provided: %d",
				c.TimeoutPortScan(),
			)
		}

		if c.PortScanRateLimit < 1 {
			return fmt.Errorf(
				"invalid port scan rate limit value provided: %d",
				c.TimeoutPortScan(),
			)
		}

		// NOTE: It is likely that we'll use a different flag later in order
		// to accept a mix of single, CIDR range, and a standard
		// start-finish range of IP Addresses.
		// if c.CIDRRange == "" {
		// 	return fmt.Errorf("CIDR IP range not provided")
		// }
		if c.CIDRRange == nil {
			return fmt.Errorf("CIDR IP range(s) not provided")
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
