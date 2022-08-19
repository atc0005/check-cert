// Copyright 2022 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package config

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// parseServerValue evaluates a given string as a potential URL.
//
// If the given string does not fail parsing, but is not found to be a valid
// URL the given string is assigned directly to the Config.Server field as-is
// for later evaluation.
//
// If matched, the parsed host value is used to populate the Config.Server
// field and the parsed port value (if available) is used to populate the
// Config.Port field.
//
// The caller is responsible for guarding against overwriting any values
// already specified by flags in order to provide the documented behavior for
// specified flags and the URL pattern positional argument.
func (c *Config) parseServerValue(serverVal string) error {

	// url.Parse() is very forgiving. All known "valid" values are
	// successfully parsed:
	//
	// - bare hostname (shortname)
	// - bare FQDN
	// - IP Address
	// - valid URL pattern with scheme, but without port
	// - valid URL pattern with scheme and port
	//
	// Because url.Parse() is so forgiving, a parse error of any kind is
	// sufficient cause to abort further evaluation of a given pattern.
	u, err := url.Parse(serverVal)
	if err != nil {
		return fmt.Errorf(
			"unable to parse %q as URL: %w",
			serverVal,
			err,
		)
	}

	// A bare string value (e.g., "tacos") provided as a URL pattern is
	// treated as a relative URL or "path" value, but does not result in the
	// Host field being populated. We can use that parsing behavior to
	// determine whether a given pattern should be further evaluated or used
	// as-is for later validation.
	switch {

	case u.Host != "":

		switch {

		// If the specified server value was successfully parsed as a URL with
		// a host value it may contain an optional separator + port pattern.
		// We need to remove the separator and port from the host value before
		// we record it as the server value for later validation.
		case strings.Contains(u.Host, ":"):

			// Remove any :port pattern from u.Host by splitting on
			// ':' and throwing away the second portion.
			uHost := strings.Split(u.Host, ":")

			// Prevent invalid indexing
			if len(uHost) > 0 {
				c.Server = uHost[0]
			}

		default:

			c.Server = u.Host
		}

		if u.Port() != "" {
			uPort, err := strconv.Atoi(u.Port())
			if err != nil {
				return fmt.Errorf(
					"failed to parse %q as port number: %w",
					u.Port(),
					err,
				)
			}

			// NOTE: Config validation will apply bounds checks for
			// integer port value (1:65535).
			c.Port = uPort
		}

	// If the specified server value was successfully parsed as a URL without
	// a hostname value (in which case the server value is treated as a
	// relative URL) we record the specified server value as-is for later
	// validation.
	default:

		c.Server = serverVal

	}

	return nil

}
