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

// parseServerValue evaluates a given string as a potential URL. If matched,
// the URL is used to populate the Config.Server field. If the URL specifies a
// port, the parsed port value is used to populate the Config.Port field. If
// the given string is not parsed as a URL, the value is assigned directly to
// the Config.Server field as-is.
//
// The caller is responsible for guarding against overwriting any values
// already specified by flags.
func (c *Config) parseServerValue(serverVal string) error {

	// url.Parse() is very forgiving. A bare string value (e.g., "tacos") is
	// treated as a relative URL or "path" value. In other words, a parse
	// error is sufficient reason to abort further evaluation of the given
	// server value.
	u, err := url.Parse(serverVal)
	if err != nil {
		return fmt.Errorf(
			"unable to parse %q as URL: %w",
			serverVal,
			err,
		)
	}

	// We're populating the Config struct *before* validation is applied. As a
	// result, we assign directly to the Config struct fields that are
	// normally populated by specific flags.
	switch {

	// If the specified server value was successfully parsed as a URL with a
	// hostname value we use that value to populate the Config.Server field
	// and potentially the Config.Port field.
	case u.Host != "":

		switch {
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
	// relative URL) we use the specified server value as-is and assign
	// directly to the Config.Server field.
	default:

		c.Server = serverVal

	}

	return nil

}
