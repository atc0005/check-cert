// Copyright 2022 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package config

import (
	"flag"
	"fmt"
)

// handlePositionalArgs handles any positional arguments remaining after flags
// have been parsed. This behavior is controlled via the specified application
// type as set by each cmd. Based on the application type, a specific set of
// positional arguments are evaluated and potentially used to override default
// values for defined flags.
func (c *Config) handlePositionalArgs(appType AppType) error {

	// fmt.Println("Evaluating positional arguments ...")
	// fmt.Println("flag.Arg(0):", flag.Arg(0))
	// fmt.Println("flag.Args():", flag.Args())

	switch {
	case appType.Plugin:

		// placeholder

	case appType.Inspecter:

		// If flag.Arg(0) is non-empty, then flag parsing has already been
		// applied and a positional argument is available for evaluation. We
		// evaluate Arg(0) only if specific flag values have not already been
		// provided.
		//
		// This prevents overwriting any values already specified by flags in
		// order to provide the documented behavior for specified flags and
		// the URL pattern positional argument.
		if flag.Arg(0) != "" && c.Server == "" && c.Filename == "" {
			err := c.parseServerValue(flag.Arg(0))
			if err != nil {
				return fmt.Errorf(
					"error parsing server value: %w",
					err,
				)
			}
		}

	case appType.Scanner:

		// placeholder

	}

	// Shared positional argument handling for all application types goes
	// here.

	return nil

}
