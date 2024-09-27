// Copyright 2022 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func (c *Config) validatePositionalArgs(appType AppType) error {
	switch {
	case appType.Plugin:

		// placeholder

	case appType.Inspector:

		// placeholder

	case appType.Copier:

		switch {
		// User opted to use positional argument for INPUT_PATTERN and one of
		// the associated flags for that value.
		case (c.InputFilename != "" || c.Server != "") && flag.Arg(0) != "":
			return fmt.Errorf(
				"one of %q or %q flags may be specified"+
					" OR one of filename, URL, FQDN or hostname provided"+
					" via first positional argument: %w",
				ServerFlagLong,
				InputFilenameFlagLong,
				ErrUnsupportedOption,
			)

		// User opted to use positional argument for OUTPUT_PATTERN and the
		// associated flag for that value.
		case c.OutputFilename != "" && flag.Arg(1) != "":
			return fmt.Errorf(
				"output filename may only be specified via one of %q flag "+
					"OR second positional argument: %w",
				OutputFilenameFlagLong,
				ErrUnsupportedOption,
			)

		case c.OutputFilename == "" && flag.Arg(1) == "":
			return fmt.Errorf(
				"output filename is required via %q flag "+
					"OR second positional argument: %w",
				OutputFilenameFlagLong,
				ErrUnsupportedOption,
			)

		}

	case appType.Scanner:

		// placeholder

	}

	// Shared positional argument handling for all application types goes
	// here.

	return nil
}

// handlePositionalArgs handles any positional arguments remaining after flags
// have been parsed. This behavior is controlled via the specified application
// type as set by each cmd. Based on the application type, a specific set of
// positional arguments are evaluated.
//
// Responsibility for validating flags and positional arguments is shared
// between this helper function and the validate method.
func (c *Config) handlePositionalArgs(appType AppType) error {

	// fmt.Println("Evaluating positional arguments ...")
	// fmt.Println("flag.Arg(0):", flag.Arg(0))
	// fmt.Println("flag.Args():", flag.Args())

	if err := c.validatePositionalArgs(appType); err != nil {
		return err
	}

	switch {
	case appType.Plugin:

		// placeholder

	case appType.Inspector:

		// If flag.Arg(0) is non-empty, then flag parsing has already been
		// applied and a positional argument is available for evaluation. We
		// evaluate Arg(0) only if specific flag values have not already been
		// provided.
		//
		// This prevents overwriting any values already specified by flags in
		// order to provide the documented behavior for specified flags and
		// the URL pattern positional argument.
		if flag.Arg(0) != "" && c.Server == "" && c.InputFilename == "" {
			err := c.parseServerValue(flag.Arg(0))
			if err != nil {
				return fmt.Errorf(
					"error parsing server value: %w",
					err,
				)
			}
		}

	case appType.Copier:

		// If flag.Arg(0) for INPUT_PATTERN is non-empty, then flag parsing
		// has already been applied and a positional argument is available for
		// evaluation.
		if flag.Arg(0) != "" {
			c.PosArgInputPattern = flag.Arg(0)

			cleanPath := filepath.Clean(flag.Arg(0))

			if _, err := os.Stat(cleanPath); err == nil {
				c.InputFilename = cleanPath
			} else if errors.Is(err, os.ErrNotExist) {
				err := c.parseServerValue(flag.Arg(0))
				if err != nil {
					// While we check for it, parsing is *very* liberal and
					// unlikely to trigger an error condition.
					return fmt.Errorf(
						"error parsing input pattern as server value or filename: %w",
						ErrInvalidPosArgPattern,
					)
				}
			}
		}

		// If flag.Arg(1) for OUTPUT_FILE is non-empty, then flag parsing has
		// already been applied and a second positional argument is available
		// for evaluation.
		if flag.Arg(1) != "" {
			c.PosArgOutputPattern = flag.Arg(1)
			c.OutputFilename = c.PosArgOutputPattern
		}

	case appType.Scanner:

		// placeholder

	}

	// Shared positional argument handling for all application types goes
	// here.

	return nil

}
