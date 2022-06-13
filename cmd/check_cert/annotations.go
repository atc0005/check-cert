// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"
)

// errRuntimeTimeoutReached indicates that plugin runtime exceeded specified
// timeout value.
var errRuntimeTimeoutReached = errors.New("plugin runtime exceeded specified timeout value")

// runtimeTimeoutReachedAdvice offers advice to the sysadmin for routine
// occurrence.
const runtimeTimeoutReachedAdvice string = "consider increasing value if this is routinely encountered"

// annotateError is a helper function used to add additional human-readable
// explanation for errors commonly emitted by dependencies. This function
// receives an error, evaluates whether it contains specific errors in its
// chain and then (potentially) appends additional details for later use. This
// updated error chain is returned to the caller, preserving the original
// wrapped error. The original error is returned unmodified if no annotations
// were deemed necessary.
func annotateError(err error, logger zerolog.Logger) error {

	funcTimeStart := time.Now()

	defer func() {
		logger.Printf(
			"It took %v to execute annotateError func.",
			time.Since(funcTimeStart),
		)
	}()

	switch {

	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf(
			"%w: %s; %s",
			err,
			errRuntimeTimeoutReached,
			runtimeTimeoutReachedAdvice,
		)

	default:

		// Return error unmodified if additional decoration isn't defined for the
		// error type.
		return err

	}

}
