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
	"syscall"
	"time"

	"github.com/rs/zerolog"
)

// errRuntimeTimeoutReached indicates that plugin runtime exceeded specified
// timeout value.
var errRuntimeTimeoutReached = errors.New("plugin runtime exceeded specified timeout value")

// runtimeTimeoutReachedAdvice offers advice to the sysadmin for routine
// occurrence.
const runtimeTimeoutReachedAdvice string = "consider increasing value if this is routinely encountered"

// connectionResetByPeerAdvice offers advice to the sysadmin to check the
// certificate/port bindings when a "read: connection reset by peer" error is
// encountered. An IIS site with a missing binding has been observed in the
// field as a cause of this issue.
const connectionResetByPeerAdvice string = "consider checking certificate/port bindings (e.g., IIS Site Bindings)"

// connectionRefusedAdvice offers advice to the sysadmin to check the
// specified port and remote service state. The "connect: connection refused"
// error is often encountered when an application associated with the
// certificate being checked is stopped (e.g., troubleshooting purposes,
// replacing a certificate or the service has crashed) or if the wrong
// port was specified for a service.
const connectionRefusedAdvice string = "consider double-checking specified port and remote service state (i.e., make sure service is actually running on given port)"

// annotateError is a helper function used to add additional human-readable
// explanation for errors commonly emitted by dependencies.
//
// This function receives a logger and one or more errors, evaluates whether
// any contain specific errors in its chain and then (potentially) appends
// additional details for later use. This updated collection of error chains
// are returned to the caller, preserving any original wrapped errors.
//
// The original error collection is returned unmodified if no annotations were
// deemed necessary.
//
// Nil is returned if an empty collection or a collection of nil values are
// provided for evaluation.
func annotateError(logger zerolog.Logger, errs ...error) []error {

	funcTimeStart := time.Now()

	var errsAnnotated int
	defer func(counter *int) {
		logger.Printf(
			"It took %v to execute annotateError func (errors evaluated: %d, annotated: %d)",
			time.Since(funcTimeStart),
			len(errs),
			*counter,
		)
	}(&errsAnnotated)

	isNilErrCollection := func(collection []error) bool {
		if len(collection) != 0 {
			for _, err := range collection {
				if err != nil {
					return false
				}
			}
		}
		return true
	}

	switch {

	// Process errors as long as the collection is not empty or not composed
	// entirely of nil values.
	case !isNilErrCollection(errs):
		annotatedErrors := make([]error, 0, len(errs))

		for _, err := range errs {
			if err != nil {
				switch {
				case errors.Is(err, context.DeadlineExceeded):
					annotatedErrors = append(annotatedErrors, fmt.Errorf(
						"%w: %s; %s",
						err,
						errRuntimeTimeoutReached,
						runtimeTimeoutReachedAdvice,
					))

				case errors.Is(err, syscall.ECONNRESET):
					annotatedErrors = append(annotatedErrors, fmt.Errorf(
						"%w: %s",
						err,
						connectionResetByPeerAdvice,
					))

				case errors.Is(err, syscall.ECONNREFUSED):
					annotatedErrors = append(annotatedErrors, fmt.Errorf(
						"%w: %s",
						err,
						connectionRefusedAdvice,
					))

				default:
					// Record error unmodified if additional decoration isn't defined
					// for the error type.
					annotatedErrors = append(annotatedErrors, err)
				}
			}
		}

		return annotatedErrors

	// No errors were provided for evaluation.
	default:
		return nil
	}

}
