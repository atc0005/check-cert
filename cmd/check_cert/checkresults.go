// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"fmt"
	"os"
)

// NagiosExitState represents the last known execution state of the
// application, including the most recent error and the final intended plugin
// state.
// TODO: Refine this further and consider moving to the atc0005/go-nagios
// package.
type NagiosExitState struct {

	// LastError is the last error encountered which should be reported as
	// part of ending the service check (e.g., "Failed to connect to XYZ to
	// check contents of Inbox").
	LastError error

	// LastError is the exit or exit status code provided to the Nagios
	// instance that calls this service check. These status codes indicate to
	// Nagios "state" the service is considered to be in. The most common
	// states are OK (0), WARNING (1) and CRITICAL (2).
	ExitStatusCode int

	// ServiceOutput is the first line of text output from the last service
	// check (i.e. "Ping OK").
	ServiceOutput string

	// LongServiceOutput is the full text output (aside from the first line)
	// from the last service check.
	LongServiceOutput string
}

// ReturnCheckResults is intended to be called with the defer keyword. Nagios
// relies on plugin exit codes to determine success/failure of checks; in
// order to safely apply a final exit code without halting normal program
// execution the defer keyword is used to allow this function to execute after
// normal program execution completes.
//
// The approach that is most often used with other languages is to use
// something like Using os.Exit() directly and force an early exit of the
// application with an explicit exit code. Using os.Exit() directly in Go does
// not run deferred functions; other Go-based plugins that do not rely on
// deferring function calls may get away with using os.Exit(), but introducing
// new dependencies could introduce problems.
//
// We attempt to explicitly allow deferred functions to work as intended
// by queuing up values as the app runs and then have this block of code
// scheduled (deferred) to process those queued values, including the
// intended plugin exit state. Since this codeblock runs as the last step
// in the application, it can safely call os.Exit() to set the desired
// exit code without blocking other deferred functions from running.
func (nes NagiosExitState) ReturnCheckResults(emitBranding bool) {

	// One-line output used as the summary or short explanation for the
	// specific Nagios state that we are returning.
	fmt.Println(nes.ServiceOutput)

	fmt.Printf("\nAdditional details:\n\n")

	// If an error occurred or if there are additional details to share ...
	switch {
	case nes.LastError != nil:
		fmt.Printf("* Error: %v\n", nes.LastError)
	case nes.LongServiceOutput != "":
		fmt.Printf("* %v\n", nes.LongServiceOutput)
	}

	os.Exit(nes.ExitStatusCode)
}
