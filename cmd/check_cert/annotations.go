// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	// "syscall"

	"github.com/atc0005/go-nagios"
)

// connectionResetByPeerAdvice offers advice to the sysadmin to check the
// certificate/port bindings when a "read: connection reset by peer" error is
// encountered. An IIS site with a missing binding has been observed in the
// field as a cause of this issue.
// const connectionResetByPeerAdvice string = "consider checking certificate/port bindings (e.g., IIS Site Bindings)"

// annotateError is a helper function used to add additional human-readable
// explanation for errors encountered during plugin execution. We first apply
// common advice for more general errors then apply advice specific to errors
// routinely encountered by this specific project.
func annotateErrors(plugin *nagios.Plugin) {
	// If nothing to process, skip setup/processing steps.
	if len(plugin.Errors) == 0 {
		return
	}

	// Start off with the default advice collection.
	errorAdviceMap := nagios.DefaultErrorAnnotationMappings()

	// Override specific error with project-specific feedback.
	// errorAdviceMap[syscall.ECONNRESET] = connectionResetByPeerAdvice

	// Apply error advice annotations.
	plugin.AnnotateRecordedErrors(errorAdviceMap)
}
