// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
)

func heartBeatMonitor(
	ctx context.Context,
	appShutdown context.CancelFunc,
	heartBeat <-chan struct{},
	timeout time.Duration,
	log zerolog.Logger,
) {

	log.Debug().Msg("Starting heartBeatMonitor")

	// setup timer that will be used to trigger an application shutdown
	// when no activity has occurred for X seconds
	inactivityTimer := time.NewTimer(timeout)

	for {
		select {

		// allow main func's deferred cancel() func to shutdown this
		// goroutine even if the inactivity timer hasn't expired yet
		case <-ctx.Done():
			inactivityTimer.Stop()

			return

		case <-inactivityTimer.C:

			fmt.Printf("\nInactivity timer (%v) triggered.\n", timeout)
			inactivityTimer.Stop()

			fmt.Println("Shutting down application ...")
			appShutdown()

			return

		// reset timer if we received an indication that the application
		// is still running and actually doing something useful
		case <-heartBeat:
			inactivityTimer.Reset(timeout)
			log.Debug().Msg("Reset timeout")
		}
	}

}
