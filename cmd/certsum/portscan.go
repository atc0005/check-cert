// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"sync"
	"time"

	"github.com/atc0005/check-certs/internal/netutils"
	"github.com/rs/zerolog"
)

// certScanCollector is called as a goroutine prior to launching the port
// scanner function, also as a goroutine. This goroutine continues to
// run until all results are collected.
func portScanCollector(
	resultsIdx netutils.PortCheckResultsIndex,
	results <-chan netutils.PortCheckResult,
	log zerolog.Logger,
	wg *sync.WaitGroup,
) {

	log.Debug().Msg("starting collector routine")

	// help ensure that we don't forget to signal that we're done
	defer wg.Done()

	// Receive check results, update index
	for checkResult := range results {

		log.Debug().Msgf(
			"Adding results for %v to index",
			checkResult.IPAddress.String(),
		)

		// grow the index of IP Address to port scan results for later review
		resultsIdx[checkResult.IPAddress.String()] = append(
			resultsIdx[checkResult.IPAddress.String()],
			checkResult,
		)
	}

	log.Debug().Msg("exiting collector routine")

}

// portScanner is called as a goroutine after launching the port scan
// collector goroutine. This function performs a port scan against all
// user-specified ports and returns the results of those scan attempts on a
// channel that the collector goroutine monitors. This goroutine continues to
// run until all ports are checked, either successfully or once a specified
// timeout is reached.
func portScanner(
	ips []string,
	ports []int,
	timeout time.Duration,
	results chan<- netutils.PortCheckResult,
	rateLimiter chan struct{}, // needs to allow send & receive
	log zerolog.Logger,
	wg *sync.WaitGroup,
) {

	log.Debug().Msg("Launching port scanner goroutine")

	// caller sets this just before calling this function
	defer wg.Done()

	for _, ip := range ips {

		log.Debug().Msgf("Checking IP: %v", ip)

		for _, port := range ports {

			log.Debug().Msgf("Checking port %v for IP: %v", port, ip)

			// indicate that we are launching a goroutine that will be tracked
			// and reserve a spot in the (limited) channel
			wg.Add(1)
			rateLimiter <- struct{}{}

			go func(
				ipAddr string,
				port int,
				scanTimeout time.Duration,
				results chan<- netutils.PortCheckResult,
				rateLimiter chan struct{},
				log zerolog.Logger,
			) {

				// make sure we give up our spot when finished
				defer func() {
					// indicate that we're done with this goroutine
					wg.Done()

					// release spot for next (held back) goroutine to run
					<-rateLimiter
				}()

				portState := netutils.CheckPort(ipAddr, port, scanTimeout)
				if portState.Err != nil {
					// TODO: Check specific error type to determine how to
					// proceed. For now, we'll just assume that we're dealing
					// with a timeout, emit the error as a debug message and
					// continue.
					log.Debug().
						Str("host", ipAddr).
						Int("port", port).
						Err(portState.Err).
						Msg("")
				}

				log.Debug().Msg("Sending result back on channel")

				results <- portState

				log.Debug().Msg("Sent result on channel, proceeding")

				// if portState.Open {
				// 	fmt.Printf("%v: port %v open\n", ipAddr, port)
				// }

			}(ip, port, timeout, results, rateLimiter, log)
		}
	}

	log.Debug().Msg("Finished wrapper port scanner goroutine")

}
