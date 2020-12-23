// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/atc0005/check-certs/internal/certs"
	"github.com/atc0005/check-certs/internal/netutils"
	"github.com/rs/zerolog"
)

// certScanCollector is called as a goroutine prior to launching the cert
// scanner function, also as a goroutine. This goroutine continues to run
// until all results are collected.
func certScanCollector(
	discoveredCertChains *certs.DiscoveredCertChains,
	results <-chan certs.DiscoveredCertChain,
	wg *sync.WaitGroup) {

	// help ensure that we don't forget to signal that we're done
	defer wg.Done()

	for result := range results {
		*discoveredCertChains = append(*discoveredCertChains, result)
	}
}

// certScanner is called as a goroutine after launching the cert scan
// collector goroutine. This function performs a certificate chain check
// against all specified ports that were previously found to be open and
// returns the results of those checks on a channel that the collector
// goroutine monitors. This goroutine continues to run until all open ports
// are checked, either successfully or once a specified timeout is reached.
func certScanner(
	resultsIndex netutils.PortCheckResultsIndex,
	showHostsWithClosedPorts bool,
	showPortScanResults bool,
	timeout time.Duration,
	results chan<- certs.DiscoveredCertChain,
	rateLimiter chan struct{}, // needs to allow send & receive
	log zerolog.Logger,
	wg *sync.WaitGroup,
) {

	// caller sets this just before calling this function
	defer wg.Done()

	for host, checkResults := range resultsIndex {

		// unless user opted to show hosts with *all* closed ports, skip the
		// host and continue to the next one
		if !showHostsWithClosedPorts && !checkResults.HasOpenPort() {
			continue
		}

		switch {
		case showPortScanResults:
			portSummary := func() string {
				if checkResults.HasOpenPort() {
					return checkResults.Summary()
				}
				return "None"
			}()

			// 192.168.1.2: [443: true, 636: false]
			fmt.Printf("%s: [%s]\n", host, portSummary)
		default:
			fmt.Printf(".")
		}

		for _, result := range checkResults {
			if result.Open {

				wg.Add(1)
				rateLimiter <- struct{}{}

				go func(
					ipAddr string,
					port int,
					timeout time.Duration,
					results chan<- certs.DiscoveredCertChain,
					log zerolog.Logger,
				) {

					// make sure we give up our spot when finished
					defer func() {
						// indicate that we're done with this goroutine
						wg.Done()

						// release spot for next (held back) goroutine to run
						<-rateLimiter
					}()

					var certFetchErr error
					certChain, certFetchErr := netutils.GetCerts(
						ipAddr,
						port,
						timeout,
						log,
					)
					if certFetchErr != nil {
						if !showPortScanResults {
							// will need to insert a newline in-between error
							// output if we're not showing port summary results
							fmt.Println()
						}
						log.Error().
							Err(certFetchErr).
							Str("host", result.IPAddress.String()).
							Int("port", result.Port).
							Msg("error fetching certificates chain")

						// os.Exit(1)
						// TODO: Decide whether fetch errors are critical or just warning level

						return
					}

					results <- certs.DiscoveredCertChain{
						Host:  result.IPAddress.String(),
						Port:  result.Port,
						Certs: certChain,
					}

				}(result.IPAddress.String(), result.Port, timeout, results, log)

			}

		}

	}

}
