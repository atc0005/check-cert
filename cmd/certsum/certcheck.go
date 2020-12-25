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
	ctx context.Context,
	discoveredCertChains *certs.DiscoveredCertChains,
	certScanResultsChan <-chan certs.DiscoveredCertChain,
	log zerolog.Logger,
	wg *sync.WaitGroup,
) {

	// help ensure that we don't forget to signal that we're done
	defer func() {
		wg.Done()
		log.Debug().
			Int("certs_found", len(*discoveredCertChains)).
			Msg("certScanCollector finished")
	}()

	for {
		select {

		case <-ctx.Done():

			errMsg := "certScanCollector: context cancelled or expired"
			log.Debug().
				Err(ctx.Err()).
				Msg(errMsg)

			return

		case result, openChan := <-certScanResultsChan:

			if !openChan {

				// TODO: Does openChan go false with result having a valid value?
				if result.Certs != nil || result.Host != "" || result.Port != 0 {
					log.Error().Msgf(
						"unhandled result from certScanResultsChan: %+v",
						result,
					)
				}

				log.Debug().Msg(
					"certScanCollector: certScanResultsChan is closed; exiting goroutine",
				)

				return
			}

			log.Debug().Msgf("result: %v", result)
			*discoveredCertChains = append(*discoveredCertChains, result)

		}
	}

}

// certScanner is called as a goroutine after launching the cert scan
// collector goroutine. This function performs a certificate chain check
// against all specified ports that were previously found to be open and
// returns the results of those checks on a channel that the collector
// goroutine monitors. This goroutine continues to run until all open ports
// are checked, either successfully or once a specified timeout is reached.
func certScanner(
	ctx context.Context,
	heartBeatChan chan<- struct{},
	portScanResultsChan <-chan netutils.PortCheckResult,
	showHostsWithClosedPorts bool,
	showPortScanResults bool,
	timeout time.Duration,
	certScanResultsChan chan<- certs.DiscoveredCertChain,
	rateLimiter chan struct{}, // needs to allow send & receive
	log zerolog.Logger,
	wg *sync.WaitGroup,
) {

	log.Debug().Msg("Launching parent cert scanner goroutine")

	// caller sets this just before calling this function
	defer func() {
		log.Debug().Msg("certScanner: decrementing parent waitgroup")
		wg.Done()
	}()

	var certScanWG sync.WaitGroup

	for {
		select {
		case <-ctx.Done():

			errMsg := "certScanner: context cancelled or expired"
			log.Debug().
				Err(ctx.Err()).
				Msg(errMsg)

			return

		case portScanResult, openChan := <-portScanResultsChan:

			if !openChan {

				log.Debug().Msg("portScanResultsChan is no longer open")
				log.Debug().Msg("portScanResultsChan: waiting on certScan goroutines to complete")
				certScanWG.Wait()

				// close cert scan results channel to indicate that the collector should
				// shutdown
				close(certScanResultsChan)

				log.Debug().Msg("Finished parent cert scanner goroutine")

				return
			}

			log.Debug().Msgf("certScanner: Received %v on portScanResultsChan", portScanResult)

			log.Debug().Msg("Send heartbeat to indicate that we are still receiving values")
			heartBeatChan <- struct{}{}

			// unless user opted to show hosts with *all* closed ports, skip the
			// host and continue to the next one
			if !showHostsWithClosedPorts && !portScanResult.Open {
				continue
			}

			switch {
			case showPortScanResults:
				portSummary := func() string {
					if portScanResult.Open {
						return portScanResult.Summary()
					}
					return "None"
				}()

				// 192.168.1.2: [443: true, 636: false]
				fmt.Printf("%s: [%s]\n", portScanResult.IPAddress.String(), portSummary)
			default:
				fmt.Printf(".")
			}

			// abort early if context has been cancelled
			if ctx.Err() != nil {
				errMsg := "certScanner: ports: context cancelled or expired"
				log.Error().
					Str("host", portScanResult.IPAddress.String()).
					Int("port", portScanResult.Port).
					Err(ctx.Err()).
					Msg(errMsg)

				return
			}

			if portScanResult.Open {

				log.Debug().Msgf(
					"Checking port %v for cert on IP %v",
					portScanResult.Port,
					portScanResult.IPAddress.String(),
				)

				log.Debug().Msg("certScanner: incrementing waitgroup")
				certScanWG.Add(1)

				go func(
					ctx context.Context,
					ipAddr string,
					port int,
					timeout time.Duration,
					resultsChan chan<- certs.DiscoveredCertChain,
					log zerolog.Logger,
				) {

					// make sure we give up our spot when finished
					defer func() {
						// indicate that we're done with this goroutine
						log.Debug().Msg("certScanner: decrementing waitgroup")
						certScanWG.Done()
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
							Str("host", ipAddr).
							Int("port", port).
							Msg("error fetching certificates chain")

						// os.Exit(1)
						// TODO: Decide whether fetch errors are critical or just warning level

						return
					}

					log.Debug().Msg("Attempting to send cert chain on resultsChan")
					resultsChan <- certs.DiscoveredCertChain{
						Host:  ipAddr,
						Port:  port,
						Certs: certChain,
					}

					log.Debug().Msg("Finished child cert scanner goroutine")

				}(ctx, portScanResult.IPAddress.String(), portScanResult.Port, timeout, certScanResultsChan, log)

			}

		}
	}
}
