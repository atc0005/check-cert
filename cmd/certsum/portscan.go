// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"context"
	"sync"
	"time"

	"github.com/atc0005/check-certs/internal/netutils"
	"github.com/rs/zerolog"
)

// portScanner is called as a goroutine after launching the port scan
// collector goroutine. This function performs a port scan against all
// user-specified ports and returns the results of those scan attempts on a
// channel that the collector goroutine monitors. This goroutine continues to
// run until all ports are checked, either successfully or once a specified
// timeout is reached.
func portScanner(
	ctx context.Context,
	ips []string,
	ports []int,
	timeout time.Duration,
	portScanResultsChan chan<- netutils.PortCheckResults,
	portScanRateLimiter chan struct{}, // needs to allow send & receive
	hostRateLimiter chan struct{}, // needs to allow send & receive
	log zerolog.Logger,
	wg *sync.WaitGroup,
) {

	log.Debug().Msg("Launching parent port scanner goroutine")

	// caller sets this just before calling this function
	defer func() {
		log.Debug().Msg("portScanner: decrementing parent waitgroup")
		wg.Done()
	}()

	var hostsWG sync.WaitGroup

	for _, ip := range ips {

		// track this specific host
		hostsWG.Add(1)

		log.Debug().Msgf("Checking IP: %v", ip)

		select {
		// abort early if context has been cancelled
		case <-ctx.Done():
			errMsg := "portScanner: ips: context cancelled or expired"
			log.Error().
				Str("host", ip).
				Err(ctx.Err()).
				Msg(errMsg)

			return

		// fmt.Println("Reserving spot in host rate limiter")
		// NOTE: Reserve first so that deferred "free spot" action can safely
		// take place if we exit due to cancelled context
		case hostRateLimiter <- struct{}{}:

		}

		// process all specified ports for the current host
		go func(
			ctx context.Context,
			ipAddr string,
			ports []int,

			portScanResultsChan chan<- netutils.PortCheckResults,
		) {

			// FIXME: What causes this goroutine to exit?

			defer func() {

				log.Debug().Msg("host goroutine defer triggered")
				// indicate completion of scanning specified ports on host
				hostsWG.Done()
				log.Debug().Msg("hostsWG.Done() called")

				// release spot for next host-specific goroutine to run
				select {
				case <-hostRateLimiter:
					log.Debug().
						Int("reserved", len(hostRateLimiter)).
						Bool("ctx_cancelled", ctx.Err() != nil).
						Msg("Releasing spot in host rate limiter")
				default:
					log.Warn().Msg("No spot to release in host rate limiter")
				}
			}()

			// collect results of port scans for this specific host; it is
			// easier to work with the results per host than one at a time.
			hostPortScanResults := make(netutils.PortCheckResults, 0, len(ports))

			childPortScanResultsChan := make(chan netutils.PortCheckResult)

			var collWG sync.WaitGroup

			collWG.Add(1)
			go func(
				hostScanResults *netutils.PortCheckResults,
				resultsChan <-chan netutils.PortCheckResult,
			) {
				defer func() {
					collWG.Done()
				}()

				for {
					select {
					case <-ctx.Done():

						log.Debug().
							Err(ctx.Err()).
							Msg("portScanner: portScanResults goroutine: context cancelled or expired")

						return

					case result, openChan := <-resultsChan:

						if !openChan {
							log.Debug().Msg("childPortScanResultsChan is no longer open")

							return
						}

						log.Debug().Msgf("received result in goroutine: %v", result)
						log.Debug().Msgf("hostScanResults length before append: %v", len(*hostScanResults))
						*hostScanResults = append(*hostScanResults, result)
						log.Debug().Msgf("hostScanResults length after append: %v", len(*hostScanResults))

					}
				}

			}(&hostPortScanResults, childPortScanResultsChan)

			var portChecksWG sync.WaitGroup
			for _, port := range ports {

				log.Debug().Msgf("Checking port %v for IP: %v", port, ipAddr)

				// abort early if context has been cancelled
				if ctx.Err() != nil {
					errMsg := "portScanner: ports: context cancelled or expired"
					log.Error().
						Str("host", ipAddr).
						Int("port", port).
						Err(ctx.Err()).
						Msg(errMsg)

					// childPortScanResultsChan <- netutils.PortCheckResult{
					// 	Err: fmt.Errorf("%s: %w", errMsg, ctx.Err()),
					// }

					return
				}

				// indicate that we are launching a goroutine that will be
				// tracked and reserve a spot in the (intentionally limited)
				// channel shared with per-host (parent) goroutines.
				portChecksWG.Add(1)
				// fmt.Println("Reserving spot in port scan rate limiter")
				portScanRateLimiter <- struct{}{}

				go func(
					ctx context.Context,
					ipAddr string,
					port int,
					scanTimeout time.Duration,
					childPortScanResultsChan chan<- netutils.PortCheckResult,
					log zerolog.Logger,
				) {

					log.Debug().Msg("Launching child port scanner goroutine")

					// make sure we give up our spot when finished
					defer func() {

						log.Debug().Msg("port scan goroutine defer triggered")

						// indicate that we're done with this goroutine
						portChecksWG.Done()
						log.Debug().Msg("portChecksWG.Done() called")

						// release spot for next port scan goroutine to run
						select {
						case <-portScanRateLimiter:
							log.Debug().
								Int("reserved", len(portScanRateLimiter)).
								Msg("Releasing spot in port scan rate limiter")
							// time.Sleep(time.Duration(2) * time.Second)
						default:
							log.Warn().
								Int("reserved", len(portScanRateLimiter)).
								Bool("ctx_cancelled", ctx.Err() != nil).
								Msg("ERROR: No spot to release in port scan rate limiter")
							// time.Sleep(time.Duration(10) * time.Second)
						}

					}()

					log.Debug().Msgf("Checking %v", ipAddr)
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

						childPortScanResultsChan <- netutils.PortCheckResult{
							Err: portState.Err,
						}

						return
					}

					log.Debug().Msg("Returning portState on childPortScanResultsChan")
					childPortScanResultsChan <- portState
					log.Debug().Msg("Finished returning portState on childPortScanResultsChan")

					log.Debug().Msg("Finished child port scanner goroutine")

				}(ctx, ipAddr, port, timeout, childPortScanResultsChan, log)

			}

			portChecksWG.Wait()
			log.Debug().Msg("portChecksWG.Wait() finished")
			close(childPortScanResultsChan)
			log.Debug().Msg("childPortScanResultsChan closed")

			log.Debug().Msgf("Sending port scan results for IP %s on channel", ipAddr)

			// -race flag detects this as a data race
			// log.Debug().Msgf("hostPortScanResults before waiting: %v\n", hostPortScanResults)

			// Wait on collector to finish accumulating values before sending
			// back results
			collWG.Wait()
			log.Debug().Msg("collWG.Wait() finished")
			log.Debug().Msgf(
				"hostPortScanResults after waiting on goroutine to complete: %v",
				hostPortScanResults,
			)

			portScanResultsChan <- hostPortScanResults

		}(ctx, ip, ports, portScanResultsChan)

	}

	// Wait on all per-host goroutines to finish
	hostsWG.Wait()
	log.Debug().Msg("hostsWG.Wait() finished")

	// signal that we have no further scan results to send back
	close(portScanResultsChan)

	log.Debug().Msg("Finished parent port scanner goroutine")

}
