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

	"github.com/atc0005/check-cert/internal/netutils"
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
	hosts []string,
	ports []int,
	timeout time.Duration,
	portScanResultsChan chan<- netutils.PortCheckResult,
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

	for _, host := range hosts {

		// track this specific host
		hostsWG.Add(1)

		log.Debug().Msgf("Checking host: %v", host)

		select {
		// abort early if context has been cancelled
		case <-ctx.Done():
			errMsg := "portScanner: hosts: context cancelled or expired"
			log.Error().
				Str("host", host).
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
			target string,
			ports []int,
			portScanResultsChan chan<- netutils.PortCheckResult,
		) {

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

			var portChecksWG sync.WaitGroup
			for _, port := range ports {

				log.Debug().Msgf("Checking port %v for host: %v", port, target)

				// abort early if context has been cancelled
				if ctx.Err() != nil {
					errMsg := "portScanner: ports: context cancelled or expired"
					log.Error().
						Str("host", target).
						Int("port", port).
						Err(ctx.Err()).
						Msg(errMsg)

					// NOTE: We probably don't want to send anything back for
					// context cancellation as the check result hasn't truly
					// been determined for this port.
					//
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
					target string,
					port int,
					scanTimeout time.Duration,
					portScanResultsChan chan<- netutils.PortCheckResult,
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

						default:
							log.Warn().
								Int("reserved", len(portScanRateLimiter)).
								Bool("ctx_cancelled", ctx.Err() != nil).
								Msg("ERROR: No spot to release in port scan rate limiter")
						}
					}()

					log.Debug().Msgf("Checking %v", target)
					portState := netutils.CheckPort(target, port, scanTimeout)

					// if portState.Err != nil {
					//
					//
					// TODO: Check specific error type to determine whether a
					// port scan attempt should be retried.
					//
					// }

					log.Debug().
						Str("hostname", portState.Host).
						Str("ip_address", portState.IPAddress.String()).
						Int("port", portState.Port).
						Bool("port", portState.Open).
						Err(portState.Err).
						Msg("portState value")

					log.Debug().Msg("Returning portState on portScanResultsChan")
					portScanResultsChan <- portState
					log.Debug().Msg("Finished returning portState on portScanResultsChan")

					log.Debug().Msg("Finished child port scanner goroutine")

				}(ctx, target, port, timeout, portScanResultsChan, log)

			}

			portChecksWG.Wait()
			log.Debug().Msg("portChecksWG.Wait() finished")

			log.Debug().Msgf("Sending port scan results for host %s on channel", target)

		}(ctx, host, ports, portScanResultsChan)

	}

	// Wait on all per-host goroutines to finish
	hostsWG.Wait()
	log.Debug().Msg("hostsWG.Wait() finished")

	// signal that we have no further scan results to send back
	close(portScanResultsChan)

	log.Debug().Msg("Finished parent port scanner goroutine")

}
