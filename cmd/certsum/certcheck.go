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
	"strings"
	"sync"
	"time"

	"github.com/atc0005/check-cert/internal/certs"
	"github.com/atc0005/check-cert/internal/netutils"
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
			switch {
			case !openChan:
				// When the channel closes openChan becomes false and result
				// is zero value of its type. In this scenario we should log
				// the event and exit the goroutine.
				log.Debug().Msg(
					"certScanCollector: certScanResultsChan is closed; exiting goroutine",
				)

				return

			default:
				log.Debug().
					Str("result", fmt.Sprintf("%v", result)).
					Msg("certScanCollector received new result")
				*discoveredCertChains = append(*discoveredCertChains, result)
			}
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

			// The host value is set even if there was an issue encountered
			// checking a port's status so that we can provide a brief summary
			// of the port check results.
			var hostLabel string
			switch {
			case strings.TrimSpace(portScanResult.Host) != "":
				hostLabel = fmt.Sprintf(
					"%s (%s)",
					portScanResult.Host,
					portScanResult.IPAddress.String(),
				)
			default:
				hostLabel = portScanResult.IPAddress.String()
			}

			switch {
			case showPortScanResults:
				fmt.Printf("%s: [%s]\n", hostLabel, portScanResult.Summary())
			default:
				fmt.Printf(".")
			}

			// abort early if context has been cancelled
			if ctx.Err() != nil {
				errMsg := "certScanner: ports: context cancelled or expired"
				log.Error().
					Str("host", portScanResult.Host).
					Str("ip_address", portScanResult.IPAddress.String()).
					Int("port", portScanResult.Port).
					Err(ctx.Err()).
					Msg(errMsg)

				return
			}

			if portScanResult.Open {

				log.Debug().
					Str("host", portScanResult.Host).
					Str("ip_address", portScanResult.IPAddress.String()).
					Int("port", portScanResult.Port).
					Msg("Open port found; attempting to retrieve certificate chain")

				log.Debug().Msg("certScanner: incrementing waitgroup")
				certScanWG.Add(1)

				log.Debug().Msg("Reserving spot in cert scan rate limiter")
				rateLimiter <- struct{}{}
				log.Debug().
					Int("reserved", len(rateLimiter)).
					Msg("Cert scan rate limiter reservation added")

				go func(
					ctx context.Context,
					portscanResult netutils.PortCheckResult,
					timeout time.Duration,
					resultsChan chan<- certs.DiscoveredCertChain,
					log zerolog.Logger,
				) {

					// make sure we give up our spot when finished
					defer func() {
						log.Debug().Msg("cert scan goroutine defer triggered")

						// indicate that we're done with this goroutine
						log.Debug().Msg("certScanner: decrementing waitgroup")
						certScanWG.Done()

						// release spot for next cert scan goroutine to run
						log.Debug().
							Int("reserved", len(rateLimiter)).
							Msg("Releasing spot in cert scan rate limiter")
						select {
						case <-rateLimiter:
							log.Debug().
								Int("reserved", len(rateLimiter)).
								Msg("Released spot in cert scan rate limiter")

						default:
							log.Warn().
								Int("reserved", len(rateLimiter)).
								Bool("ctx_cancelled", ctx.Err() != nil).
								Msg("ERROR: No spot to release in cert scan rate limiter")
						}
					}()

					var certFetchErr error
					log.Debug().
						Str("host", portScanResult.Host).
						Str("ip_address", portScanResult.IPAddress.String()).
						Int("port", portScanResult.Port).
						Msg("Retrieving certificate chain")

					// NOTE: We explicitly specify the IP Address to prevent
					// earlier port check results from occurring on one IP
					// while we unintentionally connect to another IP (by way
					// of using a name/FQDN to open the connection) to
					// retrieve the certificate chain.
					certChain, certFetchErr := netutils.GetCerts(
						portScanResult.Host,
						portScanResult.IPAddress.String(),
						portScanResult.Port,
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
							Str("host", portScanResult.Host).
							Str("ip_address", portScanResult.IPAddress.String()).
							Int("port", portScanResult.Port).
							Msg("error fetching certificates chain")

						// os.Exit(1)
						// TODO: Decide whether fetch errors are critical or just warning level

						return
					}

					log.Debug().Msg("Attempting to send cert chain on resultsChan")
					resultsChan <- certs.DiscoveredCertChain{
						Name:      portScanResult.Host,
						IPAddress: portScanResult.IPAddress.String(),
						Port:      portScanResult.Port,
						Certs:     certChain,
					}

					log.Debug().Msg("Finished child cert scanner goroutine")

				}(ctx, portScanResult, timeout, certScanResultsChan, log)

			}

		}
	}
}
