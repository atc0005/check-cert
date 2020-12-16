// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"errors"
	"fmt"
	"sync"
	"time"

	zlog "github.com/rs/zerolog/log"

	"github.com/atc0005/check-certs/internal/certs"
	"github.com/atc0005/check-certs/internal/config"
	"github.com/atc0005/check-certs/internal/net"
	"github.com/atc0005/check-certs/internal/textutils"
)

func main() {

	// Setup configuration by parsing user-provided flags.
	cfg, cfgErr := config.New(config.AppType{Scanner: true})
	switch {
	case errors.Is(cfgErr, config.ErrVersionRequested):
		fmt.Println(config.Version())

		return

	case cfgErr != nil:
		// We're using the standalone Err function from rs/zerolog/log as we
		// do not have a working configuration.
		zlog.Err(cfgErr).Msg("Error initializing application")

		return
	}

	// Set common fields here so that we don't have to repeat them explicitly
	// later. This will hopefully help to standardize the log messages to make
	// them easier to search through later when troubleshooting.
	log := cfg.Log.With().
		Int("port_scan_timeout", int(cfg.TimeoutPortScan())).
		Logger()

	log.Debug().Msgf("CIDR range: %v", cfg.CIDRRange)

	givenIPsList := make([]string, 0, 1024)
	for _, ipRange := range cfg.CIDRRange {
		ips, count, err := net.Hosts(ipRange)
		if err != nil {
			log.Error().Err(err).Msg("failed to retrieve hosts from range")
		}
		log.Debug().
			Int("ips_in_range", count).
			Str("range", ipRange).
			Msg("")
		givenIPsList = append(givenIPsList, ips...)
	}

	fmt.Println("Total IPs from all ranges before deduping:", len(givenIPsList))

	ipsList := textutils.DedupeList(givenIPsList)
	fmt.Println("Total IPs from all ranges after deduping:", len(ipsList))

	fmt.Println("Beginning scan of ports:", cfg.CertPorts())

	var scanWG sync.WaitGroup
	var collWG sync.WaitGroup

	rateLimiter := make(chan struct{}, cfg.PortScanRateLimit)
	results := make(chan net.PortCheckResult)
	resultsIndex := make(net.PortCheckResultsIndex)

	// Spin off scan results collector
	collWG.Add(1)
	go func(resultsIdx net.PortCheckResultsIndex, results <-chan net.PortCheckResult) {

		log.Debug().Msg("starting collector routine")

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
		collWG.Done()
	}(resultsIndex, results)

	for _, ip := range ipsList {

		log.Debug().Msgf("Checking IP: %v", ip)

		for _, port := range cfg.CertPorts() {

			log.Debug().Msgf("Checking port %v for IP: %v", port, ip)

			// indicate that we are launching a goroutine that will be tracked and
			// reserve a spot in the (limited) channel
			scanWG.Add(1)
			rateLimiter <- struct{}{}

			go func(
				ipAddr string,
				port int,
				scanTimeout time.Duration,
				resultsChan <-chan net.PortCheckResult,
			) {

				portState := net.CheckPort(ipAddr, port, scanTimeout)
				if portState.Err != nil {
					// TODO: Check specific error type to determine how to
					// proceed. For now, we'll just emit the error and
					// continue.
					log.Error().
						Str("host", ipAddr).
						Int("port", port).
						Err(portState.Err)
				}

				log.Debug().Msg("Sending result back on channel")

				results <- portState

				log.Debug().Msg("Sent result on channel, proceeding")

				// if portState.Open {
				// 	fmt.Printf("%v: port %v open\n", ipAddr, port)
				// }

				// indicate that we're done with this goroutine
				scanWG.Done()

				// release spot for next (held back) goroutine to run
				<-rateLimiter

			}(ip, port, cfg.TimeoutPortScan(), results)

		}
	}

	// wait for all port scan attempts to complete
	scanWG.Wait()

	log.Debug().Msg("closing results channel")
	// signal to collector that port scanning is complete
	close(results)
	log.Debug().Msg("closed results channel")

	// wait for results collection goroutine to finish
	collWG.Wait()

	log.Debug().Msg("processing scan results")

	var discoveredCertChains certs.DiscoveredCertChains

	// TODO: refactor; use concurrency here instead of waiting for the port
	// scan to complete before beginning cert analysis
	fmt.Println("Completed port scan")
	fmt.Println("Beginning certificate analysis")
	for host, checkResults := range resultsIndex {

		// unless user opted to show hosts with *all* closed ports, skip the
		// host and continue to the next one
		if !cfg.ShowHostsWithClosedPorts && !checkResults.HasOpenPort() {
			continue
		}

		switch {
		case cfg.ShowPortScanResults:
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
				var certFetchErr error
				certChain, certFetchErr := net.GetCerts(
					result.IPAddress.String(),
					result.Port,
					cfg.Timeout(),
					log,
				)
				if certFetchErr != nil {
					if !cfg.ShowPortScanResults {
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
					continue
				}

				// do something with certChain
				discoveredCertChains = append(
					discoveredCertChains, certs.DiscoveredCertChain{
						Host:  result.IPAddress.String(),
						Port:  result.Port,
						Certs: certChain,
					})
			}

		}
	}

	if !cfg.ShowPortScanResults {
		// will need to insert a newline before showing cert summary
		// output if we did not include port summary results as we checked
		// examined certs earlier
		fmt.Println()
	}

	fmt.Println("Completed certificate analysis")

	fmt.Printf("\nResults:\n\n")

	switch {
	case cfg.ShowOverview:
		printSummaryHighLevel(
			cfg.ShowHostsWithValidCerts,
			discoveredCertChains,
			cfg.AgeCritical,
			cfg.AgeWarning,
		)

	default:
		printSummaryDetailedLevel(
			cfg.ShowValidCerts,
			discoveredCertChains,
			cfg.AgeCritical,
			cfg.AgeWarning,
		)
	}

}
