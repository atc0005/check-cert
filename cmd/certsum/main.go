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
	"github.com/atc0005/check-certs/internal/netutils"
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

	givenIPsList := cfg.IPAddresses()
	log.Debug().Msgf("IP Addresses: %v", givenIPsList)
	fmt.Println("Total IPs from all ranges before deduping:", len(givenIPsList))

	ipsList := textutils.DedupeList(givenIPsList)
	fmt.Println("Total IPs from all ranges after deduping:", len(ipsList))

	fmt.Println("Beginning scan of ports:", cfg.CertPorts())
	portScanStart := time.Now()

	var scanWG sync.WaitGroup
	var collWG sync.WaitGroup

	rateLimiter := make(chan struct{}, cfg.PortScanRateLimit)
	portScanResults := make(chan netutils.PortCheckResult)
	certCheckResults := make(chan certs.DiscoveredCertChain)
	resultsIndex := make(netutils.PortCheckResultsIndex)

	// Spin off port scan results collector
	collWG.Add(1)

	go portScanCollector(resultsIndex, portScanResults, log, &collWG)

	scanWG.Add(1)
	go portScanner(
		cfg.IPAddresses(),
		cfg.CertPorts(),
		cfg.TimeoutPortScan(),
		portScanResults,
		rateLimiter,
		log,
		&scanWG,
	)

	// wait for all port scan attempts to complete
	scanWG.Wait()

	log.Debug().Msg("closing port scan results channel")
	// signal to collector that port scanning is complete
	close(portScanResults)
	log.Debug().Msg("closed port scan results channel")

	// wait for port scan results collection goroutine to finish
	collWG.Wait()

	fmt.Printf("Completed port scan in %v\n", time.Since(portScanStart))

	// **********************************************************************
	// TODO: refactor to perform cert scanning immediately upon receiving a
	// successful port scan result instead of waiting for the entire port scan
	// to complete before beginning cert analysis.
	// **********************************************************************

	var discoveredCertChains certs.DiscoveredCertChains

	fmt.Println("Beginning certificate analysis")
	certCheckStart := time.Now()

	// Spin off cert check results collector, pass pointer to allow modifying
	// collection of discovered cert chains directly.
	collWG.Add(1)
	go certScanCollector(&discoveredCertChains, certCheckResults, &collWG)

	scanWG.Add(1)
	go certScanner(
		resultsIndex,
		cfg.ShowHostsWithClosedPorts,
		cfg.ShowPortScanResults,
		cfg.Timeout(),
		certCheckResults,
		rateLimiter,
		log,
		&scanWG,
	)

	log.Debug().Msg("wait for all cert check attempts to complete")
	scanWG.Wait()

	log.Debug().Msg("closing cert check results channel")
	// signal to collector that cert checks are complete
	close(certCheckResults)
	log.Debug().Msg("closed cert check results channel")

	log.Debug().Msg("wait for cert check results collection goroutine to finish")
	collWG.Wait()

	if !cfg.ShowPortScanResults {
		// will need to insert a newline before showing cert summary
		// output if we did not include port summary results as we checked
		// examined certs earlier
		fmt.Println()
	}

	fmt.Printf("Completed certificate analysis in %v\n", time.Since(certCheckStart))

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
