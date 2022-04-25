// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	zlog "github.com/rs/zerolog/log"

	"github.com/atc0005/check-cert/internal/certs"
	"github.com/atc0005/check-cert/internal/config"
	"github.com/atc0005/check-cert/internal/netutils"
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
		Str("port_scan_timeout", fmt.Sprintf("%v", cfg.TimeoutPortScan())).
		Str("app_timeout", fmt.Sprintf("%v", cfg.TimeoutAppInactivity())).
		Logger()

	expandedHostsList := cfg.Hosts()
	log.Debug().Msgf("Host values before deduping: %v", expandedHostsList)
	log.Debug().Msgf("Total host values before deduping: %d", len(expandedHostsList))

	expandedHostsList = netutils.DedupeHosts(expandedHostsList)
	log.Debug().Msgf("Total host values after deduping: %d", len(expandedHostsList))
	log.Debug().Msgf("Host values after deduping: %v", expandedHostsList)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	heartBeatChan := make(chan struct{})
	go heartBeatMonitor(ctx, cancel, heartBeatChan, cfg.TimeoutAppInactivity(), log)

	var portScanWG sync.WaitGroup
	var certScanWG sync.WaitGroup
	var collWG sync.WaitGroup

	// limit the total number of concurrent port scans (user-specified with
	// fallback default)
	portScanRateLimiter := make(chan struct{}, cfg.ScanRateLimit)

	// limit the total number of hosts concurrently processed independently
	// from port scan limit (in an effort to avoid deadlocks)
	hostRateLimiter := make(chan struct{}, cfg.ScanRateLimit)

	// results are collected and passed per port
	portScanResultsChan := make(chan netutils.PortCheckResult)

	certScanResultsChan := make(chan certs.DiscoveredCertChain)

	var discoveredCertChains certs.DiscoveredCertChains

	scanStart := time.Now()

	// Spin off cert check results collector, pass pointer to allow modifying
	// collection of discovered cert chains directly.
	collWG.Add(1)
	log.Debug().Msg("Starting certScanCollector")
	go certScanCollector(
		ctx,
		&discoveredCertChains,
		certScanResultsChan,
		log,
		&collWG,
	)

	portScanWG.Add(1)
	log.Debug().Msg("Starting portScanner")
	go portScanner(
		ctx,
		cfg.Hosts(),
		cfg.CertPorts(),
		cfg.TimeoutPortScan(),
		portScanResultsChan,
		portScanRateLimiter,
		hostRateLimiter,
		log,
		&portScanWG,
	)

	certScanWG.Add(1)
	log.Debug().Msg("Starting certScanner ...")
	go certScanner(
		ctx,
		heartBeatChan,
		portScanResultsChan,
		cfg.ShowHostsWithClosedPorts,
		cfg.ShowPortScanResults,
		cfg.Timeout(),
		certScanResultsChan,
		portScanRateLimiter,
		log,
		&certScanWG,
	)

	fmt.Printf(
		"Beginning cert scan against %d IPs expanded from %d unique host patterns using ports: %v\n",
		func() int {
			var targetIPs int
			for _, host := range expandedHostsList {
				targetIPs += len(host.Expanded)
			}
			return targetIPs
		}(),
		len(expandedHostsList),
		cfg.CertPorts(),
	)

	log.Debug().Msg("wait for port scan attempts to complete")
	portScanWG.Wait()

	log.Debug().Msg("wait for cert scan attempts to complete")
	certScanWG.Wait()

	log.Debug().Msg("wait for cert check results collection goroutine to finish")
	collWG.Wait()

	log.Debug().Msgf("Discovered cert chains: %v", discoveredCertChains)

	if !cfg.ShowPortScanResults {
		// will need to insert a newline before showing cert summary
		// output if we did not include port summary results as we checked
		// examined certs earlier
		fmt.Println()
	}

	switch {

	case ctx.Err() != nil:
		fmt.Printf(
			"Certificates scan aborted after %v due to application timeout.\n",
			time.Since(scanStart),
		)
	default:
		fmt.Printf(
			"Completed certificates scan in %v\n",
			time.Since(scanStart),
		)
	}

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
