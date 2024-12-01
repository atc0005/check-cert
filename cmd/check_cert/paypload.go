// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"

	payload "github.com/atc0005/cert-payload"
	"github.com/atc0005/cert-payload/input"
	"github.com/atc0005/check-cert/internal/config"
	"github.com/atc0005/go-nagios"
	"github.com/rs/zerolog"
)

// addCertChainPayload appends a given certificate chain payload (as a JSON
// encoded value) to plugin output.
func addCertChainPayload(certChain []*x509.Certificate, plugin *nagios.Plugin, cfg *config.Config, ipAddr string) error {
	log := cfg.Log.With().Logger()

	// We convert the last exit code registered with the plugin to a suitable
	// service check state.
	serviceState := nagios.ExitCodeToStateLabel(plugin.ExitStatusCode)

	log.Debug().Msgf("%d errors registered with plugin", len(plugin.Errors))

	inputData := input.Values{
		CertChain:                            certChain,
		Errors:                               plugin.Errors,
		IncludeFullCertChain:                 cfg.EmitPayloadWithFullChain,
		OmitSANsEntries:                      cfg.OmitSANsEntries,
		ExpirationAgeInDaysWarningThreshold:  cfg.AgeWarning,
		ExpirationAgeInDaysCriticalThreshold: cfg.AgeCritical,
		Server:                               input.Server{HostValue: cfg.Server, IPAddress: ipAddr},
		DNSName:                              cfg.DNSName,
		TCPPort:                              cfg.Port,
		ServiceState:                         serviceState,
	}

	stableFormats := payload.AvailableStableFormatVersions()

	if cfg.PayloadFormatVersion == payload.UnstablePayloadVersion {
		log.Warn().Msg("WARNING: Unstable/development payload format version chosen.")
		log.Warn().Msgf("It is recommended that you use a stable payload format version (available: %v).", stableFormats)
	}

	certChainSummary, certSummaryErr := payload.Encode(cfg.PayloadFormatVersion, inputData)

	if certSummaryErr != nil {
		return certSummaryErr
	}

	// fmt.Fprintln(os.Stderr, string(certChainSummary))
	// log.Debug().Str("json_payload", string(certChainSummary)).Msg("JSON payload before encoding")

	if zerolog.GlobalLevel() == zerolog.DebugLevel || zerolog.GlobalLevel() == zerolog.TraceLevel {
		log.Debug().Msg("JSON payload before encoding")

		var prettyJSON bytes.Buffer
		err := json.Indent(&prettyJSON, certChainSummary, "", "    ")
		if err == nil {
			fmt.Fprintln(os.Stderr, prettyJSON.String())
		}
	}

	// NOTE: AddPayloadString will NOT return an error if empty input is
	// provided.
	if _, err := plugin.AddPayloadBytes(certChainSummary); err != nil {
		return err
	}

	return nil
}
