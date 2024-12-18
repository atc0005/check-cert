// Copyright 2022 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"crypto/x509"

	"github.com/atc0005/check-cert/internal/certs"
	"github.com/atc0005/check-cert/internal/config"
	"github.com/rs/zerolog"
)

// runValidationChecks acts as a wrapper around the validation checks applied
// to a retrieved certificate chain.
func runValidationChecks(cfg *config.Config, certChain []*x509.Certificate, log zerolog.Logger) certs.CertChainValidationResults {

	// Create "bucket" to collect validation results. The initial size is
	// close to the number of planned validation checks.
	validationResults := make(certs.CertChainValidationResults, 0, 5)

	hostnameValidationOptions := certs.CertChainValidationOptions{
		IgnoreHostnameVerificationFailureIfEmptySANsList: cfg.IgnoreHostnameVerificationFailureIfEmptySANsList,
		IgnoreValidationResultHostname:                   !cfg.ApplyCertHostnameValidationResults(),
	}

	log.Debug().
		Interface("validation_options", hostnameValidationOptions).
		Msg("Hostname Validation Options")

	hostnameValidationResult := certs.ValidateHostname(
		certChain,
		cfg.Server,
		cfg.DNSName,
		config.IgnoreHostnameVerificationFailureIfEmptySANsListFlag,
		hostnameValidationOptions,
	)
	validationResults.Add(hostnameValidationResult)

	switch {
	case hostnameValidationResult.IsFailed():
		log.Debug().
			Err(hostnameValidationResult.Err()).
			Msgf("%s validation failure", hostnameValidationResult.CheckName())

	case hostnameValidationResult.IsIgnored():
		log.Debug().
			Msgf("%s validation ignored", hostnameValidationResult.CheckName())

	default:
		log.Debug().
			Msgf("%s validation successful", hostnameValidationResult.CheckName())
	}

	sansValidationOptions := certs.CertChainValidationOptions{
		IgnoreValidationResultSANs: !cfg.ApplyCertSANsListValidationResults(),
	}

	log.Debug().
		Interface("validation_options", sansValidationOptions).
		Msg("SANs Validation Options")

	sansValidationResult := certs.ValidateSANsList(
		certChain,
		cfg.SANsEntries,
		sansValidationOptions,
	)
	validationResults.Add(sansValidationResult)

	switch {
	case sansValidationResult.IsFailed():
		log.Debug().
			Err(sansValidationResult.Err()).
			Int("sans_entries_requested", sansValidationResult.NumExpected()).
			Int("sans_entries_found", sansValidationResult.NumMatched()).
			Int("sans_entries_mismatched", sansValidationResult.NumMismatched()).
			Msgf("%s validation failure", sansValidationResult.CheckName())

	case sansValidationResult.IsIgnored():
		log.Debug().
			Msgf("%s validation ignored", sansValidationResult.CheckName())

	default:
		log.Debug().
			Int("sans_entries_requested", sansValidationResult.NumExpected()).
			Int("sans_entries_found", sansValidationResult.NumMatched()).
			Msgf("%s validation successful", sansValidationResult.CheckName())
	}

	expirationValidationOptions := certs.CertChainValidationOptions{
		IgnoreExpiredIntermediateCertificates:  cfg.IgnoreExpiredIntermediateCertificates,
		IgnoreExpiredRootCertificates:          cfg.IgnoreExpiredRootCertificates,
		IgnoreExpiringIntermediateCertificates: cfg.IgnoreExpiringIntermediateCertificates,
		IgnoreExpiringRootCertificates:         cfg.IgnoreExpiringRootCertificates,
		IgnoreValidationResultExpiration:       !cfg.ApplyCertExpirationValidationResults(),
	}

	log.Debug().
		Interface("validation_options", expirationValidationOptions).
		Msg("Expiration Validation Options")

	expirationValidationResult := certs.ValidateExpiration(
		certChain,
		cfg.AgeCritical,
		cfg.AgeWarning,
		cfg.VerboseOutput,
		cfg.OmitSANsEntries,
		expirationValidationOptions,
	)

	validationResults.Add(expirationValidationResult)

	switch {
	case expirationValidationResult.IsFailed():
		log.Debug().
			Err(expirationValidationResult.Err()).
			Int("total_certificates", expirationValidationResult.TotalCerts()).
			Int("expired_certificates", expirationValidationResult.NumExpiredCerts()).
			Int("expiring_certificates", expirationValidationResult.NumExpiringCerts()).
			Int("valid_certificates", expirationValidationResult.NumValidCerts()).
			Msgf("%s validation failure", expirationValidationResult.CheckName())

	case expirationValidationResult.IsIgnored():
		log.Debug().
			Int("total_certificates", expirationValidationResult.TotalCerts()).
			Msgf("%s validation ignored", expirationValidationResult.CheckName())

	default:
		log.Debug().
			Int("total_certificates", expirationValidationResult.TotalCerts()).
			Int("expired_certificates", expirationValidationResult.NumExpiredCerts()).
			Int("expiring_certificates", expirationValidationResult.NumExpiringCerts()).
			Int("valid_certificates", expirationValidationResult.NumValidCerts()).
			Msgf("%s validation successful", expirationValidationResult.CheckName())

	}

	chainOrderValidationOptions := certs.CertChainValidationOptions{
		IgnoreValidationResultChainOrder: !cfg.ApplyCertChainOrderValidationResults(),
	}

	log.Debug().
		Interface("validation_options", chainOrderValidationOptions).
		Msg("Chain Order Validation Options")

	chainOrderValidationResult := certs.ValidateChainOrder(
		certChain,
		cfg.VerboseOutput,
		cfg.OmitSANsEntries,
		chainOrderValidationOptions,
	)
	validationResults.Add(chainOrderValidationResult)

	switch {
	case chainOrderValidationResult.IsFailed():
		log.Debug().
			Err(chainOrderValidationResult.Err()).
			Int("chain_entries_ordered", chainOrderValidationResult.NumOrderedCerts()).
			Int("chain_entries_misordered", chainOrderValidationResult.NumMisorderedCerts()).
			Int("chain_entries_total", chainOrderValidationResult.TotalCerts()).
			Msgf("%s validation failure", chainOrderValidationResult.CheckName())

	case chainOrderValidationResult.IsIgnored():
		log.Debug().
			Msgf("%s validation ignored", chainOrderValidationResult.CheckName())

	default:
		log.Debug().
			Int("chain_entries_ordered", chainOrderValidationResult.NumOrderedCerts()).
			Int("chain_entries_misordered", chainOrderValidationResult.NumMisorderedCerts()).
			Msgf("%s validation successful", chainOrderValidationResult.CheckName())
	}

	return validationResults

}
