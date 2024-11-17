// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math"

	payload "github.com/atc0005/cert-payload"
	"github.com/atc0005/check-cert/internal/certs"
	"github.com/atc0005/check-cert/internal/config"
	"github.com/atc0005/go-nagios"
)

// certExpirationMetadata is a bundle of certificate expiration related
// metadata used when preparing a certificate payload for inclusion in plugin
// output.
type certExpirationMetadata struct {
	validityPeriodDays     int
	daysRemainingTruncated int
	daysRemainingPrecise   float64
	certLifetimePercent    int
}

// lookupCertExpMetadata is a helper function used to lookup specific
// certificate expiration metadata values used when preparing a certificate
// payload for inclusion in plugin output.
func lookupCertExpMetadata(cert *x509.Certificate, certNumber int, certChain []*x509.Certificate) (certExpirationMetadata, error) {
	if cert == nil {
		return certExpirationMetadata{}, fmt.Errorf(
			"cert in chain position %d of %d is nil: %w",
			certNumber,
			len(certChain),
			certs.ErrMissingValue,
		)
	}

	certLifetime, certLifeTimeErr := certs.LifeRemainingPercentageTruncated(cert)
	if certLifeTimeErr != nil {
		return certExpirationMetadata{}, fmt.Errorf(
			"error calculating lifetime for cert %q: %w",
			cert.Subject.CommonName,
			certLifeTimeErr,
		)
	}

	daysRemainingTruncated, expLookupErr := certs.ExpiresInDays(cert)
	if expLookupErr != nil {
		return certExpirationMetadata{}, fmt.Errorf(
			"error calculating the number of days until the certificate %q expires: %w",
			cert.Subject.CommonName,
			expLookupErr,
		)
	}

	daysRemainingPrecise, expLookupErrPrecise := certs.ExpiresInDaysPrecise(cert)
	if expLookupErrPrecise != nil {
		return certExpirationMetadata{}, fmt.Errorf(
			"error calculating the number of days until the certificate %q expires: %w",
			cert.Subject.CommonName,
			expLookupErr,
		)
	}

	validityPeriodDays, lifespanLookupErr := certs.MaxLifespanInDays(cert)
	if lifespanLookupErr != nil {
		return certExpirationMetadata{}, fmt.Errorf(
			"error calculating the maximum lifespan in days for certificate %q: %w",
			cert.Subject.CommonName,
			lifespanLookupErr,
		)
	}

	return certExpirationMetadata{
		certLifetimePercent:    certLifetime,
		daysRemainingPrecise:   daysRemainingPrecise,
		daysRemainingTruncated: daysRemainingTruncated,
		validityPeriodDays:     validityPeriodDays,
	}, nil
}

// extractExpValResult is a helper function used to extract the expiration
// validation result from a collection of previously applied certificate
// validation check results.
func extractExpValResult(validationResults certs.CertChainValidationResults) (certs.ExpirationValidationResult, error) {
	var expirationValidationResult certs.ExpirationValidationResult

	for _, validationResult := range validationResults {
		if expResult, ok := validationResult.(certs.ExpirationValidationResult); ok {
			expirationValidationResult = expResult
			break
		}
	}

	// Assert that we're working with a non-zero value.
	if len(expirationValidationResult.CertChain()) == 0 {
		// We're working with an uninitialized value; abort!
		return certs.ExpirationValidationResult{}, fmt.Errorf(
			"unable to extract expiration validation results"+
				" from collection of %d values: %w",
			len(validationResults),
			certs.ErrMissingValue,
		)
	}

	return expirationValidationResult, nil
}

// extractHostnameValResult is a helper function used to extract the expiration
// validation result from a collection of previously applied certificate
// validation check results.
func extractHostnameValResult(validationResults certs.CertChainValidationResults) (certs.HostnameValidationResult, error) {
	var hostnameValidationResult certs.HostnameValidationResult

	for _, validationResult := range validationResults {
		if hostnameResult, ok := validationResult.(certs.HostnameValidationResult); ok {
			hostnameValidationResult = hostnameResult
			break
		}
	}

	// Assert that we're working with a non-zero value.
	if len(hostnameValidationResult.CertChain()) == 0 {
		// We're working with an uninitialized value; abort!
		return certs.HostnameValidationResult{}, fmt.Errorf(
			"unable to extract hostname validation results"+
				" from collection of %d values: %w",
			len(validationResults),
			certs.ErrMissingValue,
		)
	}

	return hostnameValidationResult, nil
}

// buildCertSummary is a helper function that coordinates retrieving,
// collecting, evaluating and encoding certificate metadata as a JSON encoded
// string for inclusion in plugin output.
func buildCertSummary(cfg *config.Config, validationResults certs.CertChainValidationResults) (string, error) {
	expirationValidationResult, expExtractErr := extractExpValResult(validationResults)
	if expExtractErr != nil {
		return "", fmt.Errorf(
			"failed to generate certificate summary: %w",
			expExtractErr,
		)
	}

	hostnameValidationResult, hostnameExtractErr := extractHostnameValResult(validationResults)
	if hostnameExtractErr != nil {
		return "", fmt.Errorf(
			"failed to generate certificate summary: %w",
			hostnameExtractErr,
		)
	}

	certsExpireAgeCritical := expirationValidationResult.AgeCriticalThreshold()
	certsExpireAgeWarning := expirationValidationResult.AgeWarningThreshold()

	// Question: Should we use the customized certificate chain with any
	// user-specified certificates to exclude (for whatever reason) removed so
	// that we do not report on values which are problematic?
	//
	// certChain := expirationValidationResult.FilteredCertificateChain()
	//
	// Answer: No, we use the full chain so that any "downstream" reporting
	// tools retrieving the certificate payload from the monitoring system can
	// perform their own analysis with the full chain available for review.
	certChain := expirationValidationResult.CertChain()

	certChainSubset := make([]payload.Certificate, 0, len(certChain))
	for certNumber, origCert := range certChain {
		if origCert == nil {
			return "", fmt.Errorf(
				"cert in chain position %d of %d is nil: %w",
				certNumber,
				len(certChain),
				certs.ErrMissingValue,
			)
		}

		expiresText := certs.ExpirationStatus(
			origCert,
			certsExpireAgeCritical,
			certsExpireAgeWarning,
			false,
		)

		certStatus := payload.CertificateStatus{
			OK:       expirationValidationResult.IsOKState(),
			Expiring: expirationValidationResult.HasExpiringCerts(),
			Expired:  expirationValidationResult.HasExpiredCerts(),
		}

		certExpMeta, lookupErr := lookupCertExpMetadata(origCert, certNumber, certChain)
		if lookupErr != nil {
			return "", lookupErr
		}

		var SANsEntries []string
		if cfg.OmitSANsEntries {
			SANsEntries = nil
		} else {
			SANsEntries = origCert.DNSNames
		}

		validityPeriodDescription := lookupValidityPeriodDescription(origCert)

		certSubset := payload.Certificate{
			Subject:                   origCert.Subject.String(),
			CommonName:                origCert.Subject.CommonName,
			SANsEntries:               SANsEntries,
			SANsEntriesCount:          len(SANsEntries),
			Issuer:                    origCert.Issuer.String(),
			IssuerShort:               origCert.Issuer.CommonName,
			SerialNumber:              certs.FormatCertSerialNumber(origCert.SerialNumber),
			IssuedOn:                  origCert.NotBefore,
			ExpiresOn:                 origCert.NotAfter,
			DaysRemaining:             certExpMeta.daysRemainingPrecise,
			DaysRemainingTruncated:    certExpMeta.daysRemainingTruncated,
			LifetimePercent:           certExpMeta.certLifetimePercent,
			ValidityPeriodDescription: validityPeriodDescription,
			ValidityPeriodDays:        certExpMeta.validityPeriodDays,
			Summary:                   expiresText,
			Status:                    certStatus,
			SignatureAlgorithm:        origCert.SignatureAlgorithm.String(),
			Type:                      certs.ChainPosition(origCert, certChain),
		}

		certChainSubset = append(certChainSubset, certSubset)
	}

	hasMissingIntermediateCerts := certs.NumIntermediateCerts(certChain) == 0
	hasExpiredCerts := certs.HasExpiredCert(certChain)
	hasHostnameMismatch := !hostnameValidationResult.IsOKState()
	hasMissingSANsEntries := func(certChain []*x509.Certificate) bool {
		leafCerts := certs.LeafCerts(certChain)
		for _, leafCert := range leafCerts {
			if len(leafCert.DNSNames) > 0 {
				return false
			}
		}

		return true
	}(certChain)

	hasDuplicateCertsInChain := func(certChain []*x509.Certificate) bool {
		certIdx := make(map[string]int, len(certChain))

		for _, cert := range certChain {
			certIdx[certs.FormatCertSerialNumber(cert.SerialNumber)]++
		}

		for _, v := range certIdx {
			if v > 1 {
				return true
			}
		}

		return false
	}(certChain)

	hasSelfSignedLeaf := func(certChain []*x509.Certificate) bool {
		leafCerts := certs.LeafCerts(certChain)
		for _, leafCert := range leafCerts {
			// NOTE: We may need to perform actual signature verification here for
			// the most reliable results.
			if leafCert.Issuer.String() == leafCert.Subject.String() {
				return true
			}
		}

		return false
	}(certChain)

	// hasWeakSignatureAlgorithm indicates that the certificate chain has been
	// signed using a cryptographically weak hashing algorithm (e.g. MD2, MD4,
	// MD5, or SHA1). These signature algorithms are known to be vulnerable to
	// collision attacks. An attacker can exploit this to generate another
	// certificate with the same digital signature, allowing an attacker to
	// masquerade as the affected service.
	//
	// NOTE: This does not apply to trusted root certificates; TLS clients
	// trust them by their identity instead of the signature of their hash;
	// client code setting this field would need to exclude root certificates
	// from the determination whether the chain is vulnerable to weak
	// signature algorithms.
	//
	//   - https://security.googleblog.com/2014/09/gradually-sunsetting-sha-1.html
	//   - https://security.googleblog.com/2015/12/an-update-on-sha-1-certificates-in.html
	//   - https://superuser.com/questions/1122069/why-are-root-cas-with-sha1-signatures-not-a-risk
	//   - https://developer.mozilla.org/en-US/docs/Web/Security/Weak_Signature_Algorithm
	//   - https://www.tenable.com/plugins/nessus/35291
	//   - https://docs.ostorlab.co/kb/WEAK_HASHING_ALGO/index.html
	hasWeakSignatureAlgorithm := func(certChain []*x509.Certificate) bool {
		nonRootCerts := certs.NonRootCerts(certChain)

		log := cfg.Log.With().Logger()

		log.Debug().Int("num_certs", len(nonRootCerts)).Msg("Evaluating certificates for weak signature algorithm")

		logWeak := func(cert *x509.Certificate) {
			log.Debug().
				Bool("cert_signature_algorithm_ok", false).
				Str("cert_signature_algorithm", cert.SignatureAlgorithm.String()).
				Str("cert_common_name", cert.Subject.CommonName).
				Msg("Certificate signature algorithm weak")
		}

		logOK := func(cert *x509.Certificate) {
			log.Debug().
				Bool("cert_signature_algorithm_ok", true).
				Str("cert_signature_algorithm", cert.SignatureAlgorithm.String()).
				Str("cert_common_name", cert.Subject.CommonName).
				Msg("Certificate signature algorithm ok")
		}

		for _, cert := range nonRootCerts {
			switch {
			case certs.HasWeakSignatureAlgorithm(cert):
				logWeak(cert)

				return true

			default:
				logOK(cert)
			}
		}

		return false
	}(certChain)

	certChainIssues := payload.CertificateChainIssues{
		MissingIntermediateCerts: hasMissingIntermediateCerts,
		MissingSANsEntries:       hasMissingSANsEntries,
		DuplicateCerts:           hasDuplicateCertsInChain,
		// MisorderedCerts:          false, // FIXME: Placeholder value
		ExpiredCerts:           hasExpiredCerts,
		HostnameMismatch:       hasHostnameMismatch,
		SelfSignedLeafCert:     hasSelfSignedLeaf,
		WeakSignatureAlgorithm: hasWeakSignatureAlgorithm,
	}

	// Only if the user explicitly requested the full cert payload do we
	// include it (due to significant payload size increase and risk of
	// exceeding size constraints).
	var certChainOriginal []string
	switch {
	case cfg.EmitPayloadWithFullChain:
		pemCertChain, err := payload.CertChainToPEM(certChain)
		if err != nil {
			return "", fmt.Errorf("error converting original cert chain to PEM format: %w", err)
		}

		certChainOriginal = pemCertChain

	default:
		certChainOriginal = nil
	}

	payload := payload.CertChainPayload{
		CertChainOriginal: certChainOriginal,
		CertChainSubset:   certChainSubset,
		Server:            cfg.Server,
		DNSName:           cfg.DNSName,
		TCPPort:           cfg.Port,
		Issues:            certChainIssues,
		ServiceState:      expirationValidationResult.ServiceState().Label,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf(
			"error marshaling cert chain payload as JSON: %w",
			err,
		)
	}

	return string(payloadJSON), nil
}

// addCertChainPayload is a helper function that prepares a certificate chain
// payload as a JSON encoded value for inclusion in plugin output.
func addCertChainPayload(plugin *nagios.Plugin, cfg *config.Config, validationResults certs.CertChainValidationResults) {
	certChainSummary, certSummaryErr := buildCertSummary(cfg, validationResults)

	log := cfg.Log.With().Logger()

	if certSummaryErr != nil {
		log.Error().
			Err(certSummaryErr).
			Msg("failed to generate cert chain summary for encoded payload")

		plugin.Errors = append(plugin.Errors, certSummaryErr)

		plugin.ExitStatusCode = nagios.StateUNKNOWNExitCode
		plugin.ServiceOutput = fmt.Sprintf(
			"%s: Failed to add encoded payload",
			nagios.StateUNKNOWNLabel,
		)

		return
	}

	// fmt.Fprintln(os.Stderr, certChainSummary)
	log.Debug().Str("json_payload", certChainSummary).Msg("JSON payload before encoding")

	// NOTE: AddPayloadString will NOT return an error if empty input is
	// provided.
	if _, err := plugin.AddPayloadString(certChainSummary); err != nil {
		log.Error().
			Err(err).
			Msg("failed to add encoded payload")

		plugin.Errors = append(plugin.Errors, err)

		plugin.ExitStatusCode = nagios.StateUNKNOWNExitCode
		plugin.ServiceOutput = fmt.Sprintf(
			"%s: Failed to add encoded payload",
			nagios.StateUNKNOWNLabel,
		)

		return
	}
}

// lookupValidityPeriodDescription is a helper function to lookup human
// readable validity period description for a certificate's maximum lifetime
// value.
func lookupValidityPeriodDescription(cert *x509.Certificate) string {
	maxLifeSpanInDays, err := certs.MaxLifespanInDays(cert)
	if err != nil {
		return payload.ValidityPeriodUNKNOWN
	}

	maxLifeSpanInTruncatedYears := int(math.Trunc(float64(maxLifeSpanInDays) / 365))

	switch {
	case maxLifeSpanInTruncatedYears >= 1:
		return fmt.Sprintf("%d year", maxLifeSpanInTruncatedYears)

	default:
		return fmt.Sprintf("%d days", maxLifeSpanInDays)
	}
}

// isBetween is a small helper function to determine whether a given value is
// between a specified minimum and maximum number (inclusive).
// func isBetween(val, min, max int) bool {
// 	if (val >= min) && (val <= max) {
// 		return true
// 	}
//
// 	return false
// }
