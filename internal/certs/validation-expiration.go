// Copyright 2022 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package certs

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/atc0005/go-nagios"
)

// Add an "implements assertion" to fail the build if the interface
// implementation isn't correct.
var _ CertChainValidationResult = (*ExpirationValidationResult)(nil)

// ExpirationValidationResult is the validation result from performing
// expiration validation against each certificate in a chain.
type ExpirationValidationResult struct {
	// certChain is the collection of certificates that we evaluated to
	// produce this validation check result.
	certChain []*x509.Certificate

	// filteredCertChain is the original certificate chain minus any
	// certificates that the sysadmin has opted to ignore.
	//
	// If the sysadmin did not opt to ignore any certificates then the
	// returned certificate chain is unchanged from the original.
	filteredCertChain []*x509.Certificate

	// err is the "final" error describing the validation attempt.
	err error

	// ignored indicates whether validation check results are ignored for the
	// certificate chain.
	ignored bool

	// validationOptions tracks what validation options were chosen by the
	// sysadmin.
	validationOptions CertChainValidationOptions

	// verboseOutput indicates whether user has requested verbose validation
	// results output.
	verboseOutput bool

	// omitSANsEntries indicates that SANs entries should be omitted in
	// certificate report details.
	omitSANsEntries bool

	// hasExpiredCerts indicates whether any certificates in the chain have
	// expired.
	hasExpiredCerts bool

	// hasExpiringCerts indicates whether any certificates in the chain are
	// expiring soon.
	hasExpiringCerts bool

	// hasExpiredIntermediateCerts indicates whether any intermediate
	// certificates in the chain have expired.
	hasExpiredIntermediateCerts bool

	// hasExpiredRootCerts indicates whether any root certificates in the
	// chain have expired.
	hasExpiredRootCerts bool

	// hasExpiringIntermediateCerts indicates whether any intermediate
	// certificates in the chain are expiring.
	hasExpiringIntermediateCerts bool

	// hasExpiringRootCerts indicates whether any root certificates in the
	// chain are expiring.
	hasExpiringRootCerts bool

	// numExpiredCerts indicates how many certificates in the chain have
	// expired.
	numExpiredCerts int

	// numExpiringCerts indicates how many certificates in the chain are
	// expiring soon.
	numExpiringCerts int

	// priorityModifier is applied when calculating the priority for a
	// validation check result. If a validation check result has an associated
	// error but is flagged as ignored then the base priority value is used
	// and this modifier is ignored.
	//
	// If the validation check is not flagged as ignored than this modifier is
	// used to calculate the final priority level.
	priorityModifier int

	// ageWarningThreshold is the specified age threshold for when
	// certificates in the chain with an expiration less than this value (but
	// greater than the CRITICAL threshold) are considered to be in a WARNING
	// state. This value is calculated based on user specified threshold in
	// days.
	ageWarningThreshold time.Time

	// ageCriticalThreshold is the specified age threshold for when
	// certificates in the chain with an expiration less than this value are
	// considered to be in a CRITICAL state. This value is calculated based on
	// user specified threshold in days.
	ageCriticalThreshold time.Time
}

// ValidateExpiration evaluates a given certificate chain using provided
// CRITICAL and WARNING thresholds (specified in number of days from this
// moment) for previously expired or "expiring soon" certificates. If
// specified, a flag is set to generate verbose validation output.
//
// If requested, expired intermediate or root certificates are ignored.
//
// NOTE: This validation type does not object to incorrect certificate entries
// (e.g., duplicate leaf certs) or incorrect chain order (e.g., intermediates
// before leaf cert).
func ValidateExpiration(
	certChain []*x509.Certificate,
	expireDaysCritical int,
	expireDaysWarning int,
	verboseOutput bool,
	omitSANsEntries bool,
	validationOptions CertChainValidationOptions,
) ExpirationValidationResult {

	// Perform basic validation of given values.
	switch {

	case len(certChain) == 0:
		return ExpirationValidationResult{
			certChain:         certChain,
			validationOptions: validationOptions,
			err: fmt.Errorf(
				"required certificate chain is empty: %w",
				ErrIncompleteCertificateChain,
			),
			ignored:          validationOptions.IgnoreValidationResultExpiration,
			priorityModifier: priorityModifierMaximum,
		}

	case expireDaysCritical == 0:
		return ExpirationValidationResult{
			certChain:         certChain,
			validationOptions: validationOptions,
			err: fmt.Errorf(
				"required CRITICAL certificate age threshold (in days) is required"+
					" for expiration validation: %w",
				ErrMissingValue,
			),
			ignored:          validationOptions.IgnoreValidationResultExpiration,
			priorityModifier: priorityModifierMaximum,
		}

	case expireDaysWarning == 0:
		return ExpirationValidationResult{
			certChain:         certChain,
			validationOptions: validationOptions,
			err: fmt.Errorf(
				"required WARNING certificate age threshold (in days) is required"+
					" for expiration validation: %w",
				ErrMissingValue,
			),
			ignored:          validationOptions.IgnoreValidationResultExpiration,
			priorityModifier: priorityModifierMaximum,
		}

	}

	now := time.Now().UTC()
	certsExpireAgeWarning := now.AddDate(0, 0, expireDaysWarning)
	certsExpireAgeCritical := now.AddDate(0, 0, expireDaysCritical)

	hasExpiredCerts := HasExpiredCert(certChain)
	numExpiredCerts := NumExpiredCerts(certChain)

	hasExpiringCerts := HasExpiringCert(
		certChain,
		certsExpireAgeCritical,
		certsExpireAgeWarning,
	)
	numExpiringCerts := NumExpiringCerts(
		certChain,
		certsExpireAgeCritical,
		certsExpireAgeWarning,
	)

	hasExpiringLeafCerts := HasExpiringCert(
		LeafCerts(certChain),
		certsExpireAgeCritical,
		certsExpireAgeWarning,
	)

	hasExpiringIntermediateCerts := HasExpiringCert(
		IntermediateCerts(certChain),
		certsExpireAgeCritical,
		certsExpireAgeWarning,
	)

	hasExpiringRootCerts := HasExpiringCert(
		RootCerts(certChain),
		certsExpireAgeCritical,
		certsExpireAgeWarning,
	)

	hasExpiredLeafCerts := HasExpiredCert(
		LeafCerts(certChain),
	)

	hasExpiredIntermediateCerts := HasExpiredCert(
		IntermediateCerts(certChain),
	)

	hasExpiredRootCerts := HasExpiredCert(
		RootCerts(certChain),
	)

	filteredCerts := filterCertificateChain(certChain, validationOptions, certsExpireAgeCritical, certsExpireAgeWarning)

	// Process certificates expiration status checks.
	switch {
	case hasExpiredLeafCerts:
		return ExpirationValidationResult{
			certChain:         certChain,
			filteredCertChain: filteredCerts,
			err: fmt.Errorf(
				"expiration validation failed: %w",
				ErrExpiredCertsFound,
			),
			validationOptions:            validationOptions,
			ignored:                      validationOptions.IgnoreValidationResultExpiration,
			verboseOutput:                verboseOutput,
			omitSANsEntries:              omitSANsEntries,
			ageWarningThreshold:          certsExpireAgeWarning,
			ageCriticalThreshold:         certsExpireAgeCritical,
			hasExpiredCerts:              hasExpiredCerts,
			hasExpiringCerts:             hasExpiringCerts,
			hasExpiredIntermediateCerts:  hasExpiredIntermediateCerts,
			hasExpiredRootCerts:          hasExpiredRootCerts,
			hasExpiringIntermediateCerts: hasExpiringIntermediateCerts,
			hasExpiringRootCerts:         hasExpiringRootCerts,
			numExpiredCerts:              numExpiredCerts,
			numExpiringCerts:             numExpiringCerts,
			priorityModifier:             priorityModifierMaximum,
		}

	case hasExpiringLeafCerts:
		return ExpirationValidationResult{
			certChain:         certChain,
			filteredCertChain: filteredCerts,
			err: fmt.Errorf(
				"expiration validation failed: %w",
				ErrExpiringCertsFound,
			),
			validationOptions:            validationOptions,
			ignored:                      validationOptions.IgnoreValidationResultExpiration,
			verboseOutput:                verboseOutput,
			omitSANsEntries:              omitSANsEntries,
			ageWarningThreshold:          certsExpireAgeWarning,
			ageCriticalThreshold:         certsExpireAgeCritical,
			hasExpiredCerts:              hasExpiredCerts,
			hasExpiringCerts:             hasExpiringCerts,
			hasExpiredIntermediateCerts:  hasExpiredIntermediateCerts,
			hasExpiredRootCerts:          hasExpiredRootCerts,
			hasExpiringIntermediateCerts: hasExpiringIntermediateCerts,
			hasExpiringRootCerts:         hasExpiringRootCerts,
			numExpiredCerts:              numExpiredCerts,
			numExpiringCerts:             numExpiringCerts,
			priorityModifier:             priorityModifierMinimum,
		}

	case hasExpiringIntermediateCerts &&
		!validationOptions.IgnoreExpiringIntermediateCertificates:

		return ExpirationValidationResult{
			certChain:         certChain,
			filteredCertChain: filteredCerts,
			err: fmt.Errorf(
				"expiration validation failed: %w",
				ErrExpiringCertsFound,
			),
			validationOptions:            validationOptions,
			ignored:                      validationOptions.IgnoreValidationResultExpiration,
			verboseOutput:                verboseOutput,
			omitSANsEntries:              omitSANsEntries,
			ageWarningThreshold:          certsExpireAgeWarning,
			ageCriticalThreshold:         certsExpireAgeCritical,
			hasExpiredCerts:              hasExpiredCerts,
			hasExpiringCerts:             hasExpiringCerts,
			hasExpiredIntermediateCerts:  hasExpiredIntermediateCerts,
			hasExpiredRootCerts:          hasExpiredRootCerts,
			hasExpiringIntermediateCerts: hasExpiringIntermediateCerts,
			hasExpiringRootCerts:         hasExpiringRootCerts,
			numExpiredCerts:              numExpiredCerts,
			numExpiringCerts:             numExpiringCerts,
			priorityModifier:             priorityModifierMinimum,
		}

	case hasExpiringRootCerts &&
		!validationOptions.IgnoreExpiringRootCertificates:

		return ExpirationValidationResult{
			certChain:         certChain,
			filteredCertChain: filteredCerts,
			err: fmt.Errorf(
				"expiration validation failed: %w",
				ErrExpiringCertsFound,
			),
			validationOptions:            validationOptions,
			ignored:                      validationOptions.IgnoreValidationResultExpiration,
			verboseOutput:                verboseOutput,
			omitSANsEntries:              omitSANsEntries,
			ageWarningThreshold:          certsExpireAgeWarning,
			ageCriticalThreshold:         certsExpireAgeCritical,
			hasExpiredCerts:              hasExpiredCerts,
			hasExpiringCerts:             hasExpiringCerts,
			hasExpiredIntermediateCerts:  hasExpiredIntermediateCerts,
			hasExpiredRootCerts:          hasExpiredRootCerts,
			hasExpiringIntermediateCerts: hasExpiringIntermediateCerts,
			hasExpiringRootCerts:         hasExpiringRootCerts,
			numExpiredCerts:              numExpiredCerts,
			numExpiringCerts:             numExpiringCerts,
			priorityModifier:             priorityModifierMinimum,
		}

	case hasExpiredIntermediateCerts &&
		!validationOptions.IgnoreExpiredIntermediateCertificates:

		return ExpirationValidationResult{
			certChain:         certChain,
			filteredCertChain: filteredCerts,
			err: fmt.Errorf(
				"expiration validation failed: %w",
				ErrExpiredCertsFound,
			),
			validationOptions:            validationOptions,
			ignored:                      validationOptions.IgnoreValidationResultExpiration,
			verboseOutput:                verboseOutput,
			omitSANsEntries:              omitSANsEntries,
			ageWarningThreshold:          certsExpireAgeWarning,
			ageCriticalThreshold:         certsExpireAgeCritical,
			hasExpiredCerts:              hasExpiredCerts,
			hasExpiringCerts:             hasExpiringCerts,
			hasExpiredIntermediateCerts:  hasExpiredIntermediateCerts,
			hasExpiredRootCerts:          hasExpiredRootCerts,
			hasExpiringIntermediateCerts: hasExpiringIntermediateCerts,
			hasExpiringRootCerts:         hasExpiringRootCerts,
			numExpiredCerts:              numExpiredCerts,
			numExpiringCerts:             numExpiringCerts,
			priorityModifier:             priorityModifierMaximum,
		}

	case hasExpiredRootCerts &&
		!validationOptions.IgnoreExpiredRootCertificates:

		return ExpirationValidationResult{
			certChain:         certChain,
			filteredCertChain: filteredCerts,
			err: fmt.Errorf(
				"expiration validation failed: %w",
				ErrExpiredCertsFound,
			),
			validationOptions:            validationOptions,
			ignored:                      validationOptions.IgnoreValidationResultExpiration,
			verboseOutput:                verboseOutput,
			omitSANsEntries:              omitSANsEntries,
			ageWarningThreshold:          certsExpireAgeWarning,
			ageCriticalThreshold:         certsExpireAgeCritical,
			hasExpiredCerts:              hasExpiredCerts,
			hasExpiringCerts:             hasExpiringCerts,
			hasExpiredIntermediateCerts:  hasExpiredIntermediateCerts,
			hasExpiredRootCerts:          hasExpiredRootCerts,
			hasExpiringIntermediateCerts: hasExpiringIntermediateCerts,
			hasExpiringRootCerts:         hasExpiringRootCerts,
			numExpiredCerts:              numExpiredCerts,
			numExpiringCerts:             numExpiringCerts,
			priorityModifier:             priorityModifierMinimum,
		}

	case hasExpiredIntermediateCerts &&
		validationOptions.IgnoreExpiredIntermediateCertificates:

		return ExpirationValidationResult{
			certChain:         certChain,
			filteredCertChain: filteredCerts,
			err: fmt.Errorf(
				"expiration validation failed: %w",
				ErrExpiredCertsFound,
			),
			validationOptions: validationOptions,

			// NOTE:
			//
			// Because we set this, we end up flagging the entire expiration
			// validation check as ignored. This excludes the next expiring
			// certificate from the ServiceOutput and thus the service check
			// one-line summary.
			//
			// When the *leaf* certificate approaches expiration or is expired
			// then that will cause the expiration validation check to take
			// precedence again and no longer be ignored. This seems
			// acceptable behavior for now.
			ignored:                      validationOptions.IgnoreExpiredIntermediateCertificates,
			verboseOutput:                verboseOutput,
			omitSANsEntries:              omitSANsEntries,
			ageWarningThreshold:          certsExpireAgeWarning,
			ageCriticalThreshold:         certsExpireAgeCritical,
			hasExpiredCerts:              hasExpiredCerts,
			hasExpiringCerts:             hasExpiringCerts,
			hasExpiredIntermediateCerts:  hasExpiredIntermediateCerts,
			hasExpiredRootCerts:          hasExpiredRootCerts,
			hasExpiringIntermediateCerts: hasExpiringIntermediateCerts,
			hasExpiringRootCerts:         hasExpiringRootCerts,
			numExpiredCerts:              numExpiredCerts,
			numExpiringCerts:             numExpiringCerts,
			priorityModifier:             priorityModifierBaseline,
		}

	case hasExpiredRootCerts &&
		validationOptions.IgnoreExpiredRootCertificates:

		return ExpirationValidationResult{
			certChain:         certChain,
			filteredCertChain: filteredCerts,
			err: fmt.Errorf(
				"expiration validation failed: %w",
				ErrExpiredCertsFound,
			),
			validationOptions: validationOptions,

			// NOTE:
			//
			// Because we set this, we end up flagging the entire expiration
			// validation check as ignored. This excludes the next expiring
			// certificate from the ServiceOutput and thus the service check
			// one-line summary.
			//
			// When the *leaf* certificate approaches expiration or is expired
			// then that will cause the expiration validation check to take
			// precedence again and no longer be ignored. This seems
			// acceptable behavior for now.
			ignored:                      validationOptions.IgnoreExpiredRootCertificates,
			verboseOutput:                verboseOutput,
			omitSANsEntries:              omitSANsEntries,
			ageWarningThreshold:          certsExpireAgeWarning,
			ageCriticalThreshold:         certsExpireAgeCritical,
			hasExpiredCerts:              hasExpiredCerts,
			hasExpiringCerts:             hasExpiringCerts,
			hasExpiredIntermediateCerts:  hasExpiredIntermediateCerts,
			hasExpiredRootCerts:          hasExpiredRootCerts,
			hasExpiringIntermediateCerts: hasExpiringIntermediateCerts,
			hasExpiringRootCerts:         hasExpiringRootCerts,
			numExpiredCerts:              numExpiredCerts,
			numExpiringCerts:             numExpiringCerts,
			priorityModifier:             priorityModifierBaseline,
		}

	case hasExpiringIntermediateCerts &&
		validationOptions.IgnoreExpiringIntermediateCertificates:

		return ExpirationValidationResult{
			certChain:         certChain,
			filteredCertChain: filteredCerts,
			err: fmt.Errorf(
				"expiration validation failed: %w",
				ErrExpiringCertsFound,
			),
			validationOptions: validationOptions,

			// NOTE:
			//
			// Because we set this, we end up flagging the entire expiration
			// validation check as ignored. This excludes the next expiring
			// certificate from the ServiceOutput and thus the service check
			// one-line summary.
			//
			// When the *leaf* certificate approaches expiration or is expired
			// then that will cause the expiration validation check to take
			// precedence again and no longer be ignored. This seems
			// acceptable behavior for now.
			ignored:                      validationOptions.IgnoreExpiringIntermediateCertificates,
			verboseOutput:                verboseOutput,
			omitSANsEntries:              omitSANsEntries,
			ageWarningThreshold:          certsExpireAgeWarning,
			ageCriticalThreshold:         certsExpireAgeCritical,
			hasExpiredCerts:              hasExpiredCerts,
			hasExpiringCerts:             hasExpiringCerts,
			hasExpiredIntermediateCerts:  hasExpiredIntermediateCerts,
			hasExpiredRootCerts:          hasExpiredRootCerts,
			hasExpiringIntermediateCerts: hasExpiringIntermediateCerts,
			hasExpiringRootCerts:         hasExpiringRootCerts,
			numExpiredCerts:              numExpiredCerts,
			numExpiringCerts:             numExpiringCerts,
			priorityModifier:             priorityModifierBaseline,
		}

	case hasExpiringRootCerts &&
		validationOptions.IgnoreExpiringRootCertificates:

		return ExpirationValidationResult{
			certChain:         certChain,
			filteredCertChain: filteredCerts,
			err: fmt.Errorf(
				"expiration validation failed: %w",
				ErrExpiringCertsFound,
			),
			validationOptions: validationOptions,

			// NOTE:
			//
			// Because we set this, we end up flagging the entire expiration
			// validation check as ignored. This excludes the next expiring
			// certificate from the ServiceOutput and thus the service check
			// one-line summary.
			//
			// When the *leaf* certificate approaches expiration or is expired
			// then that will cause the expiration validation check to take
			// precedence again and no longer be ignored. This seems
			// acceptable behavior for now.
			ignored:                      validationOptions.IgnoreExpiringRootCertificates,
			verboseOutput:                verboseOutput,
			omitSANsEntries:              omitSANsEntries,
			ageWarningThreshold:          certsExpireAgeWarning,
			ageCriticalThreshold:         certsExpireAgeCritical,
			hasExpiredCerts:              hasExpiredCerts,
			hasExpiringCerts:             hasExpiringCerts,
			hasExpiredIntermediateCerts:  hasExpiredIntermediateCerts,
			hasExpiredRootCerts:          hasExpiredRootCerts,
			hasExpiringIntermediateCerts: hasExpiringIntermediateCerts,
			hasExpiringRootCerts:         hasExpiringRootCerts,
			numExpiredCerts:              numExpiredCerts,
			numExpiringCerts:             numExpiringCerts,
			priorityModifier:             priorityModifierBaseline,
		}

	default:
		// Neither expired nor expiring certificates.
		return ExpirationValidationResult{
			certChain:                    certChain,
			filteredCertChain:            filteredCerts,
			err:                          nil,
			validationOptions:            validationOptions,
			ignored:                      validationOptions.IgnoreValidationResultExpiration,
			verboseOutput:                verboseOutput,
			omitSANsEntries:              omitSANsEntries,
			ageWarningThreshold:          certsExpireAgeWarning,
			ageCriticalThreshold:         certsExpireAgeCritical,
			hasExpiredCerts:              hasExpiredCerts,
			hasExpiringCerts:             hasExpiringCerts,
			hasExpiredIntermediateCerts:  hasExpiredIntermediateCerts,
			hasExpiredRootCerts:          hasExpiredRootCerts,
			hasExpiringIntermediateCerts: hasExpiringIntermediateCerts,
			hasExpiringRootCerts:         hasExpiringRootCerts,
			numExpiredCerts:              numExpiredCerts,
			numExpiringCerts:             numExpiringCerts,
			priorityModifier:             priorityModifierBaseline,
		}
	}

}

// CheckName emits the human-readable name of this validation check result.
func (evr ExpirationValidationResult) CheckName() string {
	return checkNameExpirationValidationResult
}

// CertChain returns the evaluated certificate chain.
func (evr ExpirationValidationResult) CertChain() []*x509.Certificate {
	return evr.certChain
}

// TotalCerts returns the number of certificates in the evaluated certificate
// chain.
func (evr ExpirationValidationResult) TotalCerts() int {
	return len(evr.certChain)
}

// IsWarningState indicates whether this validation check result is in a
// WARNING state. This returns false if the validation check resulted in an OK
// or CRITICAL state, or is flagged as ignored. True is returned otherwise.
func (evr ExpirationValidationResult) IsWarningState() bool {

	if evr.IsIgnored() {
		return false
	}

	// for _, cert := range evr.certChain {
	for _, cert := range evr.FilteredCertificateChain() {
		if IsExpiringCert(cert, evr.ageCriticalThreshold, evr.ageWarningThreshold) {
			return true
		}
	}

	return false
}

// IsCriticalState indicates whether this validation check result is in a
// CRITICAL state. This returns false if the validation check resulted in an
// OK or WARNING state, or is flagged as ignored. True is returned otherwise.
func (evr ExpirationValidationResult) IsCriticalState() bool {

	if evr.IsIgnored() {
		return false
	}

	// for _, cert := range evr.certChain {
	for _, cert := range evr.FilteredCertificateChain() {
		if IsExpiredCert(cert) || cert.NotAfter.Before(evr.ageCriticalThreshold) {
			return true
		}
	}

	return false
}

// IsUnknownState indicates whether this validation check result is in an
// UNKNOWN state.
func (evr ExpirationValidationResult) IsUnknownState() bool {
	// This state is not used for this certificate validation check.
	return false
}

// IsOKState indicates whether this validation check result is in an OK or
// passing state. For the purposes of validation check evaluation, ignored
// validation checks are considered to be a subset of OK status.
func (evr ExpirationValidationResult) IsOKState() bool {
	return evr.err == nil || evr.IsIgnored()
}

// IsIgnored indicates whether this validation check result was flagged as
// ignored for the purposes of determining final validation state.
func (evr ExpirationValidationResult) IsIgnored() bool {
	return evr.ignored
}

// IsSucceeded indicates whether this validation check result is not flagged
// as ignored and no problems with the certificate chain were identified.
func (evr ExpirationValidationResult) IsSucceeded() bool {
	return evr.IsOKState() && !evr.IsIgnored()
}

// IsFailed indicates whether this validation check result is not flagged as
// ignored and problems were identified.
func (evr ExpirationValidationResult) IsFailed() bool {
	return evr.err != nil && !evr.IsIgnored()
}

// Err returns the underlying error (if any) regardless of whether this
// validation check result is flagged as ignored.
func (evr ExpirationValidationResult) Err() error {
	return evr.err
}

// ServiceState returns the appropriate Service Check Status label and exit
// code for this validation check result.
func (evr ExpirationValidationResult) ServiceState() nagios.ServiceState {
	return ServiceState(evr)
}

// Priority indicates the level of importance for this validation check
// result.
//
// This value is calculated by applying a priority modifier for specific
// failure conditions (recorded when the validation check result is
// initially obtained) to a baseline value specific to the validation
// check performed.
//
// If the validation check result is flagged as ignored the priority
// modifier is also ignored.
func (evr ExpirationValidationResult) Priority() int {
	switch {
	case evr.ignored:
		return baselinePriorityExpirationValidationResult
	default:
		return baselinePriorityExpirationValidationResult + evr.priorityModifier
	}
}

// Overview provides a high-level summary of this validation check result.
func (evr ExpirationValidationResult) Overview() string {
	return fmt.Sprintf(
		"[EXPIRED: %d, EXPIRING: %d, OK: %d]",
		evr.NumExpiredCerts(),
		evr.NumExpiringCerts(),
		evr.NumValidCerts(),
	)
}

// Status is intended as a brief status of the validation check result. This
// can be used as initial lead-in text.
func (evr ExpirationValidationResult) Status() string {
	// Provide a modified certificate chain that excludes any certificates
	// that a sysadmin has requested we ignore.
	//
	// We evaluate the filtered certificate chain instead of the original in
	// case the sysadmin opted to exclude intermediate or root certificates
	// based on expiring or expired status.
	certChainFiltered := evr.FilteredCertificateChain()

	nextCertToExpire := NextToExpire(certChainFiltered, false)

	// Start by assuming that the CommonName is *not* blank
	nextCertToExpireServerName := nextCertToExpire.Subject.CommonName

	// but if it is, use the first SubjectAlternateName field in its place
	if nextCertToExpire.Subject.CommonName == "" {
		if len(nextCertToExpire.DNSNames[0]) > 0 {
			nextCertToExpireServerName = nextCertToExpire.DNSNames[0]
		}
	}

	var summaryTemplate string

	switch {
	case HasExpiredCert(certChainFiltered):
		summaryTemplate = ExpirationValidationOneLineSummaryExpiredTmpl
	case HasExpiringCert(certChainFiltered, evr.ageCriticalThreshold, evr.ageWarningThreshold):
		summaryTemplate = ExpirationValidationOneLineSummaryExpiresNextTmpl
	default:
		summaryTemplate = ExpirationValidationOneLineSummaryExpiresNextTmpl
	}

	chainPosition := ChainPosition(nextCertToExpire, evr.certChain)

	return fmt.Sprintf(
		summaryTemplate,
		evr.CheckName(),
		evr.ValidationStatus(),
		chainPosition,
		nextCertToExpireServerName,
		FormattedExpiration(nextCertToExpire.NotAfter),
		nextCertToExpire.NotAfter.Format(CertValidityDateLayout),
	)

}

// StatusDetail provides additional details intended to extend the shorter
// status text with information suitable as explanation for the overall state
// of the validation check result. This text may span multiple lines.
func (evr ExpirationValidationResult) StatusDetail() string {
	return GenerateCertChainReport(
		evr.certChain,
		evr.ageCriticalThreshold,
		evr.ageWarningThreshold,
		evr.verboseOutput,
		evr.validationOptions,
		evr.omitSANsEntries,
	)
}

// String provides the validation check result in human-readable format.
// Because the certificates chain report is so detailed we skip emitting those
// details.
func (evr ExpirationValidationResult) String() string {
	return fmt.Sprintf(
		"%s %s",
		evr.Status(),
		evr.Overview(),
	)
}

// Report provides the validation check result in verbose human-readable
// format.
func (evr ExpirationValidationResult) Report() string {
	switch {
	case evr.ignored:

		// provide overview only
		statusSummary := fmt.Sprintf(
			"%d expired certificates, %d expiring certificates",
			evr.numExpiredCerts,
			evr.numExpiringCerts,
		)

		return fmt.Sprintf(
			"%s validation %s: %s%s%s%s",
			evr.CheckName(),
			evr.ValidationStatus(),
			statusSummary,
			nagios.CheckOutputEOL,
			nagios.CheckOutputEOL,
			evr.StatusDetail(),
		)

	default:

		// provide detailed listing
		return fmt.Sprintf(
			"%s %s%s%s",
			evr.Status(),
			nagios.CheckOutputEOL,
			nagios.CheckOutputEOL,
			evr.StatusDetail(),
		)
	}

}

// HasExpiredCerts indicates whether any certificates in the chain have
// expired.
func (evr ExpirationValidationResult) HasExpiredCerts() bool {
	// return HasExpiredCert(evr.certChain)
	return evr.hasExpiredCerts
}

// NumExpiredCerts indicates how many certificates in the chain have expired.
func (evr ExpirationValidationResult) NumExpiredCerts() int {
	// return NumExpiredCerts(evr.certChain)
	return evr.numExpiredCerts
}

// HasExpiringCerts indicates whether any certificates in the chain are
// expiring soon. Any already expired certificates are ignored.
func (evr ExpirationValidationResult) HasExpiringCerts() bool {
	// return HasExpiringCert(
	// 	evr.certChain,
	// 	evr.ageCriticalThreshold,
	// 	evr.ageWarningThreshold,
	// )
	return evr.hasExpiringCerts
}

// NumExpiringCerts indicates the number of certificates in the chain that are
// expiring soon. Any already expired certificates are ignored.
func (evr ExpirationValidationResult) NumExpiringCerts() int {
	// return NumExpiringCerts(
	// 	evr.certChain,
	// 	evr.ageCriticalThreshold,
	// 	evr.ageWarningThreshold,
	// )
	return evr.numExpiringCerts
}

// NumValidCerts indicates the number of certificates in the chain that are
// not expired and not expiring soon.
func (evr ExpirationValidationResult) NumValidCerts() int {
	// return evr.TotalCerts() - evr.NumExpiredCerts() - evr.NumExpiringCerts()
	return evr.TotalCerts() - evr.numExpiredCerts - evr.numExpiringCerts
}

// WarningDateThreshold returns a formatted version of the WARNING date
// threshold used when calculating this validation check result.
func (evr ExpirationValidationResult) WarningDateThreshold() string {
	return evr.ageWarningThreshold.Format(CertValidityDateLayout)
}

// CriticalDateThreshold returns a formatted version of the CRITICAL date
// threshold used when calculating this validation check result.
func (evr ExpirationValidationResult) CriticalDateThreshold() string {
	return evr.ageWarningThreshold.Format(CertValidityDateLayout)
}

// FilteredCertificateChain returns the original certificate chain minus any
// certificates that the sysadmin has opted to ignore. The first leaf
// certificate encountered that is expired or expiring is returned by itself
// in order to give it the highest precedence.
//
// If the sysadmin did not opt to ignore any certificates then the returned
// certificate chain is unchanged from the original.
func (evr ExpirationValidationResult) FilteredCertificateChain() []*x509.Certificate {
	switch {
	case len(evr.filteredCertChain) > 0:
		return evr.filteredCertChain
	default:
		return evr.certChain
	}
}

// ValidationStatus provides a one word status value for expiration validation
// check results. If the original certificate chain was filtered then the
// validation status value is based on the filtered chain, otherwise the
// original certificate chain is used.
func (evr ExpirationValidationResult) ValidationStatus() string {
	switch {
	case evr.IsFailed():
		return ValidationStatusFailed
	case evr.IsIgnored():
		return ValidationStatusIgnored
	default:
		return ValidationStatusSuccessful
	}
}

// AgeWarningThreshold returns the value of the warning threshold based on the
// user specified value in days. Certificates in the chain with an expiration
// less than this value (but greater than the CRITICAL threshold) are
// considered to be in a WARNING state.
func (evr ExpirationValidationResult) AgeWarningThreshold() time.Time {
	return evr.ageWarningThreshold
}

// AgeCriticalThreshold returns the value of the CRITICAL threshold based on
// the user specified value in days. Certificates in the chain with an
// expiration less than this value are considered to be in a CRITICAL state.
func (evr ExpirationValidationResult) AgeCriticalThreshold() time.Time {
	return evr.ageCriticalThreshold
}

// filterCertificateChain filters a given certificate chain excluding any
// certificates that the sysadmin has opted to ignore. The first leaf
// certificate encountered that is expired or expiring is returned by itself
// in order to give it the highest precedence.
//
// If the sysadmin did not opt to ignore any certificates then the returned
// certificate chain is unchanged from the original.
func filterCertificateChain(
	certChain []*x509.Certificate,
	validationOptions CertChainValidationOptions,
	ageCriticalThreshold time.Time,
	ageWarningThreshold time.Time,
) []*x509.Certificate {

	certChainFiltered := make([]*x509.Certificate, 0, len(certChain))
	for _, cert := range certChain {

		// Leaf certs with issues get the highest priority. Add the first leaf
		// cert in the chain with issues to our list and skip processing any
		// further certificates in the chain.
		if IsLeafCert(cert, certChain) {
			isExpiringCert := IsExpiringCert(cert, ageCriticalThreshold, ageWarningThreshold)
			isExpiredCert := IsExpiredCert(cert)

			if isExpiredCert || isExpiringCert {
				// Instead of building a collection we need to return just
				// this one certificate (the certificate chain elements could
				// be in the wrong order and expired/expiring
				// intermediates/roots could be listed before the leaf).
				//
				// certChainFiltered = append(certChainFiltered, cert)
				// break

				return []*x509.Certificate{cert}
			}
		}

		if IsIntermediateCert(cert, certChain) {
			if IsExpiredCert(cert) &&
				validationOptions.IgnoreExpiredIntermediateCertificates {
				continue
			}

			if IsExpiringCert(cert, ageCriticalThreshold, ageWarningThreshold) &&
				validationOptions.IgnoreExpiringIntermediateCertificates {
				continue
			}
		}

		if IsRootCert(cert, certChain) {
			if IsExpiredCert(cert) &&
				validationOptions.IgnoreExpiredRootCertificates {
				continue
			}

			if IsExpiringCert(cert, ageCriticalThreshold, ageWarningThreshold) &&
				validationOptions.IgnoreExpiringRootCertificates {
				continue
			}
		}

		certChainFiltered = append(certChainFiltered, cert)
	}

	return certChainFiltered
}
