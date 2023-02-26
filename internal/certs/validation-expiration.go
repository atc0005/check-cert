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
	"strings"
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

	// err is the "final" error describing the validation attempt.
	err error

	// ignored indicates whether validation check results are ignored for the
	// certificate chain.
	ignored bool

	// verboseOutput indicates whether user has requested verbose validation
	// results output.
	verboseOutput bool

	// hasExpiredCerts indicates whether any certificates in the chain have
	// expired.
	hasExpiredCerts bool

	// hasExpiringCerts indicates whether any certificates in the chain are
	// expiring soon.
	hasExpiringCerts bool

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
	// certificates in the chain with an expiration less than this value are
	// considered to be in a WARNING state. This value is calculated based on
	// user specified threshold in days.
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
func ValidateExpiration(
	certChain []*x509.Certificate,
	expireDaysCritical int,
	expireDaysWarning int,
	shouldApply bool,
	verboseOutput bool,
) ExpirationValidationResult {

	// Ignore validation requests if explicitly requested.
	isResultIgnored := func() bool {
		return !shouldApply
	}

	// Perform basic validation of given values.
	switch {

	case len(certChain) == 0:
		return ExpirationValidationResult{
			certChain: certChain,
			err: fmt.Errorf(
				"required certificate chain is empty: %w",
				ErrMissingValue,
			),
			ignored:          isResultIgnored(),
			priorityModifier: priorityModifierMaximum,
		}

	case expireDaysCritical == 0:
		return ExpirationValidationResult{
			certChain: certChain,
			err: fmt.Errorf(
				"required CRITICAL certificate age threshold (in days) is required"+
					" for expiration validation: %w",
				ErrMissingValue,
			),
			ignored:          isResultIgnored(),
			priorityModifier: priorityModifierMaximum,
		}

	case expireDaysWarning == 0:
		return ExpirationValidationResult{
			certChain: certChain,
			err: fmt.Errorf(
				"required WARNING certificate age threshold (in days) is required"+
					" for expiration validation: %w",
				ErrMissingValue,
			),
			ignored:          isResultIgnored(),
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

	// Determine if any certs are expired.
	var err error
	var priorityModifier int
	switch {
	case hasExpiredCerts:
		err = fmt.Errorf(
			"expiration validation failed: %w",
			ErrExpiredCertsFound,
		)
		priorityModifier = priorityModifierMaximum

	case hasExpiringCerts:
		err = fmt.Errorf(
			"expiration validation failed: %w",
			ErrExpiringCertsFound,
		)
		priorityModifier = priorityModifierMinimum

	default:
		// Neither expired nor expiring certificates, so baseline priority.
	}

	return ExpirationValidationResult{
		certChain:            certChain,
		err:                  err,
		ignored:              isResultIgnored(),
		verboseOutput:        verboseOutput,
		ageWarningThreshold:  certsExpireAgeWarning,
		ageCriticalThreshold: certsExpireAgeCritical,
		hasExpiredCerts:      hasExpiredCerts,
		hasExpiringCerts:     hasExpiringCerts,
		numExpiredCerts:      numExpiredCerts,
		numExpiringCerts:     numExpiringCerts,
		priorityModifier:     priorityModifier,
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

	for _, cert := range evr.certChain {
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

	for _, cert := range evr.certChain {
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

	nextCertToExpire := NextToExpire(evr.certChain, false)

	// Start by assuming that the CommonName is *not* blank
	nextCertToExpireServerName := nextCertToExpire.Subject.CommonName

	// but if it is, use the first SubjectAlternateName field in its place
	if nextCertToExpire.Subject.CommonName == "" {
		if len(nextCertToExpire.DNSNames[0]) > 0 {
			nextCertToExpireServerName = nextCertToExpire.DNSNames[0]
		}
	}

	var summaryTemplate string
	var validationStatus string
	switch {
	case evr.hasExpiredCerts:
		summaryTemplate = ExpirationValidationOneLineSummaryExpiredTmpl
		validationStatus = "failed"
	case evr.hasExpiringCerts:
		summaryTemplate = ExpirationValidationOneLineSummaryExpiresNextTmpl
		validationStatus = "failed"
	default:
		summaryTemplate = ExpirationValidationOneLineSummaryExpiresNextTmpl
		validationStatus = "successful"
	}

	// Override status if this validation check result is ignored.
	if evr.ignored {
		validationStatus = "ignored"
	}

	chainPosition := ChainPosition(nextCertToExpire, evr.certChain)

	// Capitalize the first letter of the cert chain position; the chain
	// position value should always be longer than two characters, but guard
	// against out of range indexing all the same.
	//
	// TODO: Is this useful?
	//
	// if len(chainPosition) > 2 {
	// 	chainPosition = strings.ToUpper(chainPosition[0:1]) + chainPosition[1:]
	// }

	return fmt.Sprintf(
		summaryTemplate,
		evr.CheckName(),
		validationStatus,
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

	var detail strings.Builder

	// TODO: This feels redundant.
	//
	// We expose the error separately and while this package doesn't have
	// direct knowledge of this, we're listing the error in the Errors section
	// of the LongServiceOutput content.
	//
	// Any other tooling in this project can gain access to the error directly
	// from this specific check result OR from the collection, so it feels
	// much more modular to omit the error string from this method.
	//
	// Perhaps emit if the check result is flagged as ignored?
	//
	// if evr.err != nil && !evr.ignored {
	// 	fmt.Fprintf(
	// 		&detail,
	// 		"%s%s%s",
	// 		evr.err.Error(),
	// 		nagios.CheckOutputEOL,
	// 		nagios.CheckOutputEOL,
	// 	)
	// }

	detail.WriteString(GenerateCertChainReport(
		evr.certChain,
		evr.ageCriticalThreshold,
		evr.ageWarningThreshold,
		evr.verboseOutput,
	))

	return detail.String()
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
	return fmt.Sprintf(
		"%s %s%s%s",
		evr.Status(),
		nagios.CheckOutputEOL,
		nagios.CheckOutputEOL,
		evr.StatusDetail(),
	)
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
