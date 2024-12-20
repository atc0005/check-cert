// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package certs

import (
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/atc0005/go-nagios"
)

// Add an "implements assertion" to fail the build if the interface
// implementation isn't correct.
var _ CertChainValidationResult = (*RootValidationResult)(nil)

// Advice for sysadmins resolving cert chain issues saved in external files
// for easier maintenance.
var (
	//go:embed advice/root-cert-found.txt
	rootCertFoundAdvice string
)

// RootValidationResult is the validation result from performing
// expiration validation against each certificate in a chain.
type RootValidationResult struct {
	// certChain is the collection of certificates that we evaluated to
	// produce this validation check result.
	certChain []*x509.Certificate

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

	// numRootCerts is the number of certificates in the evaluated certificate
	// chain which were found to be root certificates.
	numRootCerts int

	// priorityModifier is applied when calculating the priority for a
	// validation check result. If a validation check result has an associated
	// error but is flagged as ignored then the base priority value is used
	// and this modifier is ignored.
	//
	// If the validation check is not flagged as ignored than this modifier is
	// used to calculate the final priority level.
	priorityModifier int
}

// ValidateRoot evaluates a given certificate chain for certificates
// determined to be a root certificate (best practice indicates it should not
// be included). If specified, a flag is set to generate verbose validation
// output.
func ValidateRoot(
	certChain []*x509.Certificate,
	verboseOutput bool,
	validationOptions CertChainValidationOptions,
) RootValidationResult {

	// Perform basic validation of given values.
	//
	// What other "basics" do we check for before we assert that a root
	// certificate is not present?

	if len(certChain) == 0 {
		return RootValidationResult{
			certChain:         certChain,
			validationOptions: validationOptions,
			err: fmt.Errorf(
				"required certificate chain is empty: %w",
				ErrNoCertsFound,
			),
			ignored:          validationOptions.IgnoreValidationResultRoot,
			priorityModifier: priorityModifierMaximum,
		}
	}

	numRootCerts := NumRootCerts(certChain)
	hasRootCert := numRootCerts > 0

	switch {
	case hasRootCert:
		return RootValidationResult{
			certChain: certChain,
			err: fmt.Errorf(
				"%s validation failed: %w",
				strings.ToLower(checkNameRootValidationResult),
				ErrRootCertsFound,
			),
			ignored:           validationOptions.IgnoreValidationResultRoot,
			validationOptions: validationOptions,
			verboseOutput:     verboseOutput,
			numRootCerts:      numRootCerts,
			priorityModifier:  priorityModifierMedium,
		}

	default:
		// No issues found.
		return RootValidationResult{
			certChain:         certChain,
			err:               nil,
			ignored:           validationOptions.IgnoreValidationResultRoot,
			validationOptions: validationOptions,
			verboseOutput:     verboseOutput,
			numRootCerts:      numRootCerts,
			priorityModifier:  priorityModifierBaseline,
		}
	}
}

// CheckName emits the human-readable name of this validation check result.
func (rvr RootValidationResult) CheckName() string {
	return checkNameRootValidationResult
}

// CertChain returns the evaluated certificate chain.
func (rvr RootValidationResult) CertChain() []*x509.Certificate {
	return rvr.certChain
}

// TotalCerts returns the number of certificates in the evaluated certificate
// chain.
func (rvr RootValidationResult) TotalCerts() int {
	return len(rvr.certChain)
}

// IsWarningState indicates whether this validation check result is in a
// WARNING state. This returns false if the validation check resulted in an OK
// or CRITICAL state, or is flagged as ignored.
func (rvr RootValidationResult) IsWarningState() bool {
	switch {
	case rvr.IsIgnored():
		return false

	case rvr.IsOKState():
		return false

	case rvr.IsCriticalState():
		return false

	case errors.Is(rvr.err, ErrRootCertsFound):
		// A certificate chain with a root certificate is considered a WARNING
		// state and not CRITICAL because the majority of modern clients
		// (e.g., browsers) will ignore it. A separate validation check
		// asserts that all included certificates are not expired (or
		// expiring).
		//
		// We explicitly handle this specific error type vs letting a more
		// general match handle it.This is as much to document the intent as
		// to provide a hook for future use.
		return true

	default:
		return false
	}
}

// IsCriticalState indicates whether this validation check result is in a
// CRITICAL state. This returns false if the validation check resulted in an
// OK or WARNING state, or is flagged as ignored.
func (rvr RootValidationResult) IsCriticalState() bool {
	switch {
	case rvr.IsIgnored():
		return false

	case errors.Is(rvr.err, ErrNoCertsFound):
		// A certificate chain missing all certificates is considered a
		// CRITICAL state because required certificates are not present. There
		// isn't anything we can reasonably check in this situation.
		return true

	default:
		return false
	}
}

// IsUnknownState indicates whether this validation check result is in an
// UNKNOWN state.
func (rvr RootValidationResult) IsUnknownState() bool {
	// This state is not used for this certificate validation check.
	return false
}

// IsOKState indicates whether this validation check result is in an OK or
// passing state. For the purposes of validation check evaluation, ignored
// validation checks are considered to be a subset of OK status.
func (rvr RootValidationResult) IsOKState() bool {
	return rvr.err == nil || rvr.IsIgnored()
}

// IsIgnored indicates whether this validation check result was flagged as
// ignored for the purposes of determining final validation state.
func (rvr RootValidationResult) IsIgnored() bool {
	return rvr.ignored
}

// IsSucceeded indicates whether this validation check result is not flagged
// as ignored and no problems with the certificate chain were identified.
func (rvr RootValidationResult) IsSucceeded() bool {
	return rvr.IsOKState() && !rvr.IsIgnored()
}

// IsFailed indicates whether this validation check result is not flagged as
// ignored and problems were identified.
func (rvr RootValidationResult) IsFailed() bool {
	return rvr.err != nil && !rvr.IsIgnored()
}

// Err returns the underlying error (if any) regardless of whether this
// validation check result is flagged as ignored.
func (rvr RootValidationResult) Err() error {
	return rvr.err
}

// ServiceState returns the appropriate Service Check Status label and exit
// code for this validation check result.
func (rvr RootValidationResult) ServiceState() nagios.ServiceState {
	return ServiceState(rvr)
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
func (rvr RootValidationResult) Priority() int {
	switch {
	case rvr.ignored:
		// Though the result is ignored, we indicate the baseline value for
		// this check result to allow this result to sort properly against
		// other check results which may also be ignored. This why we don't
		// use a value of 0 (or equivalent) here.
		return baselinePriorityRootValidationResult
	default:
		return baselinePriorityRootValidationResult + rvr.priorityModifier
	}
}

// Overview provides a high-level summary of this validation check result.
func (rvr RootValidationResult) Overview() string {
	return fmt.Sprintf(
		"[ROOT CERTS: %d, TOTAL: %d]",
		rvr.NumRootCerts(),
		rvr.TotalCerts(),
	)
}

// Status is intended as a brief status of the validation check result. This
// can be used as initial lead-in text.
func (rvr RootValidationResult) Status() string {
	var summary string

	switch {
	case errors.Is(rvr.err, ErrRootCertsFound):
		summary = fmt.Sprintf(
			"%s validation %s: %d root certs present",
			rvr.CheckName(),
			rvr.ValidationStatus(),
			rvr.NumRootCerts(),
		)

	// Catchall error handling
	case rvr.err != nil:
		summary = fmt.Sprintf(
			"%s validation %s: unexpected error encountered while validating %d certs: %s",
			rvr.CheckName(),
			rvr.ValidationStatus(),
			rvr.TotalCerts(),
			rvr.err.Error(),
		)

	// Success / OK scenario
	default:
		summary = fmt.Sprintf(
			"%s validation %s: %d certs present, %d root certs",
			rvr.CheckName(),
			rvr.ValidationStatus(),
			rvr.TotalCerts(),
			rvr.NumRootCerts(),
		)
	}

	return summary
}

// StatusDetail provides additional details intended to extend the shorter
// status text with information suitable as explanation for the overall state
// of the validation check result. This text may span multiple lines.
func (rvr RootValidationResult) StatusDetail() string {
	// NOTE: This is called from the Report() method and is used to compose
	// that larger output block.

	var detail strings.Builder

	switch {
	case errors.Is(rvr.err, ErrRootCertsFound):
		detail.WriteString(
			fmt.Sprintf(
				"A root certificate in the chain was found!%s",
				nagios.CheckOutputEOL,
			),
		)

		detail.WriteString(
			fmt.Sprintf(
				"%s%s%s",
				nagios.CheckOutputEOL,
				strings.TrimSpace(rootCertFoundAdvice),
				nagios.CheckOutputEOL,
			),
		)

		// detail.WriteString(reorderChainAdvice(rvr.certChain))

	// Catchall error handling
	case rvr.err != nil:
		detail.WriteString(
			fmt.Sprintf(
				"An unexpected error occurred while performing %s validation!%s",
				strings.ToLower(rvr.CheckName()),
				nagios.CheckOutputEOL,
			),
		)

		detail.WriteString(
			fmt.Sprintf(
				"Please report the following error and provide a copy of your certificate chain for evaluation (e.g., see cpcert tool in this project).%s%s",
				nagios.CheckOutputEOL,
				nagios.CheckOutputEOL,
			),
		)

		detail.WriteString(
			fmt.Sprintf(
				"Error: %q%s",
				rvr.err.Error(),
				nagios.CheckOutputEOL,
			),
		)

	// Success / OK scenario
	default:
		// TODO: Anything extra to add for no root certs detected?
		// The Status() output is likely sufficient to cover this.
	}

	return detail.String()
}

// String provides the validation check result in human-readable format.
// Because the certificates chain report is so detailed we skip emitting those
// details.
func (rvr RootValidationResult) String() string {
	return fmt.Sprintf(
		"%s %s",
		rvr.Status(),
		rvr.Overview(),
	)
}

// Report provides the validation check result in verbose human-readable
// format. Trailing whitespace is intentionally omitted per
// CertChainValidationResult recommendation.
func (rvr RootValidationResult) Report() string {
	switch {
	// Show advice regardless of whether check results were ignored (for the
	// purposes of determining final plugin check state).
	case rvr.err != nil:
		return fmt.Sprintf(
			"%s %s%s%s",
			rvr.Status(),
			nagios.CheckOutputEOL,
			nagios.CheckOutputEOL,
			rvr.StatusDetail(),
		)

	default:
		statusSummary := fmt.Sprintf(
			"%d total certificates, %d root certificates",
			rvr.TotalCerts(),
			rvr.NumRootCerts(),
		)

		// Provide overview only.
		return fmt.Sprintf(
			"%s validation %s: %s",
			rvr.CheckName(),
			rvr.ValidationStatus(),
			statusSummary,
		)
	}
}

// NumRootCerts indicates the number of certificates in the chain that are
// root certificates.
func (rvr RootValidationResult) NumRootCerts() int {
	return rvr.numRootCerts
}

// ValidationStatus provides a one word status value for expiration validation
// check results. If the original certificate chain was filtered then the
// validation status value is based on the filtered chain, otherwise the
// original certificate chain is used.
func (rvr RootValidationResult) ValidationStatus() string {
	switch {
	case rvr.IsFailed():
		return ValidationStatusFailed
	case rvr.IsIgnored():
		return ValidationStatusIgnored
	default:
		return ValidationStatusSuccessful
	}
}
