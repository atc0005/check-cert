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
var _ CertChainValidationResult = (*ChainOrderValidationResult)(nil)

// Advice for sysadmins resolving cert chain issues saved in external files
// for easier maintenance.
var (
	//go:embed advice/sectigo-email-download-links.txt
	sectigoEmailAdvice string
)

// ChainOrderValidationResult is the validation result from performing
// expiration validation against each certificate in a chain.
type ChainOrderValidationResult struct {
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

	// numOrderedCerts is the number of certificates in the evaluated
	// certificate chain which were found to be in the correct order.
	numOrderedCerts int

	// numMisorderedCerts is the number of certificates in the evaluated
	// certificate chain which were found to be in an incorrect order.
	numMisorderedCerts int

	// priorityModifier is applied when calculating the priority for a
	// validation check result. If a validation check result has an associated
	// error but is flagged as ignored then the base priority value is used
	// and this modifier is ignored.
	//
	// If the validation check is not flagged as ignored than this modifier is
	// used to calculate the final priority level.
	priorityModifier int
}

// ValidateChainOrder evaluates a given certificate chain for certificates out
// of the expected order (leaf first followed by one or more intermediates).
// If specified, a flag is set to generate verbose validation output.
//
// NOTE: This validation type objects to incorrect certificate entries (e.g.,
// duplicate leaf certs) as it causes the chain to not be in the correct
// order.
func ValidateChainOrder(
	certChain []*x509.Certificate,
	verboseOutput bool,
	validationOptions CertChainValidationOptions,
) ChainOrderValidationResult {

	// Perform basic validation of given values.
	//
	// What other "basics" do we check for before we perform chain order
	// evaluation?
	//
	// Should we object to missing leaf certificates; should we handle
	// intermediates bundle monitoring any differently?

	if len(certChain) == 0 {
		return ChainOrderValidationResult{
			certChain:         certChain,
			validationOptions: validationOptions,
			err: fmt.Errorf(
				"required certificate chain is empty: %w",
				ErrNoCertsFound,
			),
			ignored:          validationOptions.IgnoreValidationResultChainOrder,
			priorityModifier: priorityModifierMaximum,
		}
	}

	hasMisorderedCerts := HasMisorderedCerts(certChain)
	numOrderedCerts := NumOrderedCerts(certChain)
	numMisorderedCerts := NumMisorderedCerts(certChain)

	// Perform chain order evaluation.
	switch {
	case len(certChain) == 1:
		// While this focus is primarily on a cert "chain" containing only a
		// valid leaf certificate (signed by a trusted intermediate), we also
		// (currently) assume that self-signed certificates are an ordering
		// issue that requires resolution.

		// FIXME: Move this to an "Intermediates" specific check (GH-364).

		certType := ChainPosition(certChain[0], certChain)

		return ChainOrderValidationResult{
			certChain:         certChain,
			validationOptions: validationOptions,
			err: fmt.Errorf(
				"certificate chain contains only %s cert: %w",
				certType,
				ErrIncompleteCertificateChain,
			),
			ignored:          validationOptions.IgnoreValidationResultChainOrder,
			priorityModifier: priorityModifierMedium,
		}

	case hasMisorderedCerts:
		return ChainOrderValidationResult{
			certChain: certChain,
			err: fmt.Errorf(
				"%s validation failed: %w",
				strings.ToLower(checkNameChainOrderValidationResult),
				ErrMisorderedCertificateChain,
			),
			ignored:            validationOptions.IgnoreValidationResultChainOrder,
			validationOptions:  validationOptions,
			verboseOutput:      verboseOutput,
			numOrderedCerts:    numOrderedCerts,
			numMisorderedCerts: numMisorderedCerts,
			priorityModifier:   priorityModifierMedium,
		}

	default:
		// No chain order issues found.
		return ChainOrderValidationResult{
			certChain:          certChain,
			err:                nil,
			ignored:            validationOptions.IgnoreValidationResultChainOrder,
			validationOptions:  validationOptions,
			verboseOutput:      verboseOutput,
			numOrderedCerts:    numOrderedCerts,
			numMisorderedCerts: numMisorderedCerts,
			priorityModifier:   priorityModifierBaseline,
		}
	}
}

// CheckName emits the human-readable name of this validation check result.
func (covr ChainOrderValidationResult) CheckName() string {
	return checkNameChainOrderValidationResult
}

// CertChain returns the evaluated certificate chain.
func (covr ChainOrderValidationResult) CertChain() []*x509.Certificate {
	return covr.certChain
}

// TotalCerts returns the number of certificates in the evaluated certificate
// chain.
func (covr ChainOrderValidationResult) TotalCerts() int {
	return len(covr.certChain)
}

// IsWarningState indicates whether this validation check result is in a
// WARNING state. This returns false if the validation check resulted in an OK
// or CRITICAL state, or is flagged as ignored.
func (covr ChainOrderValidationResult) IsWarningState() bool {
	switch {
	case covr.IsIgnored():
		return false

	case covr.IsOKState():
		return false

	case covr.IsCriticalState():
		return false

	case errors.Is(covr.err, ErrMisorderedCertificateChain):
		// A "misordered" certificate chain is considered a WARNING state and
		// not CRITICAL because the majority of modern clients (e.g.,
		// browsers) will automatically rearrange a given certificate chain
		// into an valid order, provided that the leaf and intermediate
		// certificates are present.
		//
		// We explicitly handle this specific error type vs letting a more
		// general match handle "anything not incomplete error chain error".
		// This is as much to document the intent as to provide a hook for
		// future use.
		return true

	default:
		return false
	}
}

// IsCriticalState indicates whether this validation check result is in a
// CRITICAL state. This returns false if the validation check resulted in an
// OK or WARNING state, or is flagged as ignored.
func (covr ChainOrderValidationResult) IsCriticalState() bool {
	switch {
	case covr.IsIgnored():
		return false

	case errors.Is(covr.err, ErrNoCertsFound):
		// A certificate chain missing all certificates is considered a
		// CRITICAL state because required certificates are not present. There
		// isn't anything we can reasonably check in this situation.
		//
		// We match on this error type to provide a hook for later potential
		// use and to explicitly document how this validation check should
		// behave for this scenario.
		return true

	case errors.Is(covr.err, ErrIncompleteCertificateChain):
		//
		// FIXME: Move this to an "Intermediates" specific check (GH-364).
		//
		// An incomplete certificate chain is considered a CRITICAL state
		// because required certificates are not present; because some
		// modern/current clients will not automatically fetch missing
		// intermediates to resolve the chain users are more likely to be
		// impacted by this problem than they would be if the chain were
		// misordered.
		return true

	default:
		return false
	}
}

// IsUnknownState indicates whether this validation check result is in an
// UNKNOWN state.
func (covr ChainOrderValidationResult) IsUnknownState() bool {
	// This state is not used for this certificate validation check.
	return false
}

// IsOKState indicates whether this validation check result is in an OK or
// passing state. For the purposes of validation check evaluation, ignored
// validation checks are considered to be a subset of OK status.
func (covr ChainOrderValidationResult) IsOKState() bool {
	return covr.err == nil || covr.IsIgnored()
}

// IsIgnored indicates whether this validation check result was flagged as
// ignored for the purposes of determining final validation state.
func (covr ChainOrderValidationResult) IsIgnored() bool {
	return covr.ignored
}

// IsSucceeded indicates whether this validation check result is not flagged
// as ignored and no problems with the certificate chain were identified.
func (covr ChainOrderValidationResult) IsSucceeded() bool {
	return covr.IsOKState() && !covr.IsIgnored()
}

// IsFailed indicates whether this validation check result is not flagged as
// ignored and problems were identified.
func (covr ChainOrderValidationResult) IsFailed() bool {
	return covr.err != nil && !covr.IsIgnored()
}

// Err returns the underlying error (if any) regardless of whether this
// validation check result is flagged as ignored.
func (covr ChainOrderValidationResult) Err() error {
	return covr.err
}

// ServiceState returns the appropriate Service Check Status label and exit
// code for this validation check result.
func (covr ChainOrderValidationResult) ServiceState() nagios.ServiceState {
	return ServiceState(covr)
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
func (covr ChainOrderValidationResult) Priority() int {
	switch {
	case covr.ignored:
		// Though the result is ignored, we indicate the baseline value for
		// this check result to allow this result to sort properly against
		// other check results which may also be ignored. This why we don't
		// use a value of 0 (or equivalent) here.
		return baselinePriorityChainOrderValidationResult
	default:
		return baselinePriorityChainOrderValidationResult + covr.priorityModifier
	}
}

// Overview provides a high-level summary of this validation check result.
func (covr ChainOrderValidationResult) Overview() string {
	return fmt.Sprintf(
		"[ORDERED: %d, MISORDERED: %d, TOTAL: %d]",
		covr.NumOrderedCerts(),
		covr.NumMisorderedCerts(),
		covr.TotalCerts(),
	)
}

// Status is intended as a brief status of the validation check result. This
// can be used as initial lead-in text.
func (covr ChainOrderValidationResult) Status() string {
	var summary string

	switch {
	case errors.Is(covr.err, ErrMisorderedCertificateChain):
		summary = fmt.Sprintf(
			"%s validation %s: %d certs misordered",
			covr.CheckName(),
			covr.ValidationStatus(),
			covr.NumMisorderedCerts(),
		)

	case errors.Is(covr.err, ErrIncompleteCertificateChain):
		summary = fmt.Sprintf(
			"%s validation %s: %s",
			covr.CheckName(),
			covr.ValidationStatus(),

			// The error message is already verbose enough that we don't
			// really need to add extra qualifiers in the summary text.
			covr.err.Error(),
		)

	// Catchall error handling
	case covr.err != nil:
		summary = fmt.Sprintf(
			"%s validation %s: unexpected error encountered while validating %d certs: %s",
			covr.CheckName(),
			covr.ValidationStatus(),
			covr.TotalCerts(),
			covr.err.Error(),
		)

	// Success / OK scenario
	default:
		summary = fmt.Sprintf(
			"%s validation %s: %d certs present, %d certs misordered",
			covr.CheckName(),
			covr.ValidationStatus(),
			covr.TotalCerts(),
			covr.NumMisorderedCerts(),
		)
	}

	return summary
}

// StatusDetail provides additional details intended to extend the shorter
// status text with information suitable as explanation for the overall state
// of the validation check result. This text may span multiple lines.
func (covr ChainOrderValidationResult) StatusDetail() string {
	// NOTE: This is called from the Report() method and is used to compose
	// that larger output block.

	var detail strings.Builder

	switch {
	case errors.Is(covr.err, ErrMisorderedCertificateChain):
		detail.WriteString(
			fmt.Sprintf(
				"A misordered certificate chain was found!%s",
				nagios.CheckOutputEOL,
			),
		)

		detail.WriteString(reorderChainAdvice(covr.certChain))

	case errors.Is(covr.err, ErrIncompleteCertificateChain):
		detail.WriteString(
			fmt.Sprintf(
				"An incomplete certificate chain was found (%d certs total).%s%s",
				covr.TotalCerts(),
				nagios.CheckOutputEOL,
				nagios.CheckOutputEOL,
			),
		)

		detail.WriteString(incompleteChainAdvice(covr.certChain))

	// Catchall error handling
	case covr.err != nil:
		detail.WriteString(
			fmt.Sprintf(
				"An unexpected error occurred while performing %s validation!%s",
				strings.ToLower(covr.CheckName()),
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
				covr.err.Error(),
				nagios.CheckOutputEOL,
			),
		)

	// Success / OK scenario
	default:
		// TODO: Anything extra to add for successful chain order validation?
		// The Status() output is likely sufficient to cover this.
	}

	return detail.String()
}

// String provides the validation check result in human-readable format.
// Because the certificates chain report is so detailed we skip emitting those
// details.
func (covr ChainOrderValidationResult) String() string {
	return fmt.Sprintf(
		"%s %s",
		covr.Status(),
		covr.Overview(),
	)
}

// Report provides the validation check result in verbose human-readable
// format. Trailing whitespace is intentionally omitted per
// CertChainValidationResult recommendation.
func (covr ChainOrderValidationResult) Report() string {
	switch {
	// Show advice regardless of whether check results were ignored (for the
	// purposes of determining final plugin check state).
	case covr.err != nil:
		return fmt.Sprintf(
			"%s %s%s%s",
			covr.Status(),
			nagios.CheckOutputEOL,
			nagios.CheckOutputEOL,
			covr.StatusDetail(),
		)

	default:
		statusSummary := fmt.Sprintf(
			"%d ordered certificates, %d misordered certificates",
			covr.numOrderedCerts,
			covr.numMisorderedCerts,
		)

		// Provide overview only.
		return fmt.Sprintf(
			"%s validation %s: %s",
			covr.CheckName(),
			covr.ValidationStatus(),
			statusSummary,
		)
	}
}

// NumOrderedCerts indicates the number of certificates in the chain that are
// not out of order.
func (covr ChainOrderValidationResult) NumOrderedCerts() int {
	return NumOrderedCerts(covr.CertChain())
}

// NumMisorderedCerts indicates the number of certificates in the chain that are
// not out of order.
func (covr ChainOrderValidationResult) NumMisorderedCerts() int {
	return NumMisorderedCerts(covr.CertChain())
}

// ValidationStatus provides a one word status value for expiration validation
// check results. If the original certificate chain was filtered then the
// validation status value is based on the filtered chain, otherwise the
// original certificate chain is used.
func (covr ChainOrderValidationResult) ValidationStatus() string {
	switch {
	case covr.IsFailed():
		return ValidationStatusFailed
	case covr.IsIgnored():
		return ValidationStatusIgnored
	default:
		return ValidationStatusSuccessful
	}
}

// summarizeChainOrder returns a summarized list of the certificates in a
// given certificate chain.
func summarizeChainOrder(certChain []*x509.Certificate) string {
	var chainOrderList strings.Builder

	hostVal := func(cert *x509.Certificate) string {
		switch {
		case cert.Subject.CommonName != "":
			return cert.Subject.CommonName

		case len(cert.DNSNames) > 0:
			return cert.DNSNames[0]

		default:
			return "unknown cert"
		}
	}

	template := "(%d) %s [%s]%s"
	// template := "[%d] %s (%s)%s"

	for idx, cert := range certChain {
		chainPos := ChainPosition(cert, certChain)
		chainOrderList.WriteString(
			fmt.Sprintf(
				template,
				idx,
				hostVal(cert),
				chainPos,
				nagios.CheckOutputEOL,
			),
		)
	}

	return chainOrderList.String()
}

// summarizeFixedChainOrder returns a summarized list of the certificates in a
// given certificate chain in a fixed chain order.
func summarizeFixedChainOrder(certChain []*x509.Certificate) string {
	orderedCertChain := orderCertChain(certChain)

	return summarizeChainOrder(orderedCertChain)
}

// reorderChainAdvice provides advice for the sysadmin when a cert chain is
// found to be misordered.
func reorderChainAdvice(certChain []*x509.Certificate) string {
	if len(certChain) == 0 {
		return ""
	}

	var advice strings.Builder

	advice.WriteString(
		fmt.Sprintf(
			"This issue is often caused by using the incorrect intermediates bundle (with reversed entries).%s",
			nagios.CheckOutputEOL,
		),
	)

	advice.WriteString(
		fmt.Sprintf(
			"It is recommended that you reorder the certificate chain to resolve this issue.%s%s",
			nagios.CheckOutputEOL,
			nagios.CheckOutputEOL,
		),
	)

	advice.WriteString(
		fmt.Sprintf(
			"Current chain order:%s%s%s%s",
			nagios.CheckOutputEOL,
			nagios.CheckOutputEOL,
			summarizeChainOrder(certChain),
			nagios.CheckOutputEOL,
		),
	)

	advice.WriteString(
		fmt.Sprintf(
			"Recommended chain order:%s%s%s%s",
			nagios.CheckOutputEOL,
			nagios.CheckOutputEOL,
			summarizeFixedChainOrder(certChain),
			nagios.CheckOutputEOL,
		),
	)

	advice.WriteString(certDownloadLinksAdvice(certChain))

	return advice.String()
}
