// Copyright 2022 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package certs

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/atc0005/check-cert/internal/textutils"
	"github.com/atc0005/go-nagios"
)

// Add an "implements assertion" to fail the build if the interface
// implementation isn't correct.
var _ CertChainValidationResult = (*SANsListValidationResult)(nil)

// SANsListValidationResult is the validation result from performing a Subject
// Alternate Names (SANs) validation against a leaf certificate in a chain.
type SANsListValidationResult struct {
	// certChain is the collection of certificates that we evaluated to
	// produce this validation check result.
	certChain []*x509.Certificate

	// leafCert is the first certificate from the chain that we evaluated to
	// produce this validation check result.
	leafCert *x509.Certificate

	// err is the "final" error describing the validation attempt.
	err error

	// priorityModifier is applied when calculating the priority for a
	// validation check result. If a validation check result has an associated
	// error but is flagged as ignored then the base priority value is used
	// and this modifier is ignored.
	//
	// If the validation check is not flagged as ignored than this modifier is
	// used to calculate the final priority level.
	priorityModifier int

	// ignored indicates whether validation check results are ignored for the
	// certificate chain.
	ignored bool

	// validationOptions tracks what validation options were chosen by the
	// sysadmin.
	validationOptions CertChainValidationOptions

	// requiredSANsList represents the Subject Alternate Names that the
	// sysadmin has stated is required to be present for the evaluated leaf
	// certificate.
	//
	// If the sysadmin:
	//
	// - enables SANs list validation (explicitly or implicitly)
	// - does not specify a list
	// - does specify the DNS Name flag
	//
	// then this list is populated with the DNS Name value as the sole
	// entry.
	requiredSANsList []string

	unmatchedSANsEntriesFromCert []string

	unmatchedSANsEntriesFromList []string
}

// ValidateSANsList asserts that the leaf certificate for a given certificate
// chain contains exactly the Subject Alternate Names specified (no more, no
// less). If specified, this validation check result is ignored.
//
// NOTE: The logic for evaluating the SKIPSANSCHECKS keyword is handled by the
// config package.
func ValidateSANsList(
	certChain []*x509.Certificate,
	requiredEntries []string,
	validationOptions CertChainValidationOptions,
) SANsListValidationResult {

	// TODO: Assert that first cert really is a leaf cert?
	leafCert := certChain[0]

	// Early exit logic.
	switch {
	case len(certChain) == 0:
		return SANsListValidationResult{
			certChain:         certChain,
			leafCert:          leafCert,
			validationOptions: validationOptions,
			err: fmt.Errorf(
				"required certificate chain is empty: %w",
				ErrMissingValue,
			),
			ignored:          validationOptions.IgnoreValidationResultSANs,
			priorityModifier: priorityModifierMaximum,
		}

	// If no SANs list entries were provided we are unable to perform
	// validation of the SANs list.
	//
	// NOTE: While configuration validation is expected to prevent this
	// scenario we explicitly guard against it.
	case len(requiredEntries) == 0:
		return SANsListValidationResult{
			certChain:         certChain,
			leafCert:          leafCert,
			validationOptions: validationOptions,
			err: fmt.Errorf(
				"required SANs entries list is empty: %w",
				ErrMissingValue,
			),
			ignored:          validationOptions.IgnoreValidationResultSANs,
			priorityModifier: priorityModifierMaximum,
		}

	}

	// Assuming that the DNSNames slice is NOT already lowercase, so forcing
	// them to be so first before comparing against the user-provided slice of
	// SANs entries.
	lcDNSNames := textutils.LowerCaseStringSlice(leafCert.DNSNames)

	// Assert that the requested SANs list entries match 1:1 what the leaf
	// certificate contains.
	unmatchedSANsEntriesFromList := textutils.FailedMatches(requiredEntries, lcDNSNames, true)
	unmatchedSANsEntriesFromCert := textutils.FailedMatches(lcDNSNames, requiredEntries, true)

	switch {

	// Some required SANs entries not found, some unexpected SANs entries present.
	case len(unmatchedSANsEntriesFromList) > 0 && len(unmatchedSANsEntriesFromCert) > 0:
		return SANsListValidationResult{
			certChain:                    certChain,
			leafCert:                     leafCert,
			validationOptions:            validationOptions,
			err:                          ErrCertHasMissingAndUnexpectedSANsEntries,
			ignored:                      validationOptions.IgnoreValidationResultSANs,
			requiredSANsList:             requiredEntries,
			unmatchedSANsEntriesFromList: unmatchedSANsEntriesFromList,
			unmatchedSANsEntriesFromCert: unmatchedSANsEntriesFromCert,
			priorityModifier:             priorityModifierMaximum,
		}

	// Some required SANs entries not found, no unexpected SANs entries present.
	case len(unmatchedSANsEntriesFromList) > 0:
		return SANsListValidationResult{
			certChain:                    certChain,
			leafCert:                     leafCert,
			validationOptions:            validationOptions,
			err:                          ErrCertMissingSANsEntries,
			ignored:                      validationOptions.IgnoreValidationResultSANs,
			requiredSANsList:             requiredEntries,
			unmatchedSANsEntriesFromList: unmatchedSANsEntriesFromList,
			priorityModifier:             priorityModifierMaximum,
		}

	// Required SANs entries found, but unexpected SANs entries present.
	case len(unmatchedSANsEntriesFromCert) > 0:
		return SANsListValidationResult{
			certChain:                    certChain,
			leafCert:                     leafCert,
			validationOptions:            validationOptions,
			err:                          ErrCertHasUnexpectedSANsEntries,
			ignored:                      validationOptions.IgnoreValidationResultSANs,
			requiredSANsList:             requiredEntries,
			unmatchedSANsEntriesFromCert: unmatchedSANsEntriesFromCert,
			priorityModifier:             priorityModifierMinimum,
		}

	// No failed matches, so SANs list is as expected.
	default:
		return SANsListValidationResult{
			certChain:         certChain,
			leafCert:          leafCert,
			validationOptions: validationOptions,

			// Q: Should an explicitly ignored result be ignored if the
			// validation was successful?
			//
			// A: Yes, *if* the sysadmin explicitly requested that the result
			// be ignored.
			ignored:          validationOptions.IgnoreValidationResultSANs,
			requiredSANsList: requiredEntries,
		}
	}

}

// CheckName emits the human-readable name of this validation check result.
func (slvr SANsListValidationResult) CheckName() string {
	return checkNameSANsListValidationResult
}

// CertChain returns the evaluated certificate chain.
func (slvr SANsListValidationResult) CertChain() []*x509.Certificate {
	return slvr.certChain
}

// TotalCerts returns the number of certificates in the evaluated certificate
// chain.
func (slvr SANsListValidationResult) TotalCerts() int {
	return len(slvr.certChain)
}

// IsWarningState indicates whether this validation check result is in a
// WARNING state. This returns false if the validation check resulted in an OK
// or CRITICAL state, or is flagged as ignored. True is returned otherwise.
func (slvr SANsListValidationResult) IsWarningState() bool {
	// This state is not used for this certificate validation check.
	return false
}

// IsCriticalState indicates whether this validation check result is in a
// CRITICAL state. This returns false if the validation check resulted in an
// OK or WARNING state, or is flagged as ignored. True is returned otherwise.
func (slvr SANsListValidationResult) IsCriticalState() bool {
	return slvr.err != nil && !slvr.IsIgnored()
}

// IsUnknownState indicates whether this validation check result is in an
// UNKNOWN state.
func (slvr SANsListValidationResult) IsUnknownState() bool {
	// This state is not used for this certificate validation check.
	return false
}

// IsOKState indicates whether this validation check result is in an OK or
// passing state. For the purposes of validation check evaluation, ignored
// validation checks are considered to be a subset of OK status.
func (slvr SANsListValidationResult) IsOKState() bool {
	return slvr.err == nil || slvr.IsIgnored()
}

// IsIgnored indicates whether this validation check result was flagged as
// ignored for the purposes of determining final validation state.
func (slvr SANsListValidationResult) IsIgnored() bool {
	return slvr.ignored
}

// IsSucceeded indicates whether this validation check result is not flagged
// as ignored and no problems with the certificate chain were identified.
func (slvr SANsListValidationResult) IsSucceeded() bool {
	return slvr.IsOKState() && !slvr.IsIgnored()
}

// IsFailed indicates whether this validation check result is not flagged as
// ignored and problems were identified.
func (slvr SANsListValidationResult) IsFailed() bool {
	return slvr.err != nil && !slvr.IsIgnored()
}

// Err returns the underlying error (if any) regardless of whether this
// validation check result is flagged as ignored.
func (slvr SANsListValidationResult) Err() error {
	return slvr.err
}

// ServiceState returns the appropriate Service Check Status label and exit
// code for this validation check result.
func (slvr SANsListValidationResult) ServiceState() nagios.ServiceState {
	return ServiceState(slvr)
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
func (slvr SANsListValidationResult) Priority() int {
	switch {
	case slvr.ignored:
		return baselinePrioritySANsListValidationResult
	default:
		return baselinePrioritySANsListValidationResult + slvr.priorityModifier
	}
}

// Overview provides a high-level summary of this validation check result.
func (slvr SANsListValidationResult) Overview() string {
	return fmt.Sprintf(
		"[%d EXPECTED, %d MISSING, %d UNEXPECTED]",
		len(slvr.requiredSANsList),
		len(slvr.unmatchedSANsEntriesFromList),
		len(slvr.unmatchedSANsEntriesFromCert),
	)
}

// Status is intended as a brief status of the validation check result. This
// can be used as initial lead-in text.
func (slvr SANsListValidationResult) Status() string {
	var status string
	switch {

	// User opted to ignore validation check results.
	case slvr.IsIgnored():
		status = fmt.Sprintf(
			"%s validation ignored: %d SANs entries specified, %d SANs entries on %s cert",
			slvr.CheckName(),
			len(slvr.requiredSANsList),
			len(slvr.leafCert.DNSNames),
			ChainPosition(slvr.leafCert, slvr.certChain),
		)

	case errors.Is(slvr.err, ErrCertMissingSANsEntries) ||
		errors.Is(slvr.err, ErrCertHasUnexpectedSANsEntries) ||
		errors.Is(slvr.err, ErrCertHasMissingAndUnexpectedSANsEntries):

		status = fmt.Sprintf(
			"%s validation failed: %q %s",
			slvr.CheckName(),
			ChainPosition(slvr.leafCert, slvr.certChain),
			slvr.Err(),
		)

	case slvr.err != nil:
		status = fmt.Sprintf(
			"Error encountered validating %d expected SANs entries: %v",
			len(slvr.requiredSANsList),
			slvr.err,
		)

	// No validation errors occurred.
	default:
		status = fmt.Sprintf(
			"%s validation successful: expected and confirmed (%d) SANs entries present for %s certificate",
			slvr.CheckName(),
			len(slvr.leafCert.DNSNames),
			ChainPosition(slvr.leafCert, slvr.certChain),
		)

	}

	return status

}

// StatusDetail provides additional details intended to extend the shorter
// status text with information suitable as explanation for the overall state
// of the validation check result. This text may span multiple lines.
func (slvr SANsListValidationResult) StatusDetail() string {

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
	// if slvr.err != nil && !slvr.ignored {
	// 	fmt.Fprintf(
	// 		&detail,
	// 		"%s%s%s",
	// 		slvr.err.Error(),
	// 		nagios.CheckOutputEOL,
	// 		nagios.CheckOutputEOL,
	// 	)
	// }

	// No additional details to add if all requested SANs list entries were
	// found and no unexpected SANs entries are present.
	switch {

	case len(slvr.unmatchedSANsEntriesFromList) == 0 &&
		len(slvr.unmatchedSANsEntriesFromCert) == 0:

		return ""

	default:

		missing := "N/A"
		if len(slvr.unmatchedSANsEntriesFromList) > 0 {
			missing = strings.Join(slvr.unmatchedSANsEntriesFromList, ", ")
		}

		unexpected := "N/A"
		if len(slvr.unmatchedSANsEntriesFromCert) > 0 {
			unexpected = strings.Join(slvr.unmatchedSANsEntriesFromCert, ", ")
		}

		_, _ = fmt.Fprintf(
			&detail,
			"missing: [%s], unexpected: [%s]",
			missing,
			unexpected,
		)

		return detail.String()

	}
}

// String provides the validation check result in human-readable format.
func (slvr SANsListValidationResult) String() string {
	output := fmt.Sprintf(
		"%s %s",
		slvr.Status(),
		slvr.Overview(),
	)

	if slvr.StatusDetail() != "" {
		output += "; " + slvr.StatusDetail()
	}

	return output

}

// Report provides the validation check result in verbose human-readable
// format.
func (slvr SANsListValidationResult) Report() string {

	detail := slvr.StatusDetail()
	switch {
	case detail == "":
		return fmt.Sprintf(
			"%s %s",
			slvr.Status(),
			slvr.Overview(),
		)
	default:
		return fmt.Sprintf(
			"%s %s; %s",
			slvr.Status(),
			slvr.Overview(),
			slvr.StatusDetail(),
		)
	}
}

// NumExpected returns the number of user-specified SANs list entries.
func (slvr SANsListValidationResult) NumExpected() int {
	return len(slvr.requiredSANsList)
}

// NumPresent returns the number of SANs list entries for the evaluated leaf
// certificate.
func (slvr SANsListValidationResult) NumPresent() int {
	return len(slvr.leafCert.DNSNames)
}

// NumMatched returns the number of matched SANs list entries for the
// evaluated leaf certificate.
func (slvr SANsListValidationResult) NumMatched() int {
	matched := len(slvr.requiredSANsList) - (len(slvr.unmatchedSANsEntriesFromCert) +
		len(slvr.unmatchedSANsEntriesFromList))

	// Guard against returning a negative number.
	switch {
	case matched > 0:
		return matched
	default:
		return 0
	}
}

// NumMismatched returns the number of failed SANs list entry matches for the
// evaluated leaf certificate.
func (slvr SANsListValidationResult) NumMismatched() int {
	return len(slvr.unmatchedSANsEntriesFromCert) +
		len(slvr.unmatchedSANsEntriesFromList)
}
