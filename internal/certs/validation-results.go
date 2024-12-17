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
	"sort"
	"strings"

	"github.com/atc0005/go-nagios"
)

// CertChainValidationResult validation status keywords. These values provide
// a one word status value for validation check results.
const (
	ValidationStatusFailed     string = "failed"
	ValidationStatusIgnored    string = "ignored"
	ValidationStatusSuccessful string = "successful"
)

// CertChainValidationResult represents the result for a validation check
// associated with a certificate chain. The result can indicate success,
// failure or if validation was ignored.
type CertChainValidationResult interface {

	// Err exposes the underlying error (if any) as-is. See the Status(),
	// Overview() and String() methods if additional context is desired for
	// display purposes.
	Err() error

	// CheckName emits the human-readable name of the validation check that
	// was performed.
	CheckName() string

	// Status is intended as a brief status of the validation result. This can
	// be used as initial lead-in text.
	//
	// Example:
	//
	// CRITICAL: Mismatched SANs entries for leaf certificate
	//
	// Implementations should not rely on leading and trailing whitespace in
	// provided output to be retained.
	Status() string

	// Overview is a high-level overview of the validation result. This can be
	// used as lead-out text for a one-line summary/overview, or sandwiched
	// between lead-in text and a more detailed status report.
	//
	// Example:
	//
	// [EXPIRED: 0, EXPIRING: 1, OK: 2]
	//
	// Implementations should not rely on leading and trailing whitespace in
	// provided output to be retained.
	Overview() string

	// StatusDetail is provides additional details intended to extend the
	// shorter status text with information suitable as explanation for the
	// overall state of the validation results. This text may span multiple
	// lines.
	//
	// Example:
	//
	// missing: [konrad-test.amazon.com, mp3recs.amazon.com, test-www.amazon.com, www.cdn.amazon.com, www.m.amazon.com, yellowpages.amazon.com], unexpected: [origin-www.amazon.com, buckeye-retail-website.amazon.com, huddles.amazon.com]
	//
	// Implementations should not rely on leading and trailing whitespace in
	// provided output to be retained.
	StatusDetail() string

	// ValidationStatus provides a one word status value for validation check
	// results (e.g., "failed", "ignored" or "successful").
	ValidationStatus() string

	// String provides the validation result in human-readable format.
	//
	// Most implementations will combine the contents of Status() and
	// Overview(), some implementations may also combine StatusDetail() if the
	// content is sufficiently brief.
	//
	// Implementations should not rely on leading and trailing whitespace in
	// provided output to be retained.
	String() string

	// ServiceState maps the validation result to a compatible ServiceState
	// value.
	ServiceState() nagios.ServiceState

	// Report provides a summary of the validation results intended for use in
	// a final report for the user/sysadmin.
	//
	// Most implementations will likely combine String() and StatusDetail()
	// along with additional verbose details to provide this output.
	//
	// Implementations should not rely on leading and trailing whitespace in
	// provided output to be retained.
	Report() string

	// IsWarningState indicates whether the results for a validation check
	// were found to be in a WARNING state. This is usually from crossing an
	// explicit or default WARNING threshold value. This returns false if the
	// validation check result is flagged as ignored.
	IsWarningState() bool

	// IsCriticalState indicates whether the results for a validation check
	// were found to be in a CRITICAL state. This is usually from crossing an
	// explicit or default CRITICAL threshold value. This returns false if the
	// validation check result is flagged as ignored.
	IsCriticalState() bool

	// IsUnknownState indicates whether the results for a validation check
	// were found to be in a UNKNOWN state. This returns false if the
	// validation check result is flagged as ignored.
	IsUnknownState() bool

	// IsOKState indicates whether the results for a validation check were
	// found to be in a passing state. For the purposes of validation check
	// evaluation, ignored validation check results are considered to be a
	// subset of OK status.
	//
	// See the IsIgnored() method for determining whether a validation check is
	// in that specific state, see the IsSuccessState() method for determining
	// whether a validation check was executed, evaluated and found to be
	// successful.
	IsOKState() bool

	// IsSucceeded indicates that the results for a validation check were
	// found to be in a non-problematic, non-ignored state; an ignored
	// validation check is considered to be OK, but not in a successful state.
	IsSucceeded() bool

	// IsIgnored indicates whether a specific validation check was performed,
	// but the results "ignored" when determining overall plugin state.
	IsIgnored() bool

	// IsFailed indicates whether a specific validation check resulted in a
	// non-successful state and is not flagged as ignored.
	IsFailed() bool

	// TotalCerts returns the number of certificates in the evaluated chain.
	TotalCerts() int

	// Priority indicates the level of importance for a specific validation
	// result.
	//
	// This value is calculated by applying a priority modifier for specific
	// failure conditions (recorded when the validation check result is
	// initially obtained) to a baseline value specific to the validation
	// check performed.
	//
	// If the validation check result is flagged as ignored the priority
	// modifier is also ignored. In that case, the baseline value for the
	// specific implementation is used to allow it to sort properly against
	// other check result implementations which may also be ignored.
	Priority() int

	// CertChain returns the associated certificate chain which was evaluated.
	CertChain() []*x509.Certificate
}

// CertChainValidationResults is a collection of validation results. This
// grouping allows for common/bulk operations such as determining overall
// state of the operations (e.g., via method calls such as IsWarningState(),
// IsCriticalState()).
type CertChainValidationResults []CertChainValidationResult

// Add appends a validation result to the set for later evaluation.
func (ccvr *CertChainValidationResults) Add(result CertChainValidationResult) {
	*ccvr = append(*ccvr, result)
}

// Sort orders the collection of validation results based on the priority
// value of each validation result. Validation results of equal value retain
// their order.
func (ccvr CertChainValidationResults) Sort() {
	sort.SliceStable(ccvr, func(i, j int) bool {
		return ccvr[i].Priority() > ccvr[j].Priority()
	})
}

// CheckNames returns a (potentially empty) slice of validation result names.
func (ccvr CertChainValidationResults) CheckNames() []string {
	names := make([]string, len(ccvr))
	for i := range ccvr {
		names[i] = ccvr[i].CheckName()
	}
	return names
}

// OKCheckNames returns a (potentially empty) slice of names for passing
// validation checks. Ignored validation checks are included.
func (ccvr CertChainValidationResults) OKCheckNames() []string {
	names := make([]string, 0, len(ccvr))
	for _, result := range ccvr {
		if result.IsOKState() {
			names = append(names, result.CheckName())
		}
	}
	return names
}

// SuccessCheckNames returns a (potentially empty) slice of names for
// successful validation checks. Ignored validation checks are NOT included.
func (ccvr CertChainValidationResults) SuccessCheckNames() []string {
	names := make([]string, 0, len(ccvr))
	for _, result := range ccvr {
		if result.IsSucceeded() {
			names = append(names, result.CheckName())
		}
	}
	return names
}

// NotOKCheckNames returns a (potentially empty) slice of names for
// unsuccessful validation checks.
func (ccvr CertChainValidationResults) NotOKCheckNames() []string {
	names := make([]string, 0, len(ccvr))
	for _, result := range ccvr {
		if !result.IsOKState() {
			names = append(names, result.CheckName())
		}
	}
	return names
}

// IgnoredCheckNames returns a (potentially empty) slice of names for
// ignored validation checks.
func (ccvr CertChainValidationResults) IgnoredCheckNames() []string {
	names := make([]string, 0, len(ccvr))
	for _, result := range ccvr {
		if result.IsIgnored() {
			names = append(names, result.CheckName())
		}
	}
	return names
}

// HasCriticalState indicates whether any validation results in the collection
// have a CRITICAL state.
func (ccvr CertChainValidationResults) HasCriticalState() bool {
	for _, result := range ccvr {
		if result.IsCriticalState() {
			return true
		}
	}

	return false
}

// IsCriticalState is an alias for HasCriticalState.
func (ccvr CertChainValidationResults) IsCriticalState() bool {
	return ccvr.HasCriticalState()
}

// HasWarningState indicates whether any validation results in the collection
// have a WARNING state.
func (ccvr CertChainValidationResults) HasWarningState() bool {
	for _, result := range ccvr {
		if result.IsWarningState() {
			return true
		}
	}

	return false
}

// IsWarningState is an alias for HasWarningState.
func (ccvr CertChainValidationResults) IsWarningState() bool {
	return ccvr.HasWarningState()
}

// HasUnknownState indicates whether any validation results in the collection
// have a UNKNOWN state.
func (ccvr CertChainValidationResults) HasUnknownState() bool {
	for _, result := range ccvr {
		if result.IsUnknownState() {
			return true
		}
	}

	return false
}

// IsUnknownState is an alias for HasUnknownState.
func (ccvr CertChainValidationResults) IsUnknownState() bool {
	return ccvr.HasUnknownState()
}

// IsOKState indicates whether all validation results in the collection
// have an OK state.
func (ccvr CertChainValidationResults) IsOKState() bool {
	// Config validation requires that at least one validation check is
	// performed, so not having any validation results is a problem.
	if len(ccvr) == 0 {
		return false
	}

	for _, result := range ccvr {
		if !result.IsOKState() {
			return false
		}
	}

	return true
}

// HasSucceeded indicates whether any validation results in the collection
// have a succeeded state.
func (ccvr CertChainValidationResults) HasSucceeded() bool {
	for _, result := range ccvr {
		if result.IsSucceeded() {
			return true
		}
	}

	return false
}

// HasIgnored indicates whether any validation results in the collection have
// a ignored state.
func (ccvr CertChainValidationResults) HasIgnored() bool {
	for _, result := range ccvr {
		if result.IsIgnored() {
			return true
		}
	}

	return false
}

// HasFailed indicates whether any validation results in the collection
// have a failed state.
func (ccvr CertChainValidationResults) HasFailed() bool {
	for _, result := range ccvr {
		if result.IsFailed() {
			return true
		}
	}

	return false
}

// ServiceState returns the appropriate Service Check Status label and exit
// code for the collection's validation results.
func (ccvr CertChainValidationResults) ServiceState() nagios.ServiceState {
	return ServiceState(ccvr)
}

// Total indicates how many validation results are in the collection.
func (ccvr CertChainValidationResults) Total() int {
	return len(ccvr)
}

// Err returns an error state evaluation of the validation results in the
// collection. This is a summary only and does not provide specifics regarding
// which validation errors occurred.
//
// NOTE: This method does not directly evaluate whether there is an underlying
// error recorded for one of the validation results in this collection, but
// rather whether one of the results is in a problematic, "unhandled" (or
// non-ignored) state. See the Errs method for access to any potential errors
// in the results collection.
func (ccvr CertChainValidationResults) Err() error {
	switch {

	// Config validation requires that at least one validation check is
	// performed, so not having any validation results is a problem.
	case len(ccvr) == 0:
		return ErrNoCertValidationResults

	case !ccvr.IsOKState():
		return fmt.Errorf(
			"summary: %d of %d validation checks failed",
			ccvr.NumFailed(),
			ccvr.Total(),
		)

	default:
		return nil
	}

}

// Errs returns a slice of errors recorded for validation results in the
// collection that have *not* been flagged as ignored. A nil is returned if no
// errors are recorded for the collection. If specified, all errors recorded
// are returned, not just those which have not been flagged as ignored.
func (ccvr CertChainValidationResults) Errs(includeIgnored bool) []error {
	switch {

	// Config validation requires that at least one validation check is
	// performed, so not having any validation results is a problem.
	case len(ccvr) == 0:
		return []error{ErrNoCertValidationResults}

	case ccvr.HasFailed() || ccvr.HasIgnored():

		errs := make([]error, 0, ccvr.NumFailed()+ccvr.NumIgnored())

		for _, result := range ccvr {
			if result.Err() != nil {
				if result.IsIgnored() && !includeIgnored {
					continue
				}
				errs = append(errs, result.Err())
			}
		}

		return errs

	default:
		return nil
	}
}

// NumCriticalState indicates how many validation results in the collection
// have a CRITICAL state.
func (ccvr CertChainValidationResults) NumCriticalState() int {
	var numCriticalState int
	for _, result := range ccvr {
		if result.IsCriticalState() {
			numCriticalState++
		}
	}

	return numCriticalState
}

// NumWarningState indicates how many validation results in the collection
// have a WARNING state.
func (ccvr CertChainValidationResults) NumWarningState() int {
	var numWarningState int
	for _, result := range ccvr {
		if result.IsWarningState() {
			numWarningState++
		}
	}

	return numWarningState
}

// NumUnknownState indicates how many validation results in the collection
// have an UNKNOWN state.
func (ccvr CertChainValidationResults) NumUnknownState() int {
	var numUnknownState int
	for _, result := range ccvr {
		if result.IsUnknownState() {
			numUnknownState++
		}
	}

	return numUnknownState
}

// NumOKState indicates how many validation results in the collection have an
// OK state.
func (ccvr CertChainValidationResults) NumOKState() int {
	var numOKState int
	for _, result := range ccvr {
		if result.IsOKState() {
			numOKState++
		}
	}

	return numOKState
}

// NumSucceeded indicates how many validation results in the collection
// have a succeeded state.
func (ccvr CertChainValidationResults) NumSucceeded() int {
	var numSuccessState int
	for _, result := range ccvr {
		if result.IsSucceeded() {
			numSuccessState++
		}
	}

	return numSuccessState
}

// NumIgnored indicates how many validation results in the collection have a
// ignored status.
func (ccvr CertChainValidationResults) NumIgnored() int {
	var numIgnored int
	for _, result := range ccvr {
		if result.IsIgnored() {
			numIgnored++
		}
	}

	return numIgnored

}

// NumFailed indicates how many validation results in the collection have a
// failed state.
func (ccvr CertChainValidationResults) NumFailed() int {
	var numFailed int
	for _, result := range ccvr {
		if result.IsFailed() {
			numFailed++
		}
	}

	return numFailed
}

// NotOKResults returns a (potentially empty) subset of this collection
// containing only the non-OK validation check results. Ignored validation
// check results are considered a subset of OK results and are not included
// here.
func (ccvr CertChainValidationResults) NotOKResults() CertChainValidationResults {
	results := make(CertChainValidationResults, 0, ccvr.NumFailed())
	for _, result := range ccvr {
		if !result.IsOKState() {
			results = append(results, result)
		}
	}
	return results
}

// SucceededResults returns a (potentially empty) subset of this collection
// containing only the successful validation check results. Ignored validation
// check results are not included here.
func (ccvr CertChainValidationResults) SucceededResults() CertChainValidationResults {
	results := make(CertChainValidationResults, 0, ccvr.NumFailed())
	for _, result := range ccvr {
		if result.IsSucceeded() {
			results = append(results, result)
		}
	}
	return results
}

// Overview is a high-level overview of the validation results collection.
// This can be used as lead-out text for a one-line summary/overview, or
// sandwiched between lead-in text and a more detailed status report.
func (ccvr CertChainValidationResults) Overview() string {

	// For the purposes of calculating "OK" and "NOT OK" checks, ignored
	// checks are considered as a subset of "OK" status so we instead focus on
	// the three distinct "buckets" perceived as the most useful for an
	// overview:
	//
	// 1) Failed
	// 2) Ignored
	// 3) Successful

	var failedListTmpl string
	switch {
	case ccvr.NumFailed() > 0:
		failedListTmpl = "%d FAILED (%s)"

	default:
		failedListTmpl = "%d FAILED%s"
	}
	failedList := fmt.Sprintf(
		failedListTmpl,
		ccvr.NumFailed(),
		strings.Join(ccvr.NotOKCheckNames(), ", "),
	)

	var ignoredListTmpl string
	switch {
	case ccvr.NumIgnored() > 0:
		ignoredListTmpl = "%d IGNORED (%s)"
	default:
		ignoredListTmpl = "%d IGNORED%s"
	}
	ignoredList := fmt.Sprintf(
		ignoredListTmpl,
		ccvr.NumIgnored(),
		strings.Join(ccvr.IgnoredCheckNames(), ", "),
	)

	var successListTmpl string
	switch {
	case ccvr.NumSucceeded() > 0:
		successListTmpl = "%d SUCCESSFUL (%s)"
	default:
		successListTmpl = "%d SUCCESSFUL%s"
	}
	successList := fmt.Sprintf(
		successListTmpl,
		ccvr.NumSucceeded(),
		strings.Join(ccvr.SuccessCheckNames(), ", "),
	)

	return fmt.Sprintf(
		"[checks: %s, %s, %s]",
		ignoredList,
		failedList,
		successList,
	)
}

// Status is intended as a brief status of the validation results collection.
// This can be used as initial lead-in text.
func (ccvr CertChainValidationResults) Status() string {
	// Early exit; we have an empty validation results collection. This should
	// not be possible as config validation should protect against a sysadmin
	// inadvertently disabling all validation checks.
	if !ccvr.IsOKState() && len(ccvr) == 0 {
		status := fmt.Sprintf(
			"%s: %s",
			ccvr.ServiceState().Label,
			ccvr.Err(),
		)

		return status
	}

	var summary strings.Builder

	// The number of high priority issues that we will note in our summary.
	// Because this is intended to display in approximately one line, there is
	// limited space to work with.
	const maxResultsInSummary int = 1

	resultsLimit := func(results CertChainValidationResults) int {
		if len(results) < maxResultsInSummary {
			return len(results)
		}
		return maxResultsInSummary
	}

	switch {

	// A non-OK or "Not OK" state can be triggered by a complete lack of
	// validation results. We guard against invalid indexing by skipping over
	// the collection if there are no results to evaluate.
	case !ccvr.IsOKState() && len(ccvr) > 0:
		resultsSubset := ccvr.NotOKResults()
		resultsSubset.Sort()

		// Grab resultsLimit worth of non-OK results.
		highPriority := make(CertChainValidationResults, resultsLimit(resultsSubset))
		copy(highPriority, resultsSubset)

		// Collect the statuses of the results subset.
		statuses := make([]string, 0, resultsLimit(resultsSubset))
		for _, result := range highPriority {
			statuses = append(statuses, result.Status())
		}

		status := fmt.Sprintf(
			"%s: %s",
			resultsSubset.ServiceState().Label,
			strings.Join(statuses, ", "),
		)

		summary.WriteString(status)

	case ccvr.HasIgnored() && ccvr.HasSucceeded() && !ccvr.HasFailed():

		// If we have a mix of only ignored and successful results we focus on
		// the highest priority successful results.
		resultsSubset := ccvr.SucceededResults()
		resultsSubset.Sort()

		// Grab resultsLimit worth of successful check results.
		highPriority := make(CertChainValidationResults, resultsLimit(resultsSubset))
		copy(highPriority, resultsSubset)

		// Collect the statuses of the results subset.
		statuses := make([]string, 0, resultsLimit(resultsSubset))
		for _, result := range highPriority {
			statuses = append(statuses, result.Status())
		}

		status := fmt.Sprintf(
			"%s: %s",
			resultsSubset.ServiceState().Label,
			strings.Join(statuses, ", "),
		)

		summary.WriteString(status)

	default:

		// Sort the entire results collection prior to copying a subset.
		ccvr.Sort()

		// Grab resultsLimit worth of results.
		highPriority := make(CertChainValidationResults, resultsLimit(ccvr))
		copy(highPriority, ccvr)

		// Collect the statuses of the results subset.
		statuses := make([]string, 0, resultsLimit(highPriority))
		for _, result := range highPriority {
			statuses = append(statuses, result.Status())
		}

		status := fmt.Sprintf(
			"%s: %s",
			highPriority.ServiceState().Label,
			strings.Join(statuses, ", "),
		)

		summary.WriteString(status)

	}

	return summary.String()
}

// OneLineSummary returns a one-line summary of the certificate chain
// validation results suitable for display and notification purposes. Not all
// validation results may be mentioned directly in the one-line summary text.
func (ccvr CertChainValidationResults) OneLineSummary() string {
	return fmt.Sprintf(
		"%s %s",
		ccvr.Status(),
		ccvr.Overview(),
	)
}

// Report returns a formatted report suitable for display and notification
// purposes. The caller is responsible for calling the Sort method first in
// order to arrange the validation results by appropriate priority.
func (ccvr CertChainValidationResults) Report() string {

	// Early exit; we have an empty validation results collection. This should
	// not be possible as config validation should protect against a sysadmin
	// inadvertently disabling all validation checks.
	//
	// The Status() method should have already taken care of making this
	// clear, so we opt to just return an empty string for this scenario.
	if !ccvr.IsOKState() && len(ccvr) == 0 {
		return ""
	}

	var summary strings.Builder

	// Ensure results are sorted prior to generated report output.
	ccvr.Sort()

	_, _ = fmt.Fprintf(
		&summary,
		"%s%sPROBLEM RESULTS:%s",
		nagios.CheckOutputEOL,
		nagios.CheckOutputEOL,
		nagios.CheckOutputEOL,
	)

	switch {
	case !ccvr.HasFailed():
		_, _ = fmt.Fprintf(
			&summary,
			"%s* None%s",
			nagios.CheckOutputEOL,
			nagios.CheckOutputEOL,
		)
	default:
		for _, result := range ccvr {
			if !result.IsOKState() {
				_, _ = fmt.Fprintf(
					&summary,
					// "\xE2\x9B\x94 [!!] %s%s",
					"%s[!!] %s%s%s",
					nagios.CheckOutputEOL,
					strings.TrimSpace(result.Report()),
					nagios.CheckOutputEOL,
					nagios.CheckOutputEOL,
				)
			}
		}
	}

	_, _ = fmt.Fprintf(
		&summary,
		"%s%sIGNORED RESULTS:%s",
		nagios.CheckOutputEOL,
		nagios.CheckOutputEOL,
		nagios.CheckOutputEOL,
	)

	switch {
	case !ccvr.HasIgnored():
		_, _ = fmt.Fprintf(
			&summary,
			"%s* None%s",
			nagios.CheckOutputEOL,
			nagios.CheckOutputEOL,
		)
	default:
		for _, result := range ccvr {
			if result.IsIgnored() {
				_, _ = fmt.Fprintf(
					&summary,
					// "\u23ED\uFE0F [--] %s%s",
					"%s[--] %s%s%s",
					nagios.CheckOutputEOL,
					strings.TrimSpace(result.Report()),
					nagios.CheckOutputEOL,
					nagios.CheckOutputEOL,
				)
			}
		}
	}

	_, _ = fmt.Fprintf(
		&summary,
		"%s%sSUCCESS RESULTS:%s",
		nagios.CheckOutputEOL,
		nagios.CheckOutputEOL,
		nagios.CheckOutputEOL,
	)

	switch {
	case !ccvr.HasSucceeded():
		_, _ = fmt.Fprintf(
			&summary,
			"%s* None%s",
			nagios.CheckOutputEOL,
			nagios.CheckOutputEOL,
		)
	default:
		for _, result := range ccvr {
			if result.IsSucceeded() {
				_, _ = fmt.Fprintf(
					&summary,
					// "\xE2\x9C\x85 [OK] %s%s",
					"%s[OK] %s%s%s",
					nagios.CheckOutputEOL,
					strings.TrimSpace(result.Report()),
					nagios.CheckOutputEOL,
					nagios.CheckOutputEOL,
				)
			}
		}

	}

	return summary.String()
}
