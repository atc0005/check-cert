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

	"github.com/atc0005/go-nagios"
)

// Add an "implements assertion" to fail the build if the interface
// implementation isn't correct.
var _ CertChainValidationResult = (*HostnameValidationResult)(nil)

// HostnameValidationResult is the validation result from verifying a given
// hostname against the leaf certificate in a certificate chain.
//
// NOTE: If specified by the user, hostname verification is ignored if no SANs
// entries are present for the leaf certificate.
type HostnameValidationResult struct {
	// certChain is the collection of certificates that we evaluated to
	// produce this validation check result.
	certChain []*x509.Certificate

	// leafCert is the first certificate from the chain that we evaluated to
	// produce this validation check result.
	leafCert *x509.Certificate

	// hostnameValue is the hostname value used during hostname verification.
	hostnameValue string

	// priorityModifier is applied when calculating the priority for a
	// validation check result. If a validation check result has an associated
	// error but is flagged as ignored then the base priority value is used
	// and this modifier is ignored.
	//
	// If the validation check is not flagged as ignored than this modifier is
	// used to calculate the final priority level.
	priorityModifier int

	// err is the "final" error describing the validation attempt.
	err error

	// ignored indicates whether validation check results are ignored for the
	// certificate chain.
	ignored bool

	// ignoreWhenEmptySANsList tracks whether a request was made to ignore
	// validation check results for the hostname when the leaf certificate's
	// Subject Alternate Names (SANs) list is found to be empty.
	ignoreWhenEmptySANsList bool

	// ignoreIfSANsEmptyFlagName records the flag name used to indicate
	// whether a request was made to ignore validation check results for the
	// hostname when the leaf certificate's Subject Alternate Names (SANs)
	// list is found to be empty. This flag name is referenced in output.
	ignoreIfSANsEmptyFlagName string
}

// ValidateHostname asserts that a given server or DNS Name successfully
// matches the leaf certificate for a certificate chain. If the DNS Name value
// is specified it is used when verifying the hostname, otherwise an attempt
// is made to use the given server value.
//
// Validation check results are ignored when the SANs list is found to be
// empty if the caller requests this. This option may be needed where the
// sysadmin wishes to perform expiration validation for certificates missing
// SANs entries (and does not wish to fail the overall plugin status due to
// the certificate lacking SANs entries).
//
// Validation check results are *also* ignored if explicitly requested.
func ValidateHostname(
	certChain []*x509.Certificate,
	server string,
	dnsName string,
	shouldApply bool,
	ignoreIfSANsEmpty bool,
	ignoreIfSANsEmptyFlagName string,
) HostnameValidationResult {

	// TODO: Assert that first cert really is a leaf cert?
	leafCert := certChain[0]

	// Ignore validation requests if explicitly requested.
	isResultIgnored := func() bool {
		return !shouldApply
	}

	// Default to using the server FQDN or IP Address used to make the
	// connection as our hostname value.
	hostnameValue := server

	// Allow the user to explicitly specify which hostname should be used
	// for comparison against the leaf certificate. This works for a
	// certificate retrieved by a server as well as a certificate
	// retrieved from a file.
	if dnsName != "" {
		hostnameValue = dnsName
	}

	switch {
	case strings.TrimSpace(server) == "" &&
		strings.TrimSpace(dnsName) == "":

		return HostnameValidationResult{
			certChain:                 certChain,
			leafCert:                  leafCert,
			hostnameValue:             hostnameValue,
			ignoreIfSANsEmptyFlagName: ignoreIfSANsEmptyFlagName,
			err: fmt.Errorf(
				"server or dns name values are required"+
					" for hostname verification: %w",
				ErrMissingValue,
			),
			ignored:          isResultIgnored(),
			priorityModifier: priorityModifierMaximum,
		}

	case len(certChain) == 0:
		return HostnameValidationResult{
			certChain:                 certChain,
			leafCert:                  leafCert,
			hostnameValue:             hostnameValue,
			ignoreIfSANsEmptyFlagName: ignoreIfSANsEmptyFlagName,
			err: fmt.Errorf(
				"required certificate chain is empty: %w",
				ErrMissingValue,
			),
			ignored:          isResultIgnored(),
			priorityModifier: priorityModifierMaximum,
		}
	}

	verifyErr := certChain[0].VerifyHostname(hostnameValue)

	switch {

	// Go 1.17 removed support for the legacy behavior of treating the
	// CommonName field on X.509 certificates as a host name when no Subject
	// Alternative Names are present. Go 1.17 also removed support for
	// re-enabling the behavior by way of adding the value x509ignoreCN=0 to
	// the GODEBUG environment variable.
	//
	// If the SANs list is empty and if requested, we mark this hostname
	// verification failure as ignored. We still record the error so that we
	// can surface it as an issue for the sysadmin to be aware of.
	case verifyErr != nil &&
		len(certChain[0].DNSNames) == 0 &&
		ignoreIfSANsEmpty:

		return HostnameValidationResult{
			certChain:                 certChain,
			leafCert:                  leafCert,
			hostnameValue:             hostnameValue,
			err:                       verifyErr,
			ignored:                   true,
			ignoreWhenEmptySANsList:   ignoreIfSANsEmpty,
			ignoreIfSANsEmptyFlagName: ignoreIfSANsEmptyFlagName,

			// Minimal priority bump since this is an issue that the
			// sysadmin has indicated should be worked around.
			priorityModifier: priorityModifierMinimum,
		}

	// Go 1.17 removed support for the legacy behavior of treating the
	// CommonName field on X.509 certificates as a host name when no
	// Subject Alternative Names are present. Go 1.17 also removed
	// support for re-enabling the behavior by way of adding the value
	// x509ignoreCN=0 to the GODEBUG environment variable.
	//
	// We attempt to detect this situation in order to supply additional
	// troubleshooting information and guidance to resolve the issue. We
	// accomplish this by setting a very specific error and looking for this
	// error later when deciding which feedback to provide.
	//
	// We intentionally do not mark this validation check result as ignored as
	// the sysadmin did not opt to explicitly do so.

	case verifyErr != nil &&
		(verifyErr.Error() == ErrX509CertReliesOnCommonName.Error() ||
			len(certChain[0].DNSNames) == 0):

		return HostnameValidationResult{
			certChain:     certChain,
			leafCert:      leafCert,
			hostnameValue: hostnameValue,
			err:           ErrX509CertReliesOnCommonName,
			// We intentionally do not mark this validation check result as ignored as
			// the sysadmin did not opt to explicitly do so.
			// ignored:                   false,

			// Mark result as ignored *if* the sysadmin explicitly requested
			// that we do so.
			ignored:                   isResultIgnored(),
			ignoreWhenEmptySANsList:   ignoreIfSANsEmpty,
			ignoreIfSANsEmptyFlagName: ignoreIfSANsEmptyFlagName,

			// Medium priority bump since this is an issue that the sysadmin
			// has a workaround available for.
			priorityModifier: priorityModifierMedium,
		}

	// Hostname verification failed for another reason aside from an
	// empty SANs list.
	case verifyErr != nil:
		return HostnameValidationResult{
			certChain:                 certChain,
			leafCert:                  leafCert,
			hostnameValue:             hostnameValue,
			ignoreIfSANsEmptyFlagName: ignoreIfSANsEmptyFlagName,
			err: fmt.Errorf(
				"hostname verification failed: %w",
				verifyErr,
			),
			ignored:          isResultIgnored(),
			priorityModifier: priorityModifierMinimum,
		}

	// Hostname verification succeeded.
	default:
		return HostnameValidationResult{
			certChain:                 certChain,
			leafCert:                  leafCert,
			hostnameValue:             hostnameValue,
			ignoreIfSANsEmptyFlagName: ignoreIfSANsEmptyFlagName,

			// Q: Should an explicitly ignored result be ignored if the
			// validation was successful?
			//
			// A: Yes, *if* the sysadmin explicitly requested that the result
			// be ignored.
			ignored: isResultIgnored(),
		}

	}

}

// CheckName emits the human-readable name of this validation check result.
func (hnvr HostnameValidationResult) CheckName() string {
	return checkNameHostnameValidationResult
}

// CertChain returns the evaluated certificate chain.
func (hnvr HostnameValidationResult) CertChain() []*x509.Certificate {
	return hnvr.certChain
}

// TotalCerts returns the number of certificates in the evaluated certificate
// chain.
func (hnvr HostnameValidationResult) TotalCerts() int {
	return len(hnvr.certChain)
}

// IsWarningState indicates whether this validation check result is in a
// WARNING state. This returns false if the validation check resulted in an OK
// or CRITICAL state, or is flagged as ignored. True is returned otherwise.
func (hnvr HostnameValidationResult) IsWarningState() bool {
	// This state is not used for this certificate validation check.
	return false
}

// IsCriticalState indicates whether this validation check result is in a
// CRITICAL state. This returns false if the validation check resulted in an
// OK or WARNING state, or is flagged as ignored. True is returned otherwise.
func (hnvr HostnameValidationResult) IsCriticalState() bool {
	return hnvr.err != nil && !hnvr.IsIgnored()
}

// IsUnknownState indicates whether this validation check result is in an
// UNKNOWN state.
func (hnvr HostnameValidationResult) IsUnknownState() bool {
	// This state is not used for this certificate validation check.
	return false
}

// IsOKState indicates whether this validation check result is in an OK or
// passing state. For the purposes of validation check evaluation, ignored
// validation checks are considered to be a subset of OK status.
func (hnvr HostnameValidationResult) IsOKState() bool {
	return hnvr.err == nil || hnvr.IsIgnored()
}

// IsIgnored indicates whether this validation check result was flagged as
// ignored for the purposes of determining final validation state.
func (hnvr HostnameValidationResult) IsIgnored() bool {
	return hnvr.ignored
}

// IsSucceeded indicates whether this validation check result is not flagged
// as ignored and no problems with the certificate chain were identified.
func (hnvr HostnameValidationResult) IsSucceeded() bool {
	return hnvr.IsOKState() && !hnvr.IsIgnored()
}

// IsFailed indicates whether this validation check result is not flagged as
// ignored and problems were identified.
func (hnvr HostnameValidationResult) IsFailed() bool {
	return hnvr.err != nil && !hnvr.IsIgnored()
}

// Err returns the underlying error (if any) regardless of whether this
// validation check result is flagged as ignored.
func (hnvr HostnameValidationResult) Err() error {
	return hnvr.err
}

// ServiceState returns the appropriate Service Check Status label and exit
// code for this validation check result.
func (hnvr HostnameValidationResult) ServiceState() nagios.ServiceState {
	return ServiceState(hnvr)
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
func (hnvr HostnameValidationResult) Priority() int {
	switch {
	case hnvr.ignored:
		return baselinePriorityHostnameValidationResult
	default:
		return baselinePriorityHostnameValidationResult + hnvr.priorityModifier
	}
}

// Overview provides a high-level summary of this validation check result.
func (hnvr HostnameValidationResult) Overview() string {
	// No Overview content at this time.
	return ""
}

// Status is intended as a brief status of the validation check result. This
// can be used as initial lead-in text.
func (hnvr HostnameValidationResult) Status() string {
	var status string
	switch {

	// User opted to ignore validation check results.
	case hnvr.IsIgnored():
		status = fmt.Sprintf(
			"%s validation using value %q ignored for %s cert",
			hnvr.CheckName(),
			hnvr.hostnameValue,
			ChainPosition(hnvr.leafCert, hnvr.certChain),
		)

		if len(hnvr.certChain[0].DNSNames) == 0 && hnvr.ignoreWhenEmptySANsList {
			status += " as requested for empty SANs list"
		}

	case errors.Is(hnvr.err, ErrX509CertReliesOnCommonName):

		status = fmt.Sprintf(
			"%s validation using value %q failed for first cert in chain",
			hnvr.CheckName(),
			hnvr.hostnameValue,
		)

	case hnvr.err != nil:
		status = fmt.Sprintf(
			"%s validation using value %q failed for %s certificate",
			hnvr.CheckName(),
			hnvr.hostnameValue,
			ChainPosition(hnvr.leafCert, hnvr.certChain),
		)

	// No validation errors occurred.
	default:
		status = fmt.Sprintf(
			"%s validation using value %q successful for %s certificate",
			hnvr.CheckName(),
			hnvr.hostnameValue,
			ChainPosition(hnvr.leafCert, hnvr.certChain),
		)

	}

	return status

}

// StatusDetail provides additional details intended to extend the shorter
// status text with information suitable as explanation for the overall state
// of the validation check result. This text may span multiple lines.
func (hnvr HostnameValidationResult) StatusDetail() string {
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
	// if hnvr.err != nil && !hnvr.ignored {
	// 	fmt.Fprintf(
	// 		&detail,
	// 		"%s%s%s",
	// 		hnvr.err.Error(),
	// 		nagios.CheckOutputEOL,
	// 		nagios.CheckOutputEOL,
	// 	)
	// }

	switch {

	// User opted to ignore validation check results.
	case hnvr.IsIgnored():

		// Add a specific warning or FYI message for sysadmin when the flag to
		// ignore hostname validation when a leaf cet has an empty SANs list.
		if hnvr.ignoreWhenEmptySANsList {
			detail.WriteString("NOTE: The option to ignore hostname verification when" +
				" certificate Subject Alternate Names (SANs) list is empty" +
				" has been specified." +
				nagios.CheckOutputEOL +
				nagios.CheckOutputEOL +
				"While viable as a short-term workaround for certificates" +
				" missing SANs list entries, this is not recommended as a" +
				" long-term fix. Instead, certificates missing SANs entries" +
				" should be replaced in order to avoid hostname verification" +
				" errors. For example, web browsers have deprecated using" +
				" the CommonName field of certificates missing SANs entries" +
				" for hostname verification." +
				nagios.CheckOutputEOL +
				nagios.CheckOutputEOL +
				"See these resources for additional information: " +
				nagios.CheckOutputEOL +
				nagios.CheckOutputEOL +
				" - https://github.com/atc0005/check-cert/issues/276" +
				nagios.CheckOutputEOL +
				" - https://chromestatus.com/feature/4981025180483584" +
				nagios.CheckOutputEOL +
				" - https://bugzilla.mozilla.org/show_bug.cgi?id=1245280")
		}

	// Go 1.17 removed support for the legacy behavior of treating the
	// CommonName field on X.509 certificates as a host name when no
	// Subject Alternative Names are present. Go 1.17 also removed
	// support for re-enabling the behavior by way of adding the value
	// x509ignoreCN=0 to the GODEBUG environment variable.
	//
	// We attempt to detect this situation in order to supply additional
	// troubleshooting information and guidance to resolve the issue.
	case errors.Is(hnvr.err, ErrX509CertReliesOnCommonName):

		detail.WriteString("This certificate does not contain Subject Alternate Names (SANs)" +
			" and should be replaced." +
			nagios.CheckOutputEOL +
			nagios.CheckOutputEOL +
			"As a temporary workaround you can:" +
			nagios.CheckOutputEOL +
			"  1. set the GODEBUG environment variable to" +
			" 'GODEBUG=x509ignoreCN=0' AND either deploy v0.5.3 of" +
			" this plugin or rebuild this plugin using Go 1.16" +
			nagios.CheckOutputEOL +
			"  2. specify the '" + hnvr.ignoreIfSANsEmptyFlagName + "'" +
			" flag to skip hostname verification if the" +
			" SANs list is found to be empty" +
			nagios.CheckOutputEOL +
			nagios.CheckOutputEOL +
			"See these resources for additional information: " +
			nagios.CheckOutputEOL +
			nagios.CheckOutputEOL +
			" - https://github.com/atc0005/check-cert/issues/276" +
			nagios.CheckOutputEOL +
			" - https://chromestatus.com/feature/4981025180483584" +
			nagios.CheckOutputEOL +
			" - https://bugzilla.mozilla.org/show_bug.cgi?id=1245280" +
			nagios.CheckOutputEOL +
			nagios.CheckOutputEOL +
			"Here is an example of building the plugin using the last" +
			" Go 1.16 Docker image:" +
			nagios.CheckOutputEOL +
			"docker container run -it --rm -v $PWD:$PWD" +
			" -w $PWD golang:1.16 go build ./cmd/check_cert/")

	// Hostname verification failed for another reason aside from an empty
	// SANs list.
	case hnvr.err != nil:
		detail.WriteString("Consider updating the service check or command " +
			"definition to specify the website FQDN instead of " +
			"the host FQDN using the DNS Name or server flags. " +
			"E.g., use 'www.example.org' instead of " +
			"'host7.example.com' in order to allow the remote " +
			"server to select the correct certificate instead " +
			"of using the default certificate.")

	// No validation errors occurred.
	default:

		// TODO: Anything to add for successful hostname verification?

	}

	return detail.String()
}

// String provides the validation check result in human-readable format.
func (hnvr HostnameValidationResult) String() string {
	return fmt.Sprintf(
		"%s %s",
		hnvr.Status(),
		hnvr.Overview(),
	)
}

// Report provides the validation check result in verbose human-readable
// format.
func (hnvr HostnameValidationResult) Report() string {

	detail := hnvr.StatusDetail()
	switch {
	case detail == "":
		return fmt.Sprintf(
			"%s %s",
			hnvr.Status(),
			hnvr.Overview(),
		)
	default:
		return fmt.Sprintf(
			"%s %s%s%s%s",
			hnvr.Status(),
			hnvr.Overview(),
			nagios.CheckOutputEOL,
			nagios.CheckOutputEOL,
			hnvr.StatusDetail(),
		)
	}

}
