// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package certs

import (
	"crypto"

	// We use this to verify MD5WithRSA signatures.
	// nolint:gosec
	"crypto/md5"
	"crypto/sha256"

	// We use this to generate SHA1 fingerprints
	// nolint:gosec
	"crypto/sha1"
	"crypto/sha512"

	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/atc0005/check-cert/internal/textutils"
	"github.com/atc0005/go-nagios"
)

var (
	// ErrMissingValue indicates that an expected value was missing.
	ErrMissingValue = errors.New("missing expected value")

	// ErrNoCertsFound indicates that no certificates were found when
	// evaluating a certificate chain. This error is not really expected to
	// ever occur.
	ErrNoCertsFound = errors.New("no certificates found")

	// ErrExpiredCertsFound indicates that one or more certificates were found
	// to be expired when evaluating a certificate chain.
	ErrExpiredCertsFound = errors.New("expired certificates found")

	// ErrExpiringCertsFound indicates that one or more certificates were
	// found to be expiring soon when evaluating a certificate chain.
	ErrExpiringCertsFound = errors.New("expiring certificates found")

	// ErrHostnameVerificationFailed indicates a mismatch between a
	// certificate and a given hostname.
	ErrHostnameVerificationFailed = errors.New("hostname verification failed")

	// ErrCertMissingSANsEntries indicates that a certificate is missing one or
	// more Subject Alternate Names specified by the user.
	ErrCertMissingSANsEntries = errors.New("certificate is missing requested SANs entries")
	// ErrCertMissingSANsEntries = errors.New("certificate is missing Subject Alternate Name entries")

	// ErrCertHasUnexpectedSANsEntries indicates that a certificate has one or
	// more Subject Alternate Names not specified by the user.
	ErrCertHasUnexpectedSANsEntries = errors.New("certificate has unexpected SANs entries")
	// ErrCertHasUnexpectedSANsEntries = errors.New("certificate has unexpected Subject Alternate Name entries")

	// ErrCertHasMissingAndUnexpectedSANsEntries indicates that a certificate is
	// missing one or more Subject Alternate Names specified by the user and also
	// contains one more more Subject Alternate Names not specified by the user.
	ErrCertHasMissingAndUnexpectedSANsEntries = errors.New("certificate is missing requested SANs entries, has unexpected SANs entries")
	// ErrCertHasMissingAndUnexpectedSANsEntries = errors.New("certificate is missing and has unexpected Subject Alternate Name entries")

	// ErrX509CertReliesOnCommonName mirrors the unexported error string
	// emitted by the HostnameError.Error() method from the x509 package.
	//
	// https://cs.opensource.google/go/go/+/refs/tags/go1.20.1:src/crypto/x509/verify.go;l=104
	//
	// This error string is emitted when a certificate is missing Subject
	// Alternate Names (SANs) AND a specified hostname matches the Common Name
	// field.
	//
	// TODO: Open RFE in Go project asking that this be made an exportable
	// error value so that we can drop this hard-coded version (which is bound
	// to become a problem at some point).
	// https://github.com/atc0005/check-cert/issues/520
	//
	ErrX509CertReliesOnCommonName = errors.New("x509: certificate relies on legacy Common Name field, use SANs instead")

	// ErrNoCertValidationResults indicates that the cert chain validation
	// results collection is empty. This is an unusual condition as
	// configuration validation requires that at least one validation check is
	// performed.
	ErrNoCertValidationResults = errors.New("certificate validation results collection is empty")
)

// ServiceStater represents a type that is capable of evaluating its overall
// state.
type ServiceStater interface {
	IsCriticalState() bool
	IsWarningState() bool
	IsOKState() bool
}

// CertChainValidationOptions is a collection of validation options shared by
// all validation functions for types implementing the
// CertChainValidationResult interface.
//
// Not all options are used by each validation function.
type CertChainValidationOptions struct {

	// IgnoreHostnameVerificationFailureIfEmptySANsList tracks whether a
	// request was made to ignore validation check results for the hostname
	// when the leaf certificate's Subject Alternate Names (SANs) list is
	// found to be empty.
	IgnoreHostnameVerificationFailureIfEmptySANsList bool

	// IgnoreValidationResultExpiration tracks whether a request was made to
	// ignore validation check results for certificate expiration. This is a
	// broad/blanket request that ignores expiration validation issues for ALL
	// certificates in a chain, not just the leaf/server certificate.
	IgnoreValidationResultExpiration bool

	// IgnoreValidationResultHostname tracks whether a request was made to
	// ignore validation check results from verifying a given hostname against
	// the leaf certificate in a certificate chain.
	IgnoreValidationResultHostname bool

	// IgnoreValidationResultSANs tracks whether a request was made to ignore
	// validation check results result from performing a Subject Alternate
	// Names (SANs) validation against a leaf certificate in a chain.
	IgnoreValidationResultSANs bool

	// IgnoreExpiredIntermediateCertificates tracks whether a request was made
	// to ignore validation check results for certificate expiration against
	// intermediate certificates in a certificate chain.
	IgnoreExpiredIntermediateCertificates bool

	// IgnoreExpiredRootCertificates tracks whether a request was made to
	// ignore validation check results for certificate expiration against root
	// certificates in a certificate chain.
	IgnoreExpiredRootCertificates bool
}

// DiscoveredCertChain represents the certificate chain found on a specific
// host along with that host's IP/Name and port.
type DiscoveredCertChain struct {
	// Name is the hostname or FQDN of a system where a certificate chain was
	// retrieved. Depending on how scan targets were specified, this value may
	// not be populated.
	Name string

	// IPAddress is the IP Address where a certificate chain was discovered.
	// This value should always be populated.
	IPAddress string

	// Port is the TCP port where a certificate chain was retrieved.
	Port int

	// Certs is the certificate chain associated with a host.
	Certs []*x509.Certificate
}

// DiscoveredCertChains is a collection of discovered certificate chains for
// specified hosts and ports.
type DiscoveredCertChains []DiscoveredCertChain

// CertValidityDateLayout is the chosen date layout for displaying certificate
// validity date/time values across our application.
const CertValidityDateLayout string = "2006-01-02 15:04:05 -0700 MST"

const (
	certChainPositionLeaf           string = "leaf"
	certChainPositionLeafSelfSigned string = "leaf; self-signed"
	certChainPositionIntermediate   string = "intermediate"
	certChainPositionRoot           string = "root"
	certChainPositionUnknown        string = "UNKNOWN cert chain position; please submit a bug report"
)

// ExpirationValidationOneLineSummaryExpiresNextTmpl is a shared template
// string used for emitting one-line service check status output for
// certificate chains whose certificates have not expired yet.
const ExpirationValidationOneLineSummaryExpiresNextTmpl string = "%s validation %s: %s cert %q expires next with %s (until %s)"

// ExpirationValidationOneLineSummaryExpiredTmpl is a shared template string
// used for emitting one-line service check status output for certificate
// chains with expired certificates.
const ExpirationValidationOneLineSummaryExpiredTmpl string = "%s validation %s: %s cert %q expired %s (on %s)"

// X509CertReliesOnCommonName mirrors the unexported error string emitted by
// the HostnameError.Error() method from the x509 package.
//
// This error string is emitted when a certificate is missing Subject
// Alternate Names (SANs) AND a specified hostname matches the Common Name
// field.
//
// Deprecated: See the ErrX509CertReliesOnCommonName value instead.
const X509CertReliesOnCommonName string = "x509: certificate relies on legacy Common Name field, use SANs instead"

// Names of certificate chain validation checks.
const (
	// checkNameExpirationValidationResult string = "Certificate Chain Expiration"
	// checkNameHostnameValidationResult   string = "Leaf Certificate Hostname"
	// checkNameSANsListValidationResult   string = "Leaf Certificate SANs List"
	// checkNameExpirationValidationResult string = "Expiration Validation"
	// checkNameHostnameValidationResult   string = "Hostname Validation"
	// checkNameSANsListValidationResult   string = "SANs List Validation"
	checkNameExpirationValidationResult string = "Expiration"
	checkNameHostnameValidationResult   string = "Hostname"
	checkNameSANsListValidationResult   string = "SANs List"
)

// Baseline priority values for validation results. Higher values indicate
// higher priority.
const (
	baselinePrioritySANsListValidationResult int = iota + 1
	baselinePriorityHostnameValidationResult
	baselinePriorityExpirationValidationResult
)

// Priority modifiers for validation results. These values are used to boost
// the baseline priority of a validation result in order to allow it to "jump
// the line" for review purposes.
const (

	// priorityModifierMaximum represents the maximum priority modifier for a
	// validation result. This modifier is usually applied for critical sanity
	// check failures (e.g., wrong range of requested values) or significant
	// issues needing immediate attention (e.g., "expired certificates" vs
	// "expiring soon" certificates).
	priorityModifierMaximum int = 999

	// priorityModifierMedium represents a medium priority modifier for a
	// validation result. This modifier is usually applied for check failures
	// with optional workarounds (e.g., "empty SANs list on cert").
	priorityModifierMedium int = 2

	// priorityModifierMinimum represents the minimum priority modifier for a
	// validation result. This modifier is usually applied for minor check
	// failures (e.g., "expiring soon").
	priorityModifierMinimum int = 1

	// priorityModifierBaseline represents the baseline priority modifier for
	// a validation result. This modifier is usually applied in order to
	// explicitly communicate that the default or baseline value for a
	// validation check is used (NOOP; e.g., for an OK result).
	priorityModifierBaseline int = 0
)

// ServiceState accepts a type capable of evaluating its status and uses those
// results to map to a compatible ServiceState value.
func ServiceState(val ServiceStater) nagios.ServiceState {
	var stateLabel string
	var stateExitCode int

	switch {
	case val.IsCriticalState():
		stateLabel = nagios.StateCRITICALLabel
		stateExitCode = nagios.StateCRITICALExitCode
	case val.IsWarningState():
		stateLabel = nagios.StateWARNINGLabel
		stateExitCode = nagios.StateWARNINGExitCode
	case val.IsOKState():
		stateLabel = nagios.StateOKLabel
		stateExitCode = nagios.StateOKExitCode
	default:
		stateLabel = nagios.StateUNKNOWNLabel
		stateExitCode = nagios.StateUNKNOWNExitCode
	}

	return nagios.ServiceState{
		Label:    stateLabel,
		ExitCode: stateExitCode,
	}
}

// GetCertsFromFile is a helper function for retrieving a certificate chain
// from a specified PEM formatted certificate file. An error is returned if
// the file cannot be decoded and parsed (e.g., empty file, not PEM
// formatted). Any leading non-PEM formatted data is skipped while any
// trailing non-PEM formatted data is returned for potential further
// evaluation.
func GetCertsFromFile(filename string) ([]*x509.Certificate, []byte, error) {

	var certChain []*x509.Certificate

	// Read in the entire PEM certificate file after first attempting to
	// sanitize the input file variable contents.
	pemData, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, nil, err
	}

	// Grab the first PEM formatted block in our PEM cert file data.
	block, rest := pem.Decode(pemData)

	switch {
	case block == nil:
		return nil, nil, fmt.Errorf(
			"failed to decode %s as PEM formatted certificate file; potentially malformed certificate",
			filename,
		)
	case len(block.Bytes) == 0:
		return nil, nil, fmt.Errorf(
			"failed to decode %s as PEM formatted certificate file; potentially empty certificate file",
			filename,
		)
	}

	// If there is only one certificate (e.g., "server" or "leaf" certificate)
	// we'll only get one block from the last pem.Decode() call. However, if
	// the file contains a certificate chain or "bundle" we will need to call
	// pem.Decode() multiple times, so we setup a loop to handle that.
	for {

		if block != nil {

			// fmt.Println("Type of block:", block.Type)
			// fmt.Println("size of file content:", len(pemData))
			// fmt.Println("size of rest:", len(rest))

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, err
			}

			// we got a cert. Let's add it to our list
			certChain = append(certChain, cert)

			if len(rest) > 0 {
				block, rest = pem.Decode(rest)

				// if we were able to decode the "rest" of the data, then
				// iterate again so we can parse it
				if block != nil {
					continue
				}
			}

			break
		}

		// we're done attempting to decode the cert file; we have found data
		// that fails to decode properly
		if len(rest) > 0 {
			break
		}
	}

	return certChain, rest, err

}

// IsExpiredCert receives a x509 certificate and returns a boolean value
// indicating whether the cert has expired.
func IsExpiredCert(cert *x509.Certificate) bool {
	return cert.NotAfter.Before(time.Now())
}

// IsExpiringCert receives a x509 certificate, CRITICAL age threshold and
// WARNING age threshold values and uses the provided thresholds to determine
// if the certificate is about to expire. A boolean value is returned to
// indicate the results of this check. An expired certificate fails this
// check.
func IsExpiringCert(cert *x509.Certificate, ageCritical time.Time, ageWarning time.Time) bool {

	switch {
	case !IsExpiredCert(cert) && cert.NotAfter.Before(ageCritical):
		return true
	case !IsExpiredCert(cert) && cert.NotAfter.Before(ageWarning):
		return true
	}

	return false

}

// HasExpiredCert receives a slice of x509 certificates and indicates whether
// any of the certificates in the chain have expired.
func HasExpiredCert(certChain []*x509.Certificate) bool {

	for idx := range certChain {
		if certChain[idx].NotAfter.Before(time.Now()) {
			return true
		}
	}

	return false

}

// HasExpiringCert receives a slice of x509 certificates, CRITICAL age
// threshold and WARNING age threshold values and ignoring any certificates
// already expired, uses the provided thresholds to determine if any
// certificates are about to expire. A boolean value is returned to indicate
// the results of this check.
func HasExpiringCert(certChain []*x509.Certificate, ageCritical time.Time, ageWarning time.Time) bool {
	for idx := range certChain {
		switch {
		case !IsExpiredCert(certChain[idx]) && certChain[idx].NotAfter.Before(ageCritical):
			return true
		case !IsExpiredCert(certChain[idx]) && certChain[idx].NotAfter.Before(ageWarning):
			return true
		}
	}

	return false

}

// NumExpiredCerts receives a slice of x509 certificates and returns a count
// of how many certificates have expired.
func NumExpiredCerts(certChain []*x509.Certificate) int {

	var expiredCertsCount int

	for idx := range certChain {
		if certChain[idx].NotAfter.Before(time.Now()) {
			expiredCertsCount++
		}
	}

	return expiredCertsCount

}

// NumExpiringCerts receives a slice of x509 certificates, CRITICAL age threshold
// and WARNING age threshold values and ignoring any certificates already
// expired, uses the provided thresholds to determine if any certificates are
// about to expire. A count of expiring certificates is returned.
func NumExpiringCerts(certChain []*x509.Certificate, ageCritical time.Time, ageWarning time.Time) int {

	var expiringCertsCount int
	for idx := range certChain {
		switch {
		case !IsExpiredCert(certChain[idx]) && certChain[idx].NotAfter.Before(ageCritical):
			expiringCertsCount++
		case !IsExpiredCert(certChain[idx]) && certChain[idx].NotAfter.Before(ageWarning):
			expiringCertsCount++
		}
	}

	return expiringCertsCount

}

// IsLeafCert indicates whether a given certificate from a certificate chain
// is a leaf or server certificate.
func IsLeafCert(cert *x509.Certificate, certChain []*x509.Certificate) bool {
	chainPos := ChainPosition(cert, certChain)
	switch chainPos {
	case certChainPositionLeaf:
		return true
	case certChainPositionLeafSelfSigned:
		return true
	default:
		return false
	}
}

// IsIntermediateCert indicates whether a given certificate from a certificate
// chain is an intermediate certificate.
func IsIntermediateCert(cert *x509.Certificate, certChain []*x509.Certificate) bool {
	chainPos := ChainPosition(cert, certChain)

	return chainPos == certChainPositionIntermediate
}

// IsRootCert indicates whether a given certificate from a certificate chain
// is a root certificate.
func IsRootCert(cert *x509.Certificate, certChain []*x509.Certificate) bool {
	chainPos := ChainPosition(cert, certChain)

	return chainPos == certChainPositionRoot
}

// NumLeafCerts receives a slice of x509 certificates and returns a count of
// leaf certificates present in the chain.
func NumLeafCerts(certChain []*x509.Certificate) int {
	var num int
	for _, cert := range certChain {
		chainPos := ChainPosition(cert, certChain)
		switch chainPos {
		case certChainPositionLeaf:
			num++
		case certChainPositionLeafSelfSigned:
			num++
		}
	}

	return num
}

// NumIntermediateCerts receives a slice of x509 certificates and returns a
// count of intermediate certificates present in the chain.
func NumIntermediateCerts(certChain []*x509.Certificate) int {
	var num int
	for _, cert := range certChain {
		chainPos := ChainPosition(cert, certChain)
		if chainPos == certChainPositionIntermediate {
			num++
		}
	}

	return num
}

// NumRootCerts receives a slice of x509 certificates and returns a
// count of root certificates present in the chain.
func NumRootCerts(certChain []*x509.Certificate) int {
	var num int
	for _, cert := range certChain {
		chainPos := ChainPosition(cert, certChain)
		if chainPos == certChainPositionRoot {
			num++
		}
	}

	return num
}

// NumUnknownCerts receives a slice of x509 certificates and returns a count
// of unidentified certificates present in the chain.
func NumUnknownCerts(certChain []*x509.Certificate) int {
	var num int
	for _, cert := range certChain {
		chainPos := ChainPosition(cert, certChain)
		if chainPos == certChainPositionUnknown {
			num++
		}
	}

	return num
}

// LeafCerts receives a slice of x509 certificates and returns a (potentially
// empty) collection of leaf certificates present in the chain.
func LeafCerts(certChain []*x509.Certificate) []*x509.Certificate {
	numPresent := NumLeafCerts(certChain)
	leafCerts := make([]*x509.Certificate, 0, numPresent)

	for _, cert := range certChain {
		chainPos := ChainPosition(cert, certChain)
		switch chainPos {
		case certChainPositionLeaf:
			leafCerts = append(leafCerts, cert)
		case certChainPositionLeafSelfSigned:
			leafCerts = append(leafCerts, cert)
		}

	}

	return leafCerts
}

// IntermediateCerts receives a slice of x509 certificates and returns a
// (potentially empty) collection of intermediate certificates present in the
// chain.
func IntermediateCerts(certChain []*x509.Certificate) []*x509.Certificate {
	numPresent := NumIntermediateCerts(certChain)
	intermediateCerts := make([]*x509.Certificate, 0, numPresent)

	for _, cert := range certChain {
		chainPos := ChainPosition(cert, certChain)
		if chainPos == certChainPositionIntermediate {
			intermediateCerts = append(intermediateCerts, cert)
		}
	}

	return intermediateCerts
}

// RootCerts receives a slice of x509 certificates and returns a (potentially
// empty) collection of root certificates present in the chain.
func RootCerts(certChain []*x509.Certificate) []*x509.Certificate {
	numPresent := NumRootCerts(certChain)
	rootCerts := make([]*x509.Certificate, 0, numPresent)

	for _, cert := range certChain {
		chainPos := ChainPosition(cert, certChain)
		if chainPos == certChainPositionRoot {
			rootCerts = append(rootCerts, cert)
		}
	}

	return rootCerts
}

// OldestLeafCert returns the oldest leaf certificate in a given certificate
// chain. If a leaf certificate is not not present nil is returned.
func OldestLeafCert(certChain []*x509.Certificate) *x509.Certificate {
	leafs := LeafCerts(certChain)

	return NextToExpire(leafs, false)
}

// OldestIntermediateCert returns the oldest intermediate certificate in a
// given certificate chain. If a leaf certificate is not not present nil is
// returned.
func OldestIntermediateCert(certChain []*x509.Certificate) *x509.Certificate {
	intermediates := IntermediateCerts(certChain)

	return NextToExpire(intermediates, false)
}

// OldestRootCert returns the oldest root certificate in a given certificate
// chain. If a root certificate is not not present nil is returned.
func OldestRootCert(certChain []*x509.Certificate) *x509.Certificate {
	roots := RootCerts(certChain)

	return NextToExpire(roots, false)
}

// ExpiresInDays evaluates the given certificate and returns the number of
// days until the certificate expires. If already expired, a negative number
// is returned indicating how many days the certificate is past expiration.
//
// An error is returned if the pointer to the given certificate is nil.
func ExpiresInDays(cert *x509.Certificate) (int, error) {
	if cert == nil {
		return 0, fmt.Errorf(
			"func ExpiresInDays: unable to determine expiration: %w",
			ErrMissingValue,
		)
	}

	timeRemaining := time.Until(cert.NotAfter).Hours()

	// Toss remainder so that we only get the whole number of days
	daysRemaining := int(math.Trunc(timeRemaining / 24))

	return daysRemaining, nil
}

// MaxLifespan returns the maximum lifespan for a given certificate from the
// date it was issued until the time it is scheduled to expire.
func MaxLifespan(cert *x509.Certificate) (time.Duration, error) {
	if cert == nil {
		return 0, fmt.Errorf(
			"func MaxLifespan: unable to determine expiration: %w",
			ErrMissingValue,
		)
	}

	maxCertLifespan := cert.NotAfter.Sub(cert.NotBefore)

	return maxCertLifespan, nil
}

// MaxLifespanInDays returns the maximum lifespan in days for a given
// certificate from the date it was issued until the time it is scheduled to
// expire.
func MaxLifespanInDays(cert *x509.Certificate) (int, error) {
	if cert == nil {
		return 0, fmt.Errorf(
			"func MaxLifespanInDays: unable to determine expiration: %w",
			ErrMissingValue,
		)
	}

	maxCertLifespan := cert.NotAfter.Sub(cert.NotBefore)
	daysMaxLifespan := int(math.Trunc(maxCertLifespan.Hours() / 24))

	return daysMaxLifespan, nil
}

// LifeRemainingPercentage returns the percentage of remaining time before a
// certificate expires.
func LifeRemainingPercentage(cert *x509.Certificate) (float64, error) {
	if cert == nil {
		return 0, fmt.Errorf(
			"func LifeRemainingPercentage: unable to determine expiration: %w",
			ErrMissingValue,
		)
	}

	if IsExpiredCert(cert) {
		return 0.0, nil
	}

	daysMaxLifespan, err := MaxLifespanInDays(cert)
	if err != nil {
		return 0, err
	}

	daysRemaining, err := ExpiresInDays(cert)
	if err != nil {
		return 0, err
	}

	certLifeRemainingPercentage := float64(daysRemaining) / float64(daysMaxLifespan) * 100

	return certLifeRemainingPercentage, nil
}

// LifeRemainingPercentageTruncated returns the truncated percentage of
// remaining time before a certificate expires.
func LifeRemainingPercentageTruncated(cert *x509.Certificate) (int, error) {
	if cert == nil {
		return 0, fmt.Errorf(
			"func LifeRemainingPercentageTruncated: unable to determine expiration: %w",
			ErrMissingValue,
		)
	}

	if IsExpiredCert(cert) {
		return 0, nil
	}

	certLifeRemainingPercentage, err := LifeRemainingPercentage(cert)
	if err != nil {
		return 0, err
	}

	certLifespanRemainingTruncated := int(math.Trunc(certLifeRemainingPercentage))

	return certLifespanRemainingTruncated, nil
}

// FormattedExpiration receives a Time value and converts it to a string
// representing the largest useful whole units of time in days and hours. For
// example, if a certificate has 1 year, 2 days and 3 hours remaining until
// expiration, this function will return the string '367d 3h remaining', but
// if only 3 hours remain then '3h remaining' will be returned. If a
// certificate has expired, the 'ago' suffix will be used instead. For
// example, if a certificate has expired 3 hours ago, '3h ago' will be
// returned.
func FormattedExpiration(expireTime time.Time) string {

	// hoursRemaining := time.Until(certificate.NotAfter)/time.Hour)/24,
	timeRemaining := time.Until(expireTime).Hours()

	var certExpired bool
	var formattedTimeRemainingStr string
	var daysRemainingStr string
	var hoursRemainingStr string

	// Flip sign back to positive, note that cert is expired for later use
	if timeRemaining < 0 {
		certExpired = true
		timeRemaining *= -1
	}

	// Toss remainder so that we only get the whole number of days
	daysRemaining := math.Trunc(timeRemaining / 24)

	if daysRemaining > 0 {
		daysRemainingStr = fmt.Sprintf("%dd", int64(daysRemaining))
	}

	// Multiply the whole number of days by 24 to get the hours value, then
	// subtract from the original number of hours until cert expiration to get
	// the number of hours leftover from the days calculation.
	hoursRemaining := math.Trunc(timeRemaining - (daysRemaining * 24))

	hoursRemainingStr = fmt.Sprintf("%dh", int64(hoursRemaining))

	// Only join days and hours remaining if there *are* days remaining.
	switch {
	case daysRemainingStr != "":
		formattedTimeRemainingStr = strings.Join(
			[]string{daysRemainingStr, hoursRemainingStr},
			" ",
		)
	default:
		formattedTimeRemainingStr = hoursRemainingStr
	}

	switch {
	case !certExpired:
		formattedTimeRemainingStr = strings.Join([]string{formattedTimeRemainingStr, "remaining"}, " ")
	case certExpired:
		formattedTimeRemainingStr = strings.Join([]string{formattedTimeRemainingStr, "ago"}, " ")
	}

	return formattedTimeRemainingStr

}

// FormatCertSerialNumber receives a certificate serial number in its native
// type and formats it in the text format used by OpenSSL (and many other
// tools).
//
// Example: DE:FD:50:2B:C5:7F:79:F4
func FormatCertSerialNumber(sn *big.Int) string {

	// convert serial number from native *bit.Int format to a hex string
	// snHexStr := sn.Text(16)
	//
	// use Sprintf hex formatting in order to retain leading zero (GH-114)
	// credit: inspired by discussion on mozilla/tls-observatory#245
	snHexStr := fmt.Sprintf("%X", sn.Bytes())

	delimiterPosition := 2
	delimiter := ":"

	// ignore the leading negative sign if present
	if sn.Sign() == -1 {
		snHexStr = strings.TrimPrefix(snHexStr, "-")
	}

	formattedSerialNum := textutils.InsertDelimiter(snHexStr, delimiter, delimiterPosition)
	formattedSerialNum = strings.ToUpper(formattedSerialNum)

	// add back negative sign if originally present
	if sn.Sign() == -1 {
		return "-" + formattedSerialNum
	}

	return formattedSerialNum

}

// ExpirationStatus receives a certificate and the expiration threshold values
// for CRITICAL and WARNING states and returns a human-readable string
// indicating the overall status at a glance. If requested, an expired
// certificate is marked as ignored.
func ExpirationStatus(cert *x509.Certificate, ageCritical time.Time, ageWarning time.Time, ignoreExpired bool) string {
	var expiresText string
	certExpiration := cert.NotAfter

	var lifeRemainingText string
	if remaining, err := LifeRemainingPercentageTruncated(cert); err == nil {
		lifeRemainingText = fmt.Sprintf(" (%d%%)", remaining)
	}

	switch {
	case certExpiration.Before(time.Now()) && ignoreExpired:
		expiresText = fmt.Sprintf(
			"[EXPIRED, IGNORED] %s%s",
			FormattedExpiration(certExpiration),
			lifeRemainingText,
		)
	case certExpiration.Before(time.Now()):
		expiresText = fmt.Sprintf(
			"[EXPIRED] %s%s",
			FormattedExpiration(certExpiration),
			lifeRemainingText,
		)
	case certExpiration.Before(ageCritical):
		expiresText = fmt.Sprintf(
			"[%s] %s%s",
			nagios.StateCRITICALLabel,
			FormattedExpiration(certExpiration),
			lifeRemainingText,
		)
	case certExpiration.Before(ageWarning):
		expiresText = fmt.Sprintf(
			"[%s] %s%s",
			nagios.StateWARNINGLabel,
			FormattedExpiration(certExpiration),
			lifeRemainingText,
		)
	default:
		expiresText = fmt.Sprintf(
			"[%s] %s%s",
			nagios.StateOKLabel,
			FormattedExpiration(certExpiration),
			lifeRemainingText,
		)

	}

	return expiresText
}

// ShouldCertExpirationBeIgnored evaluates a given certificate, its
// certificate chain and the validation options specified and indicates
// whether the certificate should be ignored.
func ShouldCertExpirationBeIgnored(
	cert *x509.Certificate,
	certChain []*x509.Certificate,
	validationOptions CertChainValidationOptions,
) bool {

	if validationOptions.IgnoreValidationResultExpiration {
		return true
	}

	if IsRootCert(cert, certChain) {
		if IsExpiredCert(cert) &&
			validationOptions.IgnoreExpiredRootCertificates {
			return true
		}
	}
	if IsIntermediateCert(cert, certChain) {
		if IsExpiredCert(cert) &&
			validationOptions.IgnoreExpiredIntermediateCertificates {
			return true
		}
	}

	return false
}

// isSelfSigned is a helper function that attempts to validate whether a given
// certificate is self-signed by asserting that its signature can be validated
// with its own public key. Any errors encountered during signature validation
// are assumed to be an indication that a certificate is not self-signed.
func isSelfSigned(cert *x509.Certificate) bool {

	if cert.Issuer.String() == cert.Subject.String() {

		sigVerifyErr := cert.CheckSignature(
			cert.SignatureAlgorithm,
			cert.RawTBSCertificate,
			cert.Signature,
		)

		switch {

		// examine signature verification errors
		case errors.Is(sigVerifyErr, x509.InsecureAlgorithmError(cert.SignatureAlgorithm)):

			// fmt.Println("errors.Is match")

			// Handle MD5 signature verification ourselves since Go considers
			// the MD5 algorithm to be insecure (rightly so).
			if cert.SignatureAlgorithm == x509.MD5WithRSA {

				// fmt.Println("SignatureAlgorithm match")

				// nolint:gosec
				h := md5.New()
				if _, err := h.Write(cert.RawTBSCertificate); err != nil {
					// fmt.Println(
					// 	"isSelfSigned: failed to generate MD5 hash of RawTBSCertificate:",
					// 	err,
					// )
					return false
				}
				hashedBytes := h.Sum(nil)

				if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {

					// fmt.Println("type assertion for rsa.PublicKey successful")

					md5RSASigVerifyErr := rsa.VerifyPKCS1v15(
						pub, crypto.MD5, hashedBytes, cert.Signature,
					)

					switch {

					case md5RSASigVerifyErr != nil:
						// fmt.Println(
						// 	"isSelfSigned: failed to validate MD5WithRSA signature:",
						// 	md5RSASigVerifyErr,
						// )

						return false

					default:
						// fmt.Println("MD5 signature verified")

						return true
					}

				}

			}

			// TODO: Do we need to check this ourselves in Go 1.18?
			// if cert.SignatureAlgorithm == x509.SHA1WithRSA {
			// }

			return false

		// no problems verifying self-signed signature
		case sigVerifyErr == nil:

			return true

		}

	}

	return false
}

// ChainPosition receives a cert and the cert chain that it belongs to and
// returns a string indicating what position or "role" it occupies in the
// certificate chain.
//
// https://en.wikipedia.org/wiki/X.509
// https://tools.ietf.org/html/rfc5280
func ChainPosition(cert *x509.Certificate, certChain []*x509.Certificate) string {

	// We require a valid certificate chain. Fail if not provided.
	if certChain == nil {
		return certChainPositionUnknown
	}

	switch cert.Version {

	// Because v1 and v2 certs lack the more descriptive "intention"
	// fields of v3 certs, we are limited in what checks we can apply. We
	// rely on a combination of self-signed and literal chain position to
	// help determine the purpose of each v1 and v2 certificate.
	case 1, 2:

		switch {
		case isSelfSigned(cert):
			if cert == certChain[0] {
				return certChainPositionLeafSelfSigned
			}

			return certChainPositionRoot

		default:
			if cert == certChain[0] {
				return certChainPositionLeaf
			}

			return certChainPositionIntermediate
		}

	case 3:

		switch {
		case isSelfSigned(cert):

			// FIXME: What pattern to use for self-signed v3 leaf?

			// The cA boolean indicates whether the certified public key may be
			// used to verify certificate signatures.
			if cert.IsCA {
				return certChainPositionRoot
			}

			// The Extended key usage extension indicates one or more purposes
			// for which the certified public key may be used, in addition to
			// or in place of the basic purposes indicated in the key usage
			// extension. In general, this extension will appear only in end
			// entity certificates.
			if cert.ExtKeyUsage != nil {
				return certChainPositionLeafSelfSigned
			}

			// CA certs are intended for cert and CRL signing.
			//
			// In the majority of cases (all?), the cA boolean field will
			// already be set if either of these under `X509v3 Basic
			// Constraints` are specified.
			switch cert.KeyUsage {
			case cert.KeyUsage | x509.KeyUsageCertSign | x509.KeyUsageCRLSign:
				return certChainPositionRoot
			case cert.KeyUsage | x509.KeyUsageCertSign:
				return certChainPositionRoot
			default:
				return certChainPositionLeafSelfSigned
			}

		default:

			// The cA boolean indicates whether the certified public key may be
			// used to verify certificate signatures.
			if cert.IsCA {
				return certChainPositionIntermediate
			}

			// The Extended key usage extension indicates one or more purposes
			// for which the certified public key may be used, in addition to
			// or in place of the basic purposes indicated in the key usage
			// extension. In general, this extension will appear only in end
			// entity certificates.
			if cert.ExtKeyUsage != nil {
				return certChainPositionLeaf
			}

			// CA certs are intended for cert and CRL signing.
			//
			// In the majority (all?) of cases, the cA boolean field will
			// already be set if either of these under `X509v3 Basic
			// Constraints` are specified.
			switch cert.KeyUsage {
			case cert.KeyUsage | x509.KeyUsageCertSign | x509.KeyUsageCRLSign:
				return certChainPositionIntermediate
			case cert.KeyUsage | x509.KeyUsageCertSign:
				return certChainPositionIntermediate
			default:
				return certChainPositionLeaf
			}

		}
	}

	// no known match, so position unknown
	return certChainPositionUnknown

}

// GenerateCertChainReport receives the current certificate chain status
// generates a formatted report suitable for display on the console or
// (potentially) via Microsoft Teams provided suitable conversion is performed
// on the output. If specified, additional details are provided such as
// certificate fingerprint and key IDs.
func GenerateCertChainReport(
	certChain []*x509.Certificate,
	ageCriticalThreshold time.Time,
	ageWarningThreshold time.Time,
	verboseDetails bool,
	validationOptions CertChainValidationOptions,
) string {

	var certsReport string

	certsTotal := len(certChain)

	for idx, certificate := range certChain {

		certPosition := ChainPosition(certificate, certChain)

		expiresText := ExpirationStatus(
			certificate,
			ageCriticalThreshold,
			ageWarningThreshold,
			ShouldCertExpirationBeIgnored(certificate, certChain, validationOptions),
		)

		fingerprints := struct {
			SHA1   string
			SHA256 string
			SHA512 string
		}{
			SHA1:   fmt.Sprintf("%s", sha1.Sum(certificate.Raw)), // nolint:gosec
			SHA256: fmt.Sprintf("%s", sha256.Sum256(certificate.Raw)),
			SHA512: fmt.Sprintf("%s", sha512.Sum512(certificate.Raw)),
		}

		// fingerprints := struct {
		// 	SHA1   []byte
		// 	SHA256 []byte
		// 	SHA512 []byte
		// }{
		// 	SHA1: func() []byte {
		// 		sha1 := sha1.Sum(certificate.Raw) //nolint:gosec
		// 		bx := make([]byte, len(sha1))
		// 		for i := range sha1 {
		// 			bx[i] = sha1[i]
		// 		}
		// 		return bx
		// 	}(),
		// 	SHA256: func() []byte {
		// 		sum := sha256.Sum256(certificate.Raw)
		// 		bx := make([]byte, len(sum))
		// 		for i := range sum {
		// 			bx[i] = sum[i]
		// 		}
		// 		return bx
		// 	}(),
		// 	SHA512: func() []byte {
		// 		sum := sha512.Sum512(certificate.Raw)
		// 		bx := make([]byte, len(sum))
		// 		for i := range sum {
		// 			bx[i] = sum[i]
		// 		}
		// 		return bx
		// 	}(),
		// }

		switch {
		case verboseDetails:
			certsReport += fmt.Sprintf(
				"Certificate %d of %d (%s):"+
					"%s\tName: %s"+
					"%s\tSANs entries: %s"+
					"%s\tKeyID: %v"+
					"%s\tIssuer: %s"+
					"%s\tIssuerKeyID: %v"+
					"%s\tFingerprint (SHA-1): %v"+
					"%s\tFingerprint (SHA-256): %v"+
					"%s\tFingerprint (SHA-512): %v"+
					"%s\tSerial: %v"+
					"%s\tIssued On: %s"+
					"%s\tExpiration: %s"+
					"%s\tStatus: %s%s%s",
				idx+1,
				certsTotal,
				certPosition,
				nagios.CheckOutputEOL,
				certificate.Subject,
				nagios.CheckOutputEOL,
				certificate.DNSNames,
				nagios.CheckOutputEOL,
				textutils.BytesToDelimitedHexStr(certificate.SubjectKeyId, ":"),
				nagios.CheckOutputEOL,
				certificate.Issuer,
				nagios.CheckOutputEOL,
				textutils.BytesToDelimitedHexStr(certificate.AuthorityKeyId, ":"),
				nagios.CheckOutputEOL,
				textutils.BytesToDelimitedHexStr([]byte(fingerprints.SHA1), ":"),
				nagios.CheckOutputEOL,
				textutils.BytesToDelimitedHexStr([]byte(fingerprints.SHA256), ":"),
				nagios.CheckOutputEOL,
				textutils.BytesToDelimitedHexStr([]byte(fingerprints.SHA512), ":"),
				nagios.CheckOutputEOL,
				FormatCertSerialNumber(certificate.SerialNumber),
				nagios.CheckOutputEOL,
				certificate.NotBefore.Format(CertValidityDateLayout),
				nagios.CheckOutputEOL,
				certificate.NotAfter.Format(CertValidityDateLayout),
				nagios.CheckOutputEOL,
				expiresText,
				nagios.CheckOutputEOL,
				nagios.CheckOutputEOL,
			)
		default:
			certsReport += fmt.Sprintf(
				"Certificate %d of %d (%s):"+
					"%s\tName: %s"+
					"%s\tSANs entries: %s"+
					"%s\tIssuer: %s"+
					"%s\tSerial: %v"+
					"%s\tIssued On: %s"+
					"%s\tExpiration: %s"+
					"%s\tStatus: %s%s%s",
				idx+1,
				certsTotal,
				certPosition,
				nagios.CheckOutputEOL,
				certificate.Subject,
				nagios.CheckOutputEOL,
				certificate.DNSNames,
				nagios.CheckOutputEOL,
				certificate.Issuer,
				nagios.CheckOutputEOL,
				FormatCertSerialNumber(certificate.SerialNumber),
				nagios.CheckOutputEOL,
				certificate.NotBefore.Format(CertValidityDateLayout),
				nagios.CheckOutputEOL,
				certificate.NotAfter.Format(CertValidityDateLayout),
				nagios.CheckOutputEOL,
				expiresText,
				nagios.CheckOutputEOL,
				nagios.CheckOutputEOL,
			)
		}
	}

	return strings.TrimSpace(certsReport)

}

// NextToExpire receives a slice of x509 certificates and a boolean flag
// indicating whether already expired certificates should be excluded. If not
// excluded, the first expired certificate is returned, otherwise the first
// certificate out of the pool set to expire next is returned.
//
// If *all* certs are expired, the cert which first expired will be returned
// regardless of the boolean flag provided. If the provided slice of x509
// certificates is empty or nil then nil will be returned.
func NextToExpire(certChain []*x509.Certificate, excludeExpired bool) *x509.Certificate {

	// Guard against index out of range.
	if len(certChain) == 0 {
		return nil
	}

	// Copy method will return the minimum of length of source and destination
	// slice which is zero for this empty slice  (regardless of what initial
	// capacity we allow for)
	// https://www.geeksforgeeks.org/how-to-copy-one-slice-into-another-slice-in-golang/
	//
	// sortedChain := make([]*x509.Certificate, 0, len(certChain))
	// copy(sortedChain, certChain)

	sortedChain := make([]*x509.Certificate, len(certChain))
	copy(sortedChain, certChain)

	// First, go ahead and sort the chain by expiration date.
	sort.Slice(sortedChain, func(i, j int) bool {
		return sortedChain[i].NotAfter.Before(sortedChain[j].NotAfter)
	})

	// Grab the first cert to use as our default return value if not
	// overridden later. This is either first expired certificate (if present)
	// or the next certificate to expire.
	nextToExpire := sortedChain[0]

	if excludeExpired {
		// Attempt to return the first non-expired certificate set to expire
		// next.
		for idx := range sortedChain {
			if !IsExpiredCert(sortedChain[idx]) {
				nextToExpire = sortedChain[idx]
				break
			}
			continue
		}
	}

	// If *all* certs are expired, the cert which first expired will be
	// returned.
	return nextToExpire
}

// HasProblems asserts that no evaluated certificates are expired or expiring
// soon.
func (dcc DiscoveredCertChains) HasProblems(
	certsExpireAgeCritical time.Time,
	certsExpireAgeWarning time.Time) bool {

	for _, chain := range dcc {

		hasExpiredCerts := HasExpiredCert(chain.Certs)
		hasExpiringCerts := HasExpiringCert(
			chain.Certs,
			certsExpireAgeCritical,
			certsExpireAgeWarning,
		)

		if hasExpiredCerts || hasExpiringCerts {
			return true
		}

	}

	return false

}

// NumProblems indicates how many evaluated certificates are expired or
// expiring soon.
//
// TODO: Need to either rename or expand the scope to also include hostname
// verification errors, chain validity, etc.
func (dcc DiscoveredCertChains) NumProblems(
	certsExpireAgeCritical time.Time,
	certsExpireAgeWarning time.Time) int {

	var problems int
	for _, chain := range dcc {

		hasExpiredCerts := HasExpiredCert(chain.Certs)
		hasExpiringCerts := HasExpiringCert(
			chain.Certs,
			certsExpireAgeCritical,
			certsExpireAgeWarning,
		)

		if hasExpiredCerts || hasExpiringCerts {
			problems++
		}

	}

	return problems

}
