// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package certs

import (
	"bytes"
	"crypto"

	"crypto/ecdsa"
	"crypto/md5" //nolint:gosec // used for MD5WithRSA signature verification
	"crypto/sha256"

	"crypto/sha1" //nolint:gosec // used for SHA1 fingerprints and signature verification
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

	// ErrUnsupportedFileFormat indicates that parsing attempts against a
	// given file have failed because the file is in an unsupported format.
	ErrUnsupportedFileFormat = errors.New("unsupported file format")

	// ErrEmptyCertificateFile indicates that decoding/parsing attempts have
	// failed due to an empty input file.
	ErrEmptyCertificateFile = errors.New("potentially empty certificate file")

	// ErrPEMParseFailureMalformedCertificate indicates that PEM decoding
	// attempts have failed due to the assumption that the given input
	// certificate data is malformed.
	ErrPEMParseFailureMalformedCertificate = errors.New("potentially malformed certificate")

	// ErrPEMParseFailureEmptyCertificateBlock indicates that PEM decoding
	// attempts have failed due to what appears to be an empty PEM certificate
	// block in the given input.
	//
	// For example:
	//
	// -----BEGIN CERTIFICATE-----
	// -----END CERTIFICATE-----
	//
	//
	// See also:
	//
	//  - https://github.com/smallstep/certinfo/pull/38
	ErrPEMParseFailureEmptyCertificateBlock = errors.New("potentially empty certificate block")

	// ErrSignatureVerificationFailed indicates that a signature verification
	// attempt between an issued certificate and an issuer certificate was
	// unsuccessful.
	ErrSignatureVerificationFailed = errors.New("signature verification failed")

	// ErrIncompleteCertificateChain indicates that a certificate chain is
	// missing one or more certificates (e.g., only leaf cert is present).
	ErrIncompleteCertificateChain = errors.New("certificate chain incomplete")
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

	// IgnoreExpiringIntermediateCertificates tracks whether a request was
	// made to ignore validation check results for certificate expiration
	// against intermediate certificates in a certificate chain which are
	// expiring.
	IgnoreExpiringIntermediateCertificates bool

	// IgnoreExpiringRootCertificates tracks whether a request was made to
	// ignore validation check results for certificate expiration against root
	// certificates in a certificate chain which are expiring.
	IgnoreExpiringRootCertificates bool

	// IgnoreExpiredIntermediateCertificates tracks whether a request was made
	// to ignore validation check results for certificate expiration against
	// intermediate certificates in a certificate chain which have expired.
	IgnoreExpiredIntermediateCertificates bool

	// IgnoreExpiredRootCertificates tracks whether a request was made to
	// ignore validation check results for certificate expiration against root
	// certificates in a certificate chain which have expired.
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

// PEM block type values (from preamble).
//
// See also:
//
//   - https://pkg.go.dev/encoding/pem#Block
//   - https://8gwifi.org/PemParserFunctions.jsp
//   - https://stackoverflow.com/questions/5355046/where-is-the-pem-file-format-specified
//   - https://github.com/openssl/openssl/blob/4f899849ceec7cd8e45da9aa1802df782cf80202/include/openssl/pem.h#L35
//
// #nosec G101 -- Ignore false positive matches
const (
	PEMBlockTypeCRLBegin           = "-----BEGIN X509 CRL-----"
	PEMBlockTypeCRLEnd             = "-----END X509 CRL-----"
	PEMBlockTypeCRTBegin           = "-----BEGIN CERTIFICATE-----"
	PEMBlockTypeCRTEnd             = "-----END CERTIFICATE-----"
	PEMBlockTypeCSRBegin           = "-----BEGIN CERTIFICATE REQUEST-----"
	PEMBlockTypeCSREnd             = "-----END CERTIFICATE REQUEST-----"
	PEMBlockTypeNewCSRBegin        = "-----BEGIN NEW CERTIFICATE REQUEST-----"
	PEMBlockTypeNewCSREnd          = "-----END NEW CERTIFICATE REQUEST-----"
	PEMBlockTypePublicKeyBegin     = "-----BEGIN RSA PUBLIC KEY-----"
	PEMBlockTypePublicKeyEnd       = "-----END RSA PUBLIC KEY-----"
	PEMBlockTypeRSAPrivateKeyBegin = "-----BEGIN RSA PRIVATE KEY-----"
	PEMBlockTypeRSAPrivateKeyEnd   = "-----END RSA PRIVATE KEY-----"
	PEMBlockTypeDSAPrivateKeyBegin = "-----BEGIN DSA PRIVATE KEY-----"
	PEMBlockTypeDSAPrivateKeyEnd   = "-----END DSA PRIVATE KEY-----"
	PEMBlockTypeECPrivateKeyBegin  = "-----BEGIN EC PRIVATE KEY-----"
	PEMBlockTypeECPrivateKeyEnd    = "-----END EC PRIVATE KEY-----"
	PEMBlockTypePrivateKeyBegin    = "-----BEGIN PRIVATE KEY-----"
	PEMBlockTypePrivateKeyEnd      = "-----END PRIVATE KEY-----"
	PEMBlockTypePKCS7Begin         = "-----BEGIN PKCS7-----"
	PEMBlockTypePKCS7End           = "-----END PKCS7-----"
	PEMBlockTypePGPPrivateKeyBegin = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
	PEMBlockTypePGPPrivateKeyEnd   = "-----END PGP PRIVATE KEY BLOCK-----"
	PEMBlockTypePGPPublicKeyBegin  = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
	PEMBlockTypePGPPublicKeyEnd    = "-----END PGP PUBLIC KEY BLOCK-----"
)

// Human readable values for common PEM block types.
const (
	PEMBlockTypeCRL           = "certificate revocation list"
	PEMBlockTypeCRT           = "PEM encoded certificate"
	PEMBlockTypeCSR           = "certificate signing request"
	PEMBlockTypeNewCSR        = "certificate signing request"
	PEMBlockTypePublicKey     = "RSA public key"
	PEMBlockTypeRSAPrivateKey = "RSA private key"
	PEMBlockTypeDSAPrivateKey = "DSA private key"
	PEMBlockTypeECPrivateKey  = "EC private key"
	PEMBlockTypePrivateKey    = "private key"
	PEMBlockTypePKCS7         = "PKCS7"
	PEMBlockTypePGPPrivateKey = "PGP private key"
	PEMBlockTypePGPPublicKey  = "PGP public key"
)

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

// chainPositionV1V2Cert relies on a combination of self-signed and literal
// chain position to help determine the purpose of each v1 and v2 certificate.
// This is because those certificate versions lack the more descriptive
// "intention" fields (i.e., "extensions") of v3 certificates.
func chainPositionV1V2Cert(cert *x509.Certificate, certChain []*x509.Certificate) string {
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
}

// chainPosV3CertKeyUsage evaluates the KeyUsage field for a certificate to
// determine the chain position for a certificate; the KeyUsage field
// identifies the set of actions that are valid for a given key.
func chainPosV3CertKeyUsage(cert *x509.Certificate) string {
	switch {
	case isSelfSigned(cert):
		switch cert.KeyUsage {
		case cert.KeyUsage | x509.KeyUsageCertSign | x509.KeyUsageCRLSign:
			return certChainPositionRoot
		case cert.KeyUsage | x509.KeyUsageCertSign:
			return certChainPositionRoot
		default:
			return certChainPositionLeafSelfSigned
		}
	default:

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

// chainPositionV3Cert identifies the certificate chain position for a given
// v3 cert.
func chainPositionV3Cert(cert *x509.Certificate) string {
	selfSigned := isSelfSigned(cert)

	// The CA boolean indicates whether the certified public key may be used
	// to verify certificate signatures.
	switch {
	case selfSigned && cert.IsCA:
		return certChainPositionRoot
	case cert.IsCA:
		return certChainPositionIntermediate
	}

	// The Extended key usage extension indicates one or more purposes for
	// which the certified public key may be used, in addition to or in place
	// of the basic purposes indicated in the key usage extension. In general,
	// this extension will appear only in end entity certificates.
	switch {
	case selfSigned && cert.ExtKeyUsage != nil:
		return certChainPositionLeafSelfSigned
	case cert.ExtKeyUsage != nil:
		return certChainPositionLeaf
	}

	return chainPosV3CertKeyUsage(cert)
}

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
// from a specified certificate file. An error is returned if the file format
// cannot be decoded and parsed. Any trailing non-parsable data is returned
// for potential further evaluation.
func GetCertsFromFile(filename string) ([]*x509.Certificate, []byte, error) {
	var certChain []*x509.Certificate

	// Anything from the specified file that couldn't be converted to a
	// certificate chain. While likely not of high value by itself, failure to
	// parse a certificate file indicates a likely source of trouble.
	var parseAttemptLeftovers []byte

	// Read in the entire certificate file after first attempting to sanitize
	// the input file variable contents.
	certFileData, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, nil, err
	}

	// Bail if nothing was found.
	if len(certFileData) == 0 {
		return nil, nil, fmt.Errorf(
			"failed to decode %s as certificate file: %w",
			filename,
			ErrEmptyCertificateFile,
		)
	}

	// Do *NOT* normalize newlines on this content, strip blank lines only. If
	// applied directly to DER encoded binary file content it will break
	// parsing.
	certFileData = textutils.StripBlankLines(certFileData)

	unsupportedCertFormat := func(actualFormat string) ([]*x509.Certificate, []byte, error) {
		return nil, nil, fmt.Errorf(
			"failed to decode %s (%s format) as certificate file: %w",
			filename,
			actualFormat,
			ErrUnsupportedFileFormat,
		)
	}

	// Attempt to determine cert file type based on initial file contents. As
	// of GH-862 only two input file formats are supported:
	//
	//   - PEM (text) encoded ASN.1 DER
	//   - binary ASN.1 DER
	//
	// We attempt to match other known PEM encoded file formats and provide a
	// useful error message to help sysadmins with troubleshooting.
	switch {
	case bytes.Contains(certFileData, []byte(PEMBlockTypeCRTBegin)):
		// fmt.Println("File detected as PEM formatted")

		// Attempt to parse as PEM encoded DER certificate file.
		certChain, parseAttemptLeftovers, err = ParsePEMCertificates(certFileData)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"failed to decode %s as PEM formatted certificate file: %w",
				filename,
				err,
			)
		}

	case bytes.Contains(certFileData, []byte(PEMBlockTypeCRLBegin)):
		return unsupportedCertFormat(PEMBlockTypeCRL)

	case bytes.Contains(certFileData, []byte(PEMBlockTypeCSRBegin)):
		return unsupportedCertFormat(PEMBlockTypeCSR)

	case bytes.Contains(certFileData, []byte(PEMBlockTypeNewCSRBegin)):
		return unsupportedCertFormat(PEMBlockTypeNewCSR)

	case bytes.Contains(certFileData, []byte(PEMBlockTypePublicKeyBegin)):
		return unsupportedCertFormat(PEMBlockTypePublicKey)

	case bytes.Contains(certFileData, []byte(PEMBlockTypeRSAPrivateKeyBegin)):
		return unsupportedCertFormat(PEMBlockTypeRSAPrivateKey)

	case bytes.Contains(certFileData, []byte(PEMBlockTypeDSAPrivateKeyBegin)):
		return unsupportedCertFormat(PEMBlockTypeDSAPrivateKey)

	case bytes.Contains(certFileData, []byte(PEMBlockTypeECPrivateKeyBegin)):
		return unsupportedCertFormat(PEMBlockTypeECPrivateKey)

	case bytes.Contains(certFileData, []byte(PEMBlockTypePrivateKeyBegin)):
		return unsupportedCertFormat(PEMBlockTypePrivateKey)

	case bytes.Contains(certFileData, []byte(PEMBlockTypePKCS7Begin)):
		return unsupportedCertFormat(PEMBlockTypePKCS7)

	case bytes.Contains(certFileData, []byte(PEMBlockTypePGPPrivateKeyBegin)):
		return unsupportedCertFormat(PEMBlockTypePGPPrivateKey)

	case bytes.Contains(certFileData, []byte(PEMBlockTypePGPPublicKeyBegin)):
		return unsupportedCertFormat(PEMBlockTypePGPPublicKey)

	default:
		// Parse as ASN.1 (binary) DER data.
		certChain, err = x509.ParseCertificates(certFileData)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"failed to decode %s as ASN.1 (binary) DER formatted certificate file: %w",
				filename,
				err,
			)
		}
	}

	return certChain, parseAttemptLeftovers, err

}

// GetCertsFromPEMFile is a helper function for retrieving a certificate chain
// from a specified PEM formatted certificate file. An error is returned if
// the file cannot be decoded and parsed (e.g., empty file, not PEM
// formatted). Any leading non-PEM formatted data is skipped while any
// trailing non-PEM formatted data is returned for potential further
// evaluation.
func GetCertsFromPEMFile(filename string) ([]*x509.Certificate, []byte, error) {
	// Read in the entire certificate file after first attempting to sanitize
	// the input file variable contents.
	certFileData, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, nil, err
	}

	certFileData = textutils.StripBlankLines(certFileData)

	// Attempt to parse as PEM encoded DER certificate file.
	certChain, parseAttemptLeftovers, err := ParsePEMCertificates(certFileData)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"failed to decode %s as PEM formatted certificate file: %w",
			filename,
			err,
		)
	}

	return certChain, parseAttemptLeftovers, nil
}

// ParsePEMCertificates retrieves the given byte slice as a PEM formatted
// certificate chain. Any leading non-PEM formatted data is skipped while any
// trailing non-PEM formatted data is returned for potential further
// evaluation. An error is returned if the given data cannot be decoded and
// parsed.
func ParsePEMCertificates(pemData []byte) ([]*x509.Certificate, []byte, error) {
	var certChain []*x509.Certificate

	// It's safe to normalize EOLs in PEM encoded data, but *not* in DER
	// data itself.
	pemData = textutils.NormalizeNewlines(pemData)

	// Grab the first PEM formatted block.
	block, parseAttemptLeftovers := pem.Decode(pemData)

	switch {
	case block == nil:
		return nil, nil, ErrPEMParseFailureMalformedCertificate
	case len(block.Bytes) == 0:
		return nil, nil, ErrPEMParseFailureEmptyCertificateBlock
	}

	// If there is only one certificate (e.g., "server" or "leaf" certificate)
	// we'll only get one block from the last pem.Decode() call. However, if
	// the file contains a certificate chain or "bundle" we will need to call
	// pem.Decode() multiple times, so we setup a loop to handle that.
	for {

		if block != nil {

			// fmt.Println("Type of block:", block.Type)
			// fmt.Println("size of file content:", len(pemData))
			// fmt.Println("size of parseAttemptLeftovers:", len(parseAttemptLeftovers))

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, err
			}

			// we got a cert. Let's add it to our list
			certChain = append(certChain, cert)

			if len(parseAttemptLeftovers) > 0 {
				block, parseAttemptLeftovers = pem.Decode(parseAttemptLeftovers)

				// if we were able to decode the rest of the data, then
				// iterate again so we can parse it
				if block != nil {
					continue
				}
			}

			break
		}

		// we're done attempting to decode the cert file; we have found data
		// that fails to decode properly
		if len(parseAttemptLeftovers) > 0 {
			break
		}
	}

	return certChain, parseAttemptLeftovers, nil
}

// WriteCertToPEMFile writes a single certificate to a file in PEM format.
func WriteCertToPEMFile(file *os.File, cert *x509.Certificate) error {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	err := pem.Encode(file, pemBlock)
	if err != nil {
		return err
	}

	return nil
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

// HasLeafCert receives a slice of x509 certificates and indicates whether
// any of the certificates in the chain are a leaf certificate.
func HasLeafCert(certChain []*x509.Certificate) bool {
	for _, cert := range certChain {
		if IsLeafCert(cert, certChain) {
			return true
		}
	}

	return false
}

// HasIntermediateCert receives a slice of x509 certificates and indicates
// whether any of the certificates in the chain are an intermediate
// certificate.
func HasIntermediateCert(certChain []*x509.Certificate) bool {
	for _, cert := range certChain {
		if IsIntermediateCert(cert, certChain) {
			return true
		}
	}

	return false
}

// HasRootCert receives a slice of x509 certificates and indicates whether any
// of the certificates in the chain are a root certificate.
func HasRootCert(certChain []*x509.Certificate) bool {
	for _, cert := range certChain {
		if IsRootCert(cert, certChain) {
			return true
		}
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

// verifySignatureMD5WithRSA is a helper function that attempts to validate a
// MD5WithRSA signature for issuedCert using the public key from issuerCert.
//
// An error is returned if issuedCert signature algorithm is not MD5WithRSA or
// issuerCert is determined to not have signed issuedCert.
func verifySignatureMD5WithRSA(issuedCert *x509.Certificate, issuerCert *x509.Certificate) error {
	if issuedCert.SignatureAlgorithm != x509.MD5WithRSA {
		return fmt.Errorf(
			"issued certificate signature algorithm not MD5WithRSA: %w",
			ErrSignatureVerificationFailed,
		)
	}

	h := md5.New() //nolint:gosec // not using for cryptographic purposes

	// If MD5 hash generation of the raw ASN.1 DER content fails we'll know
	// that we're not working with a MD5 signature.
	if _, err := h.Write(issuedCert.RawTBSCertificate); err != nil {
		return fmt.Errorf(
			"%w: %w",
			ErrSignatureVerificationFailed,
			err,
		)
	}

	hashedBytes := h.Sum(nil)

	pub, validRSAPublicKey := issuerCert.PublicKey.(*rsa.PublicKey)

	if !validRSAPublicKey {
		return fmt.Errorf(
			"issuer certificate public key not in RSA format: %w",
			ErrSignatureVerificationFailed,
		)
	}

	md5RSASigVerifyErr := rsa.VerifyPKCS1v15(
		pub, crypto.MD5, hashedBytes, issuedCert.Signature,
	)

	if md5RSASigVerifyErr != nil {
		return fmt.Errorf(
			"%w: %w",
			md5RSASigVerifyErr,
			ErrSignatureVerificationFailed,
		)
	}

	// Signature verified.
	return nil
}

// verifySignatureSHA1WithRSA is a helper function that attempts to validate a
// SHA1WithRSA signature for issuedCert using the public key from issuerCert.
//
// An error is returned if issuedCert signature algorithm is not SHA1WithRSA
// or issuerCert is determined to not have signed issuedCert.
func verifySignatureSHA1WithRSA(issuedCert *x509.Certificate, issuerCert *x509.Certificate) error {
	if issuedCert.SignatureAlgorithm != x509.SHA1WithRSA {
		return fmt.Errorf(
			"issued certificate signature algorithm not SHA1WithRSA: %w",
			ErrSignatureVerificationFailed,
		)
	}

	h := sha1.New() //nolint:gosec // not using for cryptographic purposes

	// If SHA1 hash generation of the raw ASN.1 DER content fails we'll know
	// that we're not working with a SHA1 signature.
	if _, err := h.Write(issuedCert.RawTBSCertificate); err != nil {
		return fmt.Errorf(
			"%w: %w",
			ErrSignatureVerificationFailed,
			err,
		)
	}

	hashedBytes := h.Sum(nil)

	pub, validRSAPublicKey := issuerCert.PublicKey.(*rsa.PublicKey)

	if !validRSAPublicKey {
		return fmt.Errorf(
			"issuer certificate public key not in RSA format: %w",
			ErrSignatureVerificationFailed,
		)
	}

	sha1RSASigVerifyErr := rsa.VerifyPKCS1v15(
		pub, crypto.SHA1, hashedBytes, issuedCert.Signature,
	)

	if sha1RSASigVerifyErr != nil {
		return fmt.Errorf(
			"%w: %w",
			sha1RSASigVerifyErr,
			ErrSignatureVerificationFailed,
		)
	}

	// Signature verified.
	return nil
}

// verifySignatureECDSAWithSHA1 is a helper function that attempts to validate
// a ECDSAWithSHA1 signature for issuedCert using the public key from
// issuerCert.
//
// An error is returned if issuedCert signature algorithm is not ECDSAWithSHA1
// or issuerCert is determined to not have signed issuedCert.
func verifySignatureECDSAWithSHA1(issuedCert *x509.Certificate, issuerCert *x509.Certificate) error {
	if issuedCert.SignatureAlgorithm != x509.ECDSAWithSHA1 {
		return fmt.Errorf(
			"issued certificate signature algorithm not ECDSAWithSHA1: %w",
			ErrSignatureVerificationFailed,
		)
	}

	h := sha1.New() //nolint:gosec // not using for cryptographic purposes

	// If SHA1 hash generation of the raw ASN.1 DER content fails we'll know
	// that we're not working with a SHA1 signature.
	if _, err := h.Write(issuedCert.RawTBSCertificate); err != nil {
		return fmt.Errorf(
			"%w: %w",
			ErrSignatureVerificationFailed,
			err,
		)
	}

	hashedBytes := h.Sum(nil)

	pub, validECDSAPublicKey := issuerCert.PublicKey.(*ecdsa.PublicKey)

	if !validECDSAPublicKey {
		return fmt.Errorf(
			"issuer certificate public key not in ECDSA format: %w",
			ErrSignatureVerificationFailed,
		)
	}

	signatureValid := ecdsa.VerifyASN1(
		pub, hashedBytes, issuedCert.Signature,
	)

	if !signatureValid {
		return fmt.Errorf(
			"ECDSA signature not valid: %w",
			ErrSignatureVerificationFailed,
		)
	}

	// Signature verified.
	return nil
}

// verifySignature is used to verify that the signature on issuedCert is a
// valid signature from issuerCert.
//
// NOTE: This function attempts to perform signature verification for
// signature algorithms which current versions of Go reject with a
// x509.InsecureAlgorithmError error value.
//
// This explicit evaluation is not done for cryptographic/security purposes,
// but rather for best-effort identification; because evaluated certificate
// chains are managed by sysadmins and already under their control the outcome
// of this logic grants no more access than was already present.
func verifySignature(issuedCert *x509.Certificate, issuerCert *x509.Certificate) error {
	if issuedCert.Issuer.String() != issuerCert.Subject.String() {
		return fmt.Errorf(
			"issuer and subject X.509 distinguished name mismatch: %w",
			ErrSignatureVerificationFailed,
		)
	}

	// Regarding the specific order of issuer/issued certs in signature
	// verification process:
	//
	// https://github.com/google/certificate-transparency-go/blob/3445599468fa7fe152d9c809ba8f2527d72768b8/x509/x509.go#L1004-L1030
	//
	// parent.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
	sigVerifyErr := issuerCert.CheckSignature(
		issuedCert.SignatureAlgorithm,
		issuedCert.RawTBSCertificate,
		issuedCert.Signature,
	)

	switch {
	// Handle verification of signature algorithms no longer supported by
	// current Go releases (declared insecure).
	case errors.Is(sigVerifyErr, x509.InsecureAlgorithmError(issuedCert.SignatureAlgorithm)):
		switch {
		case issuedCert.SignatureAlgorithm == x509.MD5WithRSA:
			return verifySignatureMD5WithRSA(issuedCert, issuerCert)

		case issuedCert.SignatureAlgorithm == x509.SHA1WithRSA:
			// https://github.com/golang/go/issues/41682
			return verifySignatureSHA1WithRSA(issuedCert, issuerCert)

		case issuedCert.SignatureAlgorithm == x509.ECDSAWithSHA1:
			// https://github.com/golang/go/issues/41682
			return verifySignatureECDSAWithSHA1(issuedCert, issuerCert)

		default:
			// Go has declared an algorithm as insecure that we're not
			// aware of.
			return fmt.Errorf(
				"unsupported signature algorithm %s (please submit bug report): %w: %w",
				issuedCert.SignatureAlgorithm,
				sigVerifyErr,
				ErrSignatureVerificationFailed,
			)
		}

	case sigVerifyErr != nil:
		// Some other signature verification error aside from
		// InsecureAlgorithmError.
		return fmt.Errorf(
			"%w: %w",
			sigVerifyErr,
			ErrSignatureVerificationFailed,
		)

	default:
		return nil
	}
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

// NonRootCerts receives a slice of x509 certificates and returns a collection
// of certificates present in the chain which are not root certificates.
func NonRootCerts(certChain []*x509.Certificate) []*x509.Certificate {
	numPresent := NumLeafCerts(certChain) + NumIntermediateCerts(certChain)
	nonRootCerts := make([]*x509.Certificate, 0, numPresent)

	for _, cert := range certChain {
		chainPos := ChainPosition(cert, certChain)
		if chainPos != certChainPositionRoot {
			nonRootCerts = append(nonRootCerts, cert)
		}
	}

	return nonRootCerts
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

// ExpiresInDaysPrecise evaluates the given certificate and returns the number
// of days until the certificate expires as a floating point number. This
// number is rounded down.
//
// If already expired, a negative number is returned indicating how many days
// the certificate is past expiration.
//
// An error is returned if the pointer to the given certificate is nil.
func ExpiresInDaysPrecise(cert *x509.Certificate) (float64, error) {
	if cert == nil {
		return 0, fmt.Errorf(
			"func ExpiresInDaysPrecise: unable to determine expiration: %w",
			ErrMissingValue,
		)
	}

	timeRemaining := time.Until(cert.NotAfter).Hours()

	// Round down to the nearest two decimal places.
	daysRemaining := timeRemaining / 24
	daysRemaining = math.Floor(daysRemaining*100) / 100

	return daysRemaining, nil
}

// ExpiresInHours evaluates the given certificate and returns the number of
// hours until the certificate expires as a floating point number.
//
// An error is returned if the pointer to the given certificate is nil.
func ExpiresInHours(cert *x509.Certificate) (float64, error) {
	if cert == nil {
		return 0, fmt.Errorf(
			"func ExpiresInHours: unable to determine expiration: %w",
			ErrMissingValue,
		)
	}

	return time.Until(cert.NotAfter).Hours(), nil
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
// expire. This value is intentionally truncated (e.g., 1.5 days becomes 1
// day) since the result may be used to determine when a sysadmin is notified
// of an impending expiration (sooner is better).
func MaxLifespanInDays(cert *x509.Certificate) (int, error) {
	if cert == nil {
		return 0, fmt.Errorf(
			"func MaxLifespanInDays: unable to determine expiration: %w",
			ErrMissingValue,
		)
	}

	maxCertLifespan := cert.NotAfter.Sub(cert.NotBefore)

	// While tempting, if we round up we will report more days for a
	// certificate, which could give a false sense of safety; we take the
	// stance that it is better to report fewer days for a certificate than
	// more.
	//
	// daysMaxLifespan := int(math.RoundToEven(maxCertLifespan.Hours() / 24))
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

// HasWeakSignatureAlgorithm evaluates the given certificate (within the
// context of a given certificate chain) and indicates whether a known weak
// signature algorithm was found.
//
// Root certificates evaluate to false (by default) as TLS clients trust them
// by their identity instead of the signature of their hash.
//
// If explicitly requested root certificates are also evaluated.
//
// - https://security.googleblog.com/2014/09/gradually-sunsetting-sha-1.html
// - https://security.googleblog.com/2015/12/an-update-on-sha-1-certificates-in.html
// - https://superuser.com/questions/1122069/why-are-root-cas-with-sha1-signatures-not-a-risk
// - https://developer.mozilla.org/en-US/docs/Web/Security/Weak_Signature_Algorithm
// - https://www.tenable.com/plugins/nessus/35291
// - https://docs.ostorlab.co/kb/WEAK_HASHING_ALGO/index.html
func HasWeakSignatureAlgorithm(cert *x509.Certificate, certChain []*x509.Certificate, evalRoot bool) bool {
	chainPos := ChainPosition(cert, certChain)

	if chainPos == certChainPositionRoot && !evalRoot {
		return false
	}

	switch {
	case cert.SignatureAlgorithm == x509.MD2WithRSA:
		return true

	case cert.SignatureAlgorithm == x509.MD5WithRSA:
		return true

	case cert.SignatureAlgorithm == x509.SHA1WithRSA:
		return true

	case cert.SignatureAlgorithm == x509.DSAWithSHA1:
		return true

	case cert.SignatureAlgorithm == x509.ECDSAWithSHA1:
		return true

	default:
		return false
	}
}

// HasCertWithWeakSignatureAlgorithm evaluates the given certificate chain and
// indicates whether certificate with a known weak signature algorithm was
// found.
//
// Root certificates evaluate to false (by default) as TLS clients trust them
// by their identity instead of the signature of their hash.
//
// If explicitly requested root certificates are also evaluated.
func HasCertWithWeakSignatureAlgorithm(certChain []*x509.Certificate, evalRoot bool) bool {
	for _, cert := range certChain {
		if HasWeakSignatureAlgorithm(cert, certChain, evalRoot) {
			return true
		}
	}

	return false
}

// WeakSignatureAlgorithmStatus returns a human-readable string indicating the
// signature algorithm used for the certificate and whether it is known to be
// cryptographically weak.
//
// Signature algorithms are ignored for root certificates as TLS clients trust
// them by their identity instead of the signature of their hash.
func WeakSignatureAlgorithmStatus(cert *x509.Certificate, certChain []*x509.Certificate) string {
	chainPos := ChainPosition(cert, certChain)

	switch {
	case HasWeakSignatureAlgorithm(cert, certChain, true):
		if chainPos == certChainPositionRoot {
			return "[WEAK, IGNORED] " + cert.SignatureAlgorithm.String()
		}

		return "[WEAK] " + cert.SignatureAlgorithm.String()

	default:
		if chainPos == certChainPositionRoot {
			return "[IGNORED] " + cert.SignatureAlgorithm.String()
		}

		return "[OK] " + cert.SignatureAlgorithm.String()
	}
}

// ExpirationStatus receives a certificate and the expiration threshold values
// for CRITICAL and WARNING states and returns a human-readable string
// indicating the overall status at a glance. If requested, an expiring or
// expired certificate is marked as ignored.
func ExpirationStatus(cert *x509.Certificate, ageCritical time.Time, ageWarning time.Time, ignoreExpiration bool) string {
	var expiresText string
	certExpiration := cert.NotAfter

	var lifeRemainingText string
	if remaining, err := LifeRemainingPercentageTruncated(cert); err == nil {
		lifeRemainingText = fmt.Sprintf(" (%d%%)", remaining)
	}

	switch {
	case certExpiration.Before(time.Now()) && ignoreExpiration:
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
	case certExpiration.Before(ageCritical) && ignoreExpiration:
		expiresText = fmt.Sprintf(
			"[EXPIRING, IGNORED] %s%s",
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
	case certExpiration.Before(ageWarning) && ignoreExpiration:
		expiresText = fmt.Sprintf(
			"[EXPIRING, IGNORED] %s%s",
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
	ageCriticalThreshold time.Time,
	ageWarningThreshold time.Time,
) bool {

	if validationOptions.IgnoreValidationResultExpiration {
		return true
	}

	if IsRootCert(cert, certChain) {
		if IsExpiredCert(cert) &&
			validationOptions.IgnoreExpiredRootCertificates {
			return true
		}

		if IsExpiringCert(cert, ageCriticalThreshold, ageWarningThreshold) &&
			validationOptions.IgnoreExpiringRootCertificates {
			return true
		}
	}
	if IsIntermediateCert(cert, certChain) {
		if IsExpiredCert(cert) &&
			validationOptions.IgnoreExpiredIntermediateCertificates {
			return true
		}

		if IsExpiringCert(cert, ageCriticalThreshold, ageWarningThreshold) &&
			validationOptions.IgnoreExpiringIntermediateCertificates {
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
	if cert.Issuer.String() != cert.Subject.String() {
		return false
	}

	sigVerifyErr := verifySignature(cert, cert)

	switch {
	case sigVerifyErr != nil:
		// Some other signature verification error, which we'll interpret as a
		// failure due to the certificate not being self-signed.
		return false

	default:
		// No problems verifying self-signed signature; conclusively
		// self-signed.
		return true
	}
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
	case 1, 2:
		return chainPositionV1V2Cert(cert, certChain)

	case 3:
		return chainPositionV3Cert(cert)
	}

	// no known match, so position unknown
	return certChainPositionUnknown
}

// SANsEntriesLine provides a formatted list of SANs entries for a given
// certificate if present, "none" if none are available or if requested a
// brief message indicating that they have been explicitly omitted.
func SANsEntriesLine(cert *x509.Certificate, omitSANsEntries bool) string {
	switch {
	case omitSANsEntries && len(cert.DNSNames) > 0:
		return fmt.Sprintf(
			"SANs entries (%d): Omitted by request",
			len(cert.DNSNames),
		)

	case len(cert.DNSNames) > 0:
		return fmt.Sprintf(
			"SANs entries (%d): %s",
			len(cert.DNSNames),
			cert.DNSNames,
		)

	default:
		return "SANs entries: None"
	}
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
	omitSANsEntries bool,
) string {

	var certsReport string

	certsTotal := len(certChain)

	for idx, certificate := range certChain {

		certPosition := ChainPosition(certificate, certChain)

		expiresText := ExpirationStatus(
			certificate,
			ageCriticalThreshold,
			ageWarningThreshold,
			ShouldCertExpirationBeIgnored(
				certificate,
				certChain,
				validationOptions,
				ageCriticalThreshold,
				ageWarningThreshold,
			),
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
					"%s\t%s"+
					"%s\tKeyID: %v"+
					"%s\tIssuer: %s"+
					"%s\tIssuerKeyID: %v"+
					"%s\tFingerprint (SHA-1): %v"+
					"%s\tFingerprint (SHA-256): %v"+
					"%s\tFingerprint (SHA-512): %v"+
					"%s\tSerial: %v"+
					"%s\tIssued On: %s"+
					"%s\tExpiration: %s"+
					"%s\tSignature Algorithm: %s"+
					"%s\tStatus: %s%s%s",
				idx+1,
				certsTotal,
				certPosition,
				nagios.CheckOutputEOL,
				certificate.Subject,
				nagios.CheckOutputEOL,
				SANsEntriesLine(certificate, omitSANsEntries),
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
				WeakSignatureAlgorithmStatus(certificate, certChain),
				nagios.CheckOutputEOL,
				expiresText,
				nagios.CheckOutputEOL,
				nagios.CheckOutputEOL,
			)
		default:
			certsReport += fmt.Sprintf(
				"Certificate %d of %d (%s):"+
					"%s\tName: %s"+
					"%s\t%s"+
					"%s\tIssuer: %s"+
					"%s\tSerial: %v"+
					"%s\tIssued On: %s"+
					"%s\tExpiration: %s"+
					"%s\tSignature Algorithm: %s"+
					"%s\tStatus: %s%s%s",
				idx+1,
				certsTotal,
				certPosition,
				nagios.CheckOutputEOL,
				certificate.Subject,
				nagios.CheckOutputEOL,
				SANsEntriesLine(certificate, omitSANsEntries),
				nagios.CheckOutputEOL,
				certificate.Issuer,
				nagios.CheckOutputEOL,
				FormatCertSerialNumber(certificate.SerialNumber),
				nagios.CheckOutputEOL,
				certificate.NotBefore.Format(CertValidityDateLayout),
				nagios.CheckOutputEOL,
				certificate.NotAfter.Format(CertValidityDateLayout),
				nagios.CheckOutputEOL,
				WeakSignatureAlgorithmStatus(certificate, certChain),
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
