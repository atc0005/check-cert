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

	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/atc0005/check-cert/internal/textutils"
	"github.com/atc0005/go-nagios"
)

// DiscoveredCertChain is a poorly named type that represents the certificate
// chain found on a specific host along with that hosts IP/Name and port.
type DiscoveredCertChain struct {
	Host  string
	Port  int
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

// CertCheckOneLineSummaryTmpl is a shared template string used for emitting
// one-line service check status output for certificate chains whose
// certificates have not expired yet.
const CertCheckOneLineSummaryTmpl string = "%s: %s cert %q expires next with %s (until %s) %s"

// CertCheckOneLineSummaryExpiredTmpl is a shared template string used for
// emitting one-line service check status output for certificate chains with
// expired certificates.
const CertCheckOneLineSummaryExpiredTmpl string = "%s: %s cert %q expired %s (on %s) %s"

// ChainStatus provides a quick status overview of the certificates in a
// provided certificate chain.
type ChainStatus struct {

	// HasExpiredCerts indicates whether the certificate chain has any
	// expired certificates.
	HasExpiredCerts bool

	// HasExpiringCerts indicates whether the certificate chain has any
	// certificates set to expire before the WARNING or CRITICAL age
	// thresholds.
	HasExpiringCerts bool

	// ExpiredCertsCount is the number of expired certificates in the chain.
	ExpiredCertsCount int

	// ExpiringCertsCount is the number of certificates expiring before one of
	// the WARNING or CRITICAL age thresholds.
	ExpiringCertsCount int

	// ValidCertsCount is the number of certificates not yet expired or
	// expiring
	ValidCertsCount int

	// TotalCertsCount is the total number of certificates in a chain
	TotalCertsCount int

	// ServiceCheckStatus is the overall status of the service check backed on
	// the presence of (or lack thereof) expired or expiring certificates.
	ServiceCheckStatus string

	// Summary is a high-level overview of the number of expired, expiring and
	// certificates not yet crossing over a WARNING or CRITICAL age threshold.
	Summary string
}

// GetCertsFromFile is a helper function for retrieving a certificates
// chain from a specified filename.
func GetCertsFromFile(filename string) ([]*x509.Certificate, []byte, error) {

	var certChain []*x509.Certificate

	// Read in the entire PEM certificate file after first attempting to
	// sanitize the input file variable contents.
	pemData, err := ioutil.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, nil, err
	}

	// Grab the first PEM formatted block in our PEM cert file data.
	block, rest := pem.Decode(pemData)

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
				return certChain, rest, err
			}

			// we got a cert. Let's add it to our list
			certChain = append(certChain, cert)

			if len(rest) > 0 {
				block, rest = pem.Decode(rest)
				continue
			}

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
// indicate the results of this check.
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

// FormattedExpiration receives a Time value and converts it to a string
// representing the largest useful whole units of time in days and hours. For
// example, if a certificate has 1 year, 2 days and 3 hours remaining, this
// function will return the string 367d 3h, but if only 3 hours remain then 3h
// will be returned.
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
	// the number of hours leftover from the days calculation
	// FIXME: math is not my strong suit, so this logic can likely be greatly
	// simplified
	hoursRemaining := math.Trunc(timeRemaining - (daysRemaining * 24))

	hoursRemainingStr = fmt.Sprintf("%dh", int64(hoursRemaining))

	formattedTimeRemainingStr = strings.Join([]string{
		daysRemainingStr, hoursRemainingStr}, " ")

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
// indicating the overall status at a glance.
func ExpirationStatus(cert *x509.Certificate, ageCritical time.Time, ageWarning time.Time) string {

	var expiresText string
	certExpiration := cert.NotAfter
	switch {
	case certExpiration.Before(time.Now()):
		expiresText = fmt.Sprintf(
			"[EXPIRED] %s",
			FormattedExpiration(certExpiration),
		)
	case certExpiration.Before(ageCritical):
		expiresText = fmt.Sprintf(
			"[%s] %s",
			nagios.StateCRITICALLabel,
			FormattedExpiration(certExpiration),
		)
	case certExpiration.Before(ageWarning):
		expiresText = fmt.Sprintf(
			"[%s] %s",
			nagios.StateWARNINGLabel,
			FormattedExpiration(certExpiration),
		)
	default:
		expiresText = fmt.Sprintf(
			"[%s] %s",
			nagios.StateOKLabel,
			FormattedExpiration(certExpiration),
		)

	}

	return expiresText

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

					case md5RSASigVerifyErr == nil:
						// fmt.Println("MD5 signature verified")

						return true
					}

				}

			}

			return false

		// no problems verifying self-signed signature
		case sigVerifyErr == nil:

			return true

		}

	}

	return false
}

// ChainPosition receives a cert and the cert chain that it belongs to and
// returns a string indicating what position or "role" it occurpies in the
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

// GenerateCertsReport receives a slice of x509 certificates, CRITICAL age
// threshold and WARNING age threshold values generates a formatted report
// suitable for display on the console or (potentially) via Microsoft Teams
// provided suitable conversion is performed on the output.
func GenerateCertsReport(certChain []*x509.Certificate, ageCritical time.Time, ageWarning time.Time) string {

	var certsReport string

	certsTotal := len(certChain)

	for idx, certificate := range certChain {

		certPosition := ChainPosition(certificate, certChain)

		expiresText := ExpirationStatus(
			certificate,
			ageCritical,
			ageWarning,
		)

		// FWIW: Nagios seems to display `\n` literally, but interpret `\r\n`
		// as the intended newline. Using `\r\n` seems to work normally when
		// testing with Ubuntu console output, so presumably this is fine
		// elsewhere too? The `\r\n` escape sequence "set" is provided by the
		// `nagios` package as `nagios.CheckOutputEOL`.
		certsReport += fmt.Sprintf(
			"Certificate %d of %d (%s):"+
				"%s\tName: %s"+
				"%s\tSANs entries: %s"+
				"%s\tKeyID: %v"+
				"%s\tIssuer: %s"+
				"%s\tIssuerKeyID: %v"+
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

	return certsReport

}

// CheckSANsEntries receives a x509 certificate, the x509 certificate chain it
// is a part of and a list of expected SANs entries that should be present for
// the certificate. The number of unmatched SANs entries is returned along
// with an error if validation failed.
func CheckSANsEntries(cert *x509.Certificate, certChain []*x509.Certificate, expectedEntries []string) (int, error) {

	unmatchedSANsEntriesFromList := make([]string, 0, len(expectedEntries))
	unmatchedSANsEntriesFromCert := make([]string, 0, len(cert.DNSNames))

	// Assuming that the DNSNames slice is NOT already lowercase, so forcing
	// them to be so first before comparing against the user-provided slice of
	// SANs entries.
	lcDNSNames := textutils.LowerCaseStringSlice(cert.DNSNames)

	switch {

	// more entries than is on the cert
	case len(expectedEntries) >= len(lcDNSNames):
		for idx := range expectedEntries {
			if !textutils.InList(strings.ToLower(expectedEntries[idx]), lcDNSNames) {
				unmatchedSANsEntriesFromList = append(unmatchedSANsEntriesFromList, expectedEntries[idx])
				continue
			}
		}

		if len(unmatchedSANsEntriesFromList) > 0 {
			return len(unmatchedSANsEntriesFromList), fmt.Errorf(
				"%d specified SANs entries missing from %s certificate: %v",
				len(unmatchedSANsEntriesFromList),
				ChainPosition(cert, certChain),
				unmatchedSANsEntriesFromList,
			)
		}

	// having more entries on the cert than specified is also a problem
	case len(expectedEntries) < len(lcDNSNames):

		for idx := range lcDNSNames {
			if !textutils.InList(strings.ToLower(lcDNSNames[idx]), expectedEntries) {
				unmatchedSANsEntriesFromCert = append(unmatchedSANsEntriesFromCert, lcDNSNames[idx])
				continue
			}
		}

		return len(unmatchedSANsEntriesFromCert), fmt.Errorf(
			"%d SANs entries on %s certificate not specified in provided list: %v",
			len(unmatchedSANsEntriesFromCert),
			ChainPosition(cert, certChain),
			unmatchedSANsEntriesFromCert,
		)

	}

	// best case, everything checks out
	return 0, nil

}

// NextToExpire receives a slice of x509 certificates and a boolean flag
// indicating whether already expired certificates should be excluded. If not
// excluded, the first expired certificate is returned, otherwise the first
// certificate out of the pool set to expire next is returned.
func NextToExpire(certChain []*x509.Certificate, excludeExpired bool) *x509.Certificate {

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
	// or the next certificate to expire. If *all* certs are expired, the cert
	// which first expired will be returned.
	nextToExpire := sortedChain[0]

	if excludeExpired {
		// skip expired certs and return the one set to expire next
		for idx := range sortedChain {
			if !IsExpiredCert(sortedChain[idx]) {
				nextToExpire = sortedChain[idx]
				break
			}
			continue
		}
	}

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

// ChainSummary receives a certificate chain, the critical age threshold and
// the warning age threshold and generates a summary of certificate details.
func ChainSummary(
	certChain []*x509.Certificate,
	certsExpireAgeCritical time.Time,
	certsExpireAgeWarning time.Time,
) ChainStatus {

	hasExpiredCerts := HasExpiredCert(certChain)
	expiredCertsCount := NumExpiredCerts(certChain)

	hasExpiringCerts := HasExpiringCert(
		certChain,
		certsExpireAgeCritical,
		certsExpireAgeWarning,
	)
	expiringCertsCount := NumExpiringCerts(
		certChain,
		certsExpireAgeCritical,
		certsExpireAgeWarning,
	)

	totalCerts := len(certChain)
	validCertsCount := totalCerts - expiredCertsCount - expiringCertsCount

	certsSummary := fmt.Sprintf(
		"[EXPIRED: %d, EXPIRING: %d, OK: %d]",
		expiredCertsCount,
		expiringCertsCount,
		validCertsCount,
	)

	var serviceCheckStatus string
	switch {
	case hasExpiredCerts:
		serviceCheckStatus = nagios.StateCRITICALLabel
	case hasExpiringCerts:
		serviceCheckStatus = nagios.StateWARNINGLabel
	case !hasExpiringCerts && !hasExpiredCerts:
		serviceCheckStatus = nagios.StateOKLabel
	default:
		serviceCheckStatus = nagios.StateUNKNOWNLabel
	}

	chainStatus := ChainStatus{
		HasExpiredCerts:    hasExpiredCerts,
		HasExpiringCerts:   hasExpiringCerts,
		ExpiredCertsCount:  expiredCertsCount,
		ExpiringCertsCount: expiringCertsCount,
		TotalCertsCount:    totalCerts,
		ServiceCheckStatus: serviceCheckStatus,
		Summary:            certsSummary,
	}

	return chainStatus

}

// OneLineCheckSummary receives the desired service check state as a prefix, a
// certificate chain, a cert summary as a suffix and then generates a one-line
// summary of the check results for display and notification purposes.
func OneLineCheckSummary(serviceState string, certChain []*x509.Certificate, certsSummary string) string {

	// Give the all clear: no issues found. Do go ahead and mention the next
	// expiration date in the chain for quick reference however.
	nextCertToExpire := NextToExpire(certChain, false)

	// Start by assuming that the CommonName is *not* blank
	nextCertToExpireServerName := nextCertToExpire.Subject.CommonName

	// but if it is, use the first SubjectAlterateName field in its place
	if nextCertToExpire.Subject.CommonName == "" {
		if len(nextCertToExpire.DNSNames[0]) > 0 {
			nextCertToExpireServerName = nextCertToExpire.DNSNames[0]
		}
	}

	summaryTemplate := CertCheckOneLineSummaryTmpl
	if hasExpiredCert := HasExpiredCert(certChain); hasExpiredCert {
		summaryTemplate = CertCheckOneLineSummaryExpiredTmpl
	}

	summary := fmt.Sprintf(
		summaryTemplate,
		serviceState,
		ChainPosition(nextCertToExpire, certChain),
		nextCertToExpireServerName,
		FormattedExpiration(nextCertToExpire.NotAfter),
		nextCertToExpire.NotAfter.Format(CertValidityDateLayout),
		certsSummary,
	)

	return summary

}
