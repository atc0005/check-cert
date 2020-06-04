// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package certs

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math"
	"strings"
	"time"

	"github.com/atc0005/check-certs/internal/textutils"
)

const (
	certChainPositionLeaf         string = "leaf"
	certChainPositionIntermediate string = "intermediate"
	certChainPositionRoot         string = "root"
	certChainPositionUnknown      string = "UNKNOWN: Please submit a bug report"
)

// ConvertKeyIDToHexStr converts a provided byte slice format of a X509v3
// Authority Key Identifier or X509v3 Subject Key Identifier to a hex-encoded
// string to reflect what is shown in the OpenSSL "text" format.
func ConvertKeyIDToHexStr(keyID []byte) string {

	hexStrKeyID := make([]string, 0, len(keyID))
	for _, field := range keyID {
		hexStrKeyID = append(hexStrKeyID, fmt.Sprintf("%X", field))
	}
	return strings.Join(hexStrKeyID, ":")
}

// GetGetCertsFromFile is a helper function for retrieving a certificates
// chain from a specified filename.
func GetCertsFromFile(filename string) ([]*x509.Certificate, []byte, error) {

	var certChain []*x509.Certificate

	// Read in the entire PEM certificate file
	pemData, err := ioutil.ReadFile(filename)
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

// IsIsExpiredCert receives a x509 certificate and returns a boolean value
// indicating whether the cert has expired.
func IsExpiredCert(cert *x509.Certificate) bool {
	return cert.NotAfter.Before(time.Now())
}

// HasExpiredCert receives a slice of x509 certificates and returns a boolean
// value indicating whether any certificates in the chain are expired along
// with a count of how many.
func HasExpiredCert(certChain []*x509.Certificate) (bool, int) {

	var expiredCertsPresent bool
	var expiredCertsCount int
	for idx := range certChain {

		if certChain[idx].NotAfter.Before(time.Now()) {
			expiredCertsPresent = true
			expiredCertsCount++
		}

	}

	return expiredCertsPresent, expiredCertsCount

}

// HasExpiringCert receives a slice of x509 certificates, CRITICAL age
// threshold and WARNING age threshold values and ignoring any certificates
// already expired, uses the provided thresholds to determine if any
// certificates are about to expire. A boolean value is returned to indicate
// the results of this check along with a count of expiring certificates.
func HasExpiringCert(certChain []*x509.Certificate, ageCritical time.Time, ageWarning time.Time) (bool, int) {

	var expiringCertsPresent bool
	var expiringCertsCount int
	for idx := range certChain {

		switch {
		case !IsExpiredCert(certChain[idx]) && certChain[idx].NotAfter.Before(ageCritical):
			expiringCertsPresent = true
			expiringCertsCount++
		case !IsExpiredCert(certChain[idx]) && certChain[idx].NotAfter.Before(ageWarning):
			expiringCertsPresent = true
			expiringCertsCount++
		}
	}

	return expiringCertsPresent, expiringCertsCount

}

// FormattedTimeUntilExpiration receives a Time value and converts it to a
// string representing the largest useful whole units of time in days and
// hours. For example, if a certificate has 1 year, 2 days and 3 hours
// remaining, this function will return the string 367d 3h, but if only 3
// hours remain then 3h will be returned.
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

	//if hoursRemaining > 0 {
	hoursRemainingStr = fmt.Sprintf("%dh", int64(hoursRemaining))
	//}

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

// ExpirationStatus receives a certificate and the expiration threshold values
// for CRITICAL and WARNING states and returns a human-readable string
// indicating the overall status at a glance.
func ExpirationStatus(cert *x509.Certificate, ageCritical time.Time, ageWarning time.Time) string {

	var expiresText string
	switch {
	case cert.NotAfter.Before(time.Now()):
		expiresText = fmt.Sprintf(
			"[EXPIRED] %s",
			FormattedExpiration(cert.NotAfter),
		)
	case cert.NotAfter.Before(ageCritical):
		expiresText = fmt.Sprintf(
			"[CRITICAL] %s",
			FormattedExpiration(cert.NotAfter),
		)
	case cert.NotAfter.Before(ageWarning):
		expiresText = fmt.Sprintf(
			"[WARNING] %s",
			FormattedExpiration(cert.NotAfter),
		)
	default:
		expiresText = fmt.Sprintf(
			// "[OK] | %s (%s)",
			"[OK] %s",
			FormattedExpiration(cert.NotAfter),
		)

	}

	return expiresText

}

// ChainChainPosition receives a cert and returns a string indicating what
// position or "role" it occurpies in the certificate chain
func ChainPosition(cert *x509.Certificate) string {

	var certPosition string

	switch {
	case cert.Issuer.String() == cert.Subject.String():
		certPosition = certChainPositionRoot
	case cert.IsCA:
		certPosition = certChainPositionIntermediate
	case !cert.IsCA:
		certPosition = certChainPositionLeaf
	default:
		certPosition = certChainPositionUnknown
	}

	return certPosition
}

// GenerateCertsReport receives a slice of x509 certificates, CRITICAL age
// threshold and WARNING age threshold values generates a formatted report
// suitable for display on the console or (potentially) via Microsoft Teams
// provided suitable conversion is performed on the output.
func GenerateCertsReport(certChain []*x509.Certificate, ageCritical time.Time, ageWarning time.Time) string {

	var certsReport string

	certsTotal := len(certChain)

	for idx, certificate := range certChain {

		certPosition := ChainPosition(certificate)

		expiresText := ExpirationStatus(
			certificate,
			ageCritical,
			ageWarning,
		)

		certsReport += fmt.Sprintf(
			"\nCertificate %d of %d (%s):"+
				"\n\tName: %s"+
				"\n\tSANs entries: %s"+
				"\n\tKeyID: %v"+
				"\n\tIssuer: %s"+
				"\n\tIssuerKeyID: %v"+
				"\n\tSerial: %s"+
				"\n\tExpiration: %s"+
				"\n\tStatus: %s\n\n",
			idx+1,
			certsTotal,
			certPosition,
			certificate.Subject,
			certificate.DNSNames,
			ConvertKeyIDToHexStr(certificate.SubjectKeyId),
			certificate.Issuer,
			ConvertKeyIDToHexStr(certificate.AuthorityKeyId),
			certificate.SerialNumber,
			certificate.NotAfter.String(),
			expiresText,
		)

	}

	return certsReport

}

// CheckSANsEntries receives a x509 certificate and a list of expected SANs
// entries that should be present for the certificate. A slice of SANs entries
// NOT found on the specified certificate is returned along with an error if
// validation failed.
func CheckSANsEntries(cert *x509.Certificate, expectedEntries []string) ([]string, error) {

	// if all goes well this will remain nil
	var err error

	unmatchedSANsEntries := make([]string, 0, len(expectedEntries))

	// Assuming that the DNSNames slice is NOT already lowercase, so forcing
	// them to be so first before comparing against the user-provided slice of
	// SANs entries.
	lcDNSNames := textutils.LowerCaseStringSlice(cert.DNSNames)

	switch {

	// more entries than is on the cert
	case len(expectedEntries) > len(lcDNSNames):
		for idx := range expectedEntries {
			if !textutils.InList(strings.ToLower(expectedEntries[idx]), lcDNSNames) {
				unmatchedSANsEntries = append(unmatchedSANsEntries, expectedEntries[idx])
				continue
			}
		}

		if len(unmatchedSANsEntries) > 0 {
			err = fmt.Errorf(
				"%d specified SANs entries missing from %s certificate: %v",
				len(unmatchedSANsEntries),
				ChainPosition(cert),
				unmatchedSANsEntries,
			)
		}

	// having more entries on the cert than specified is also a problem
	case len(expectedEntries) < len(lcDNSNames):

		for idx := range lcDNSNames {
			if !textutils.InList(strings.ToLower(lcDNSNames[idx]), expectedEntries) {
				unmatchedSANsEntries = append(unmatchedSANsEntries, lcDNSNames[idx])
				continue
			}
		}

		err = fmt.Errorf(
			"%d SANs entries on certificate not specified in provided list: %v",
			len(unmatchedSANsEntries),
			ChainPosition(cert),
			unmatchedSANsEntries,
		)

	}

	// entries requested that are missing from the cert are a problem
	if len(unmatchedSANsEntries) > 0 {
		return unmatchedSANsEntries, fmt.Errorf(
			"%d specified SANs entries missing from %s certificate: %v",
			len(unmatchedSANsEntries),
			ChainPosition(cert),
			unmatchedSANsEntries,
		)
	}

	// best case, everything checks out
	return unmatchedSANsEntries, nil

	// if len(unmatchedSANsEntries) > 0 {

	// }

	// 	return fmt.Errorf("one or more SANs entries not provided")
	// }

}
