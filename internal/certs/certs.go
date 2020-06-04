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
)

// ConvertKeyIdToHexStr converts a provided byte slice format of a X509v3
// Authority Key Identifier or X509v3 Subject Key Identifier to a hex-encoded
// string to reflect what is shown in the OpenSSL "text" format.
func ConvertKeyIdToHexStr(keyId []byte) string {
	var hexStrKeyId []string
	for _, field := range keyId {
		hexStrKeyId = append(hexStrKeyId, fmt.Sprintf("%X", field))
	}
	return strings.Join(hexStrKeyId, ":")
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

// FormattedTimeUntilExpiration receives a Time value and converts it to a
// string representing the largest useful whole units of time in days and
// hours. For example, if a certificate has 1 year, 2 days and 3 hours
// remaining, this function will return the string 367d 3h, but if only 3
// hours remain then 3h will be returned.
func FormattedTimeUntilExpiration(expireTime time.Time) string {

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

	if hoursRemaining > 0 {
		hoursRemainingStr = fmt.Sprintf("%dh", int64(hoursRemaining))
	}

	formattedTimeRemainingStr = strings.Join([]string{
		daysRemainingStr, hoursRemainingStr}, " ")

	switch {
	case !certExpired:
		formattedTimeRemainingStr += " remaining"
	case certExpired:
		formattedTimeRemainingStr += " ago"
	}

	return formattedTimeRemainingStr

}
