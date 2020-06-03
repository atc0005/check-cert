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
	"strings"
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

			fmt.Println("Type of block:", block.Type)
			fmt.Println("size of file content:", len(pemData))
			fmt.Println("size of rest:", len(rest))

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
