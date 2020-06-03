// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package certs

import (
	"fmt"
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
