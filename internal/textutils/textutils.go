// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package textutils

import (
	"fmt"
	"strings"
)

// InList is a helper function to emulate Python's `if "x"
// in list:` functionality
func InList(needle string, haystack []string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}

func PrintHeader(headerText string) {
	headerBorderStr := strings.Repeat("=", len(headerText))
	fmt.Printf(
		"\n\n%s\n%s\n%s\n",
		headerBorderStr,
		headerText,
		headerBorderStr,
	)
}
