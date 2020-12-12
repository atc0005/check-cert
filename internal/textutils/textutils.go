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

// LowerCaseStringSlice is a helper function to convert all provided string
// slice elements to lowercase.
//
// FIXME: There is likely a better way to do this already; replace with that
// better way.
func LowerCaseStringSlice(xs []string) []string {
	lxs := make([]string, 0, len(xs))
	for idx := range xs {
		lxs = append(lxs, strings.ToLower(xs[idx]))
	}

	return lxs
}

// PrintHeader printers a section header to help separate otherwise
// potentially dense blocks of text.
func PrintHeader(headerText string) {
	headerBorderStr := strings.Repeat("=", len(headerText))
	fmt.Printf(
		"\n\n%s\n%s\n%s\n",
		headerBorderStr,
		headerText,
		headerBorderStr,
	)
}

// InsertDelimiter inserts a delimiter into the provided string every pos
// characters. If the length of the provided string is less than pos + 1
// characters the original string is returned unmodified as we are unable to
// insert delimiter between blocks of characters of specified (pos) size.
func InsertDelimiter(s string, delimiter string, pos int) string {

	if len(s) < pos+1 {
		return s
	}

	// convert string to rune slice in order to use unicode package functions
	// (which expect to work with runes).
	r := []rune(s)

	// to track position in string
	var ctr int

	var delimitedStr string
	for i, v := range r {
		c := string(v)
		ctr++

		// add delimiter when we have reached the specified position in the
		// string, provided that we've not reached the end of the string.
		if (ctr == pos) && (i+1 != len(r)) {
			delimitedStr += c + delimiter
			ctr = 0
			continue
		}
		delimitedStr += c
	}

	return delimitedStr
}
