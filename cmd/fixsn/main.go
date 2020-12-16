// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

// Purpose:
//
// A small CLI app used to convert a given base 10 number into a base 16,
// colon delimited hex string representing a certificate serial number. Prior
// releases of this project improperly displayed serial numbers as base 10
// values instead of base 16, colon delimited hex strings. Using this tool can
// be useful for one-off conversion of older values to the proper format
// (e.g., a certs list maintained in documentation).

package main

import (
	"fmt"
	"math/big"
	"os"
	"regexp"

	"github.com/atc0005/check-certs/internal/certs"
)

func main() {

	// https://stackoverflow.com/a/58957206/903870
	var digitCheck = regexp.MustCompile(`^[0-9]+$`)

	// expected output: FD:6F:3E:24:98:C2:5B:1D:08:00:00:00:00:47:F0:33
	sampleExpectedInput := "336872288293767042001244177974291853363"

	serialNumber := new(big.Int)

	if len(os.Args) < 2 {
		fmt.Println("Error: Missing serial number (in base 10 format)")
		fmt.Println("Example expected input:", sampleExpectedInput)
		os.Exit(1)
	}

	if !digitCheck.MatchString(os.Args[1]) {
		fmt.Println("Error: Invalid serial number (in base 10 format)")
		fmt.Println("Example expected input:", sampleExpectedInput)
		os.Exit(1)
	}

	_, ok := serialNumber.SetString(os.Args[1], 10)
	if !ok {
		fmt.Println("Error: Failed to parse provided serial number (in base 10 format)")
		fmt.Println("Example expected input:", sampleExpectedInput)
		os.Exit(1)
	}

	fmt.Println(certs.FormatCertSerialNumber(serialNumber))

}
