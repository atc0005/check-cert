package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/atc0005/check-certs/internal/netutils"
)

// Purpose: Proof of concept for new partial range syntax. Based heavily off
// of nmap's "octet range addressing" syntax.

// TODO: Setup methods for this type to covert entries to IP Address strings
// or whatever format we end up needing. We could even have multiple methods.
type ipAddressOctetsIndex map[int][]int

func isCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)

	return err == nil
}

func octetWithinBounds(i int) bool {
	return i >= 0 && i <= 255
}

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Error: Missing test range")
		os.Exit(1)
	}

	givenIPsList := make([]string, 0, 1024)
	// var givenIPsList []string

	input := os.Args[1]

	// Without using a pointer to this slice the slice header is passed
	// instead. This header points to a backing array of a fixed size. Once
	// the slice exceeds that initial backing array the slice header is
	// pointed to a new array with sufficient capacity. Thus, if working with
	// a slice header, this function would end up trying to access the old
	// array through the copy of the slice header it receives. This would
	// either result in a subset of the intended values or if deferred early
	// (as we're doing), would result in an empty slice.
	defer func(ipAddrs *[]string) {

		switch {
		case ipAddrs == nil:
			fmt.Println("specified IPs slice is nil")

		case len(*ipAddrs) > 512:
			fmt.Printf("Final IPs list has %d IPs (skipping printing of large list)\n", len(*ipAddrs))

		default:
			fmt.Printf("Final IPs list (%d IPs): %v\n", len(*ipAddrs), *ipAddrs)

		}

	}(&givenIPsList)

	// non-empty, comma-separated list of values
	// loop over each value
	// confirm that . character is present
	// switch
	// if slash character is found
	// attempt to parse whole value as CIDR range
	// if dash character is found
	// split on . character
	// confirm that 4 octets are found
	// check each octet to ensure that each is within upper/lower bounds
	//

	switch {

	// assume that user specified a CIDR mask
	case strings.Contains(input, "/"):

		if isCIDR(input) {
			ipAddrs, count, err := netutils.CIDRHosts(input)
			if err != nil {
				fmt.Printf("error parsing CIDR range: %s\n", err)
			}
			fmt.Printf("%q is a CIDR rangeof %d IPs\n", input, count)
			givenIPsList = append(givenIPsList, ipAddrs...)
		}

	// valid (presumably single) IPv4 or IPv6 address
	case net.ParseIP(input) != nil:

		fmt.Printf("%q is an IP Address\n", input)
		givenIPsList = append(givenIPsList, input)

	// no CIDR mask, and not a single IP Address (earlier check would have
	// triggered), so potentially a partial range of IPv4 Addresses
	case strings.Contains(input, "."):

		octets := strings.Split(input, ".")

		if len(octets) != 4 {
			fmt.Printf(
				"%q (%d octets) not IPv4 Address; does not contain 4 octets\n",
				input,
				len(octets),
			)

			return
		}

		fmt.Printf("%q is a potential IP Address range\n", input)

		// reminder: at this point single IP Address was handled by earlier
		// switch case. We are either dealing with a partial range or invalid
		// value.

		// check for dash character used to specify partial IP range
		if !strings.Contains(input, "-") {
			fmt.Printf(
				"%q not IP Address range; does not contain dash character\n",
				input,
			)

			return
		}

		ipAddrOctIdx := make(ipAddressOctetsIndex)

		for octIdx := range octets {

			// split on dashes, loop over that
			halves := strings.Split(octets[octIdx], "-")

			switch {

			// dash is not present
			case len(halves) == 1:

				// fmt.Printf("DEBUG: octet %d does not have a dash\n", octIdx)

				num, err := strconv.Atoi(halves[0])
				if err != nil {
					fmt.Printf(
						"octet %q of IP pattern %q invalid; "+
							"non-numeric values present\n",
						octets[octIdx],
						input,
					)

					return
				}

				if !octetWithinBounds(num) {
					fmt.Printf(
						"octet %q of IP pattern %q outside lower (0), upper (255) bounds\n",
						octets[octIdx],
						input,
					)

					return
				}

				// extend values for this octet
				ipAddrOctIdx[octIdx] = append(ipAddrOctIdx[octIdx], num)

				// fmt.Printf("DEBUG: %+v\n", ipAddrOctIdx)

			// one dash present, this is a range separator
			case len(halves) == 2:

				rangeStart, err := strconv.Atoi(halves[0])
				if err != nil {
					fmt.Printf(
						"octet %q of IP pattern %q invalid; "+
							"non-numeric values present\n",
						octets[octIdx],
						input,
					)

					return
				}

				rangeEnd, err := strconv.Atoi(halves[1])
				if err != nil {
					fmt.Printf(
						"octet %q of IP pattern %q invalid; "+
							"non-numeric values present\n",
						octets[octIdx],
						input,
					)

					return
				}

				// TODO: range over halves and begin building valid values
				// using existing octet values
				//
				// e.g., 192.168.1-15.10-12 and assume we are on octet 3 at
				// this point we should combine "192.168." with "10", "11",
				// "12", "13", "14", "15" this process should be repeated once
				// octet 4 is examined

				// should I use an array to track this?
				// struct with 4 fields to track the 4 octets?

				switch {
				case rangeStart > rangeEnd:
					fmt.Printf(
						"%q is invalid octet range; "+
							"given start value %d greater than end value %d\n",
						octets[octIdx],
						rangeStart,
						rangeEnd,
					)

					return

				case rangeStart == rangeEnd:
					fmt.Printf(
						"%q is invalid octet range; "+
							"given start value %d equal to end value %d\n",
						octets[octIdx],
						rangeStart,
						rangeEnd,
					)

					return
				}

				for i := rangeStart; i <= rangeEnd; i++ {
					if !octetWithinBounds(i) {
						fmt.Printf(
							"octet %q of IP pattern %q outside lower (0), upper (255) bounds\n",
							octets[octIdx],
							input,
						)

						return
					}

					// extend values for this octet
					ipAddrOctIdx[octIdx] = append(ipAddrOctIdx[octIdx], i)
					// fmt.Printf("DEBUG: %+v\n", ipAddrOctIdx)
				}

			// more than one dash present in octet, malformed range
			default:

				numDashes := strings.Count(octets[octIdx], "-")
				fmt.Printf(
					"%d dash separators in octet %q (%d of %d); expected one\n",
					numDashes,
					octIdx,
					octIdx+1,
					len(octets),
				)

				return

			}

		}

		// EXPAND THE INDEX OF VALUES TO IP ADDRESSES HERE

		// loop over map (or not?)
		// the map should be length 4
		// each key should be numbered 0-3
		// each key points to a slice of values for the octet that the key represents

		if len(ipAddrOctIdx) != len(octets) {
			fmt.Printf(
				"ipAddress octet map size incorrect; got %d, wanted %d\n",
				len(ipAddrOctIdx),
				len(octets),
			)

			return
		}

		// Ex IP: 192.168.5.10
		// 192(w).168(x).5(y).10(z)
		// var mapEntriesSize int
		// for i := range ipAddrOctIdx {
		// 	mapEntriesSize += ipAddrOctIdx[i]
		// }

		for i := range ipAddrOctIdx[0] {
			w := strconv.Itoa(ipAddrOctIdx[0][i])

			for j := range ipAddrOctIdx[1] {
				x := strconv.Itoa(ipAddrOctIdx[1][j])

				for k := range ipAddrOctIdx[2] {
					y := strconv.Itoa(ipAddrOctIdx[2][k])

					for l := range ipAddrOctIdx[3] {
						z := strconv.Itoa(ipAddrOctIdx[3][l])

						// fmt.Println(strings.Join([]string{w, x, y, z}, "."))
						ipAddrString := strings.Join([]string{w, x, y, z}, ".")

						if net.ParseIP(ipAddrString) == nil {
							fmt.Printf(
								"%q (from parsed range) is an invalid IP Address\n",
								ipAddrString,
							)

							return
						}

						givenIPsList = append(givenIPsList, ipAddrString)
					}
				}
			}
		}

	default:
		fmt.Printf("%q not recognized as IP Address or IP Address range\n", input)

		return
	}

	// https://golang.org/pkg/net/#IPNet.Contains

}
