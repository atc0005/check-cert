// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package netutils

import "net"

// PortCheckResult indicates the discovered TCP port state for a given host
// and what error (if any) occurred while checking the port.
type PortCheckResult struct {
	// Host is the hostname, FQDN or IP Address value used to evaluate the TCP
	// port state.
	Host string

	// IPAddress represents the address of an IP end point.
	IPAddress net.IPAddr

	// Port is the specific TCP port evaluated on a host.
	Port int

	// Open indicates whether a TCP port was found to be open during a port
	// check.
	Open bool

	// Err is what error (if any) which occurred while checking a TCP port.
	Err error
}

// PortCheckResults is a collection of PortCheckResult intended for bulk
// operations such as filtering or generating summaries.
type PortCheckResults []PortCheckResult

// PortCheckResultsIndex maps the results slice from scan attempts against a
// specified list of ports to an IP Address associated with scanned ports.
type PortCheckResultsIndex map[string]PortCheckResults

// IPv4AddressOctetsIndex is a map of IPv4 octets to values within those
// octets associated with partial ranges. This type is used to help implement
// support for octet range addressing.
type IPv4AddressOctetsIndex map[int][]int
