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
	// Host is the hostname or FQDN value (if available) used to evaluate the
	// TCP port state.
	Host string

	// IPAddress represents the parsed address of an IP end point. This value
	// should always be populated.
	IPAddress net.IPAddr

	// Port is the specific TCP port evaluated on a host.
	Port int

	// Open indicates whether a TCP port was found to be open during a port
	// check.
	Open bool

	// Err is what error (if any) which occurred while checking a TCP port.
	Err error
}

// PortCheckTarget specifies values used to check the TCP port state for a
// given host.
type PortCheckTarget struct {
	// Name is the hostname or FQDN associated with a scan target. This field
	// is used to track an optional hostname or FQDN associated with a scan
	// target. This value is used in logging output and later passed to called
	// functions in order to provide SNI support.
	Name string

	// IPAddress is the resolved value used to evaluate the TCP port state.
	IPAddress string

	// Ports is the collection of TCP ports to evaluate for a host.
	Ports []int
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

// HostPattern represents an original specified host pattern provided by the
// caller and the collection of IP Addresses expanded from the pattern.
type HostPattern struct {
	// Given records the host pattern provided by the caller. This can be a
	// single IP Address, a range, a hostname or FQDN.
	Given string

	// Expanded records the individual IP Addresses associated with a given
	// host pattern. This may be a collection of IP Addresses associated with
	// a range or DNS A record, but may also be a single IP Address associated
	// with an A record or the original given single IP Address.
	Expanded []string

	// Resolved indicates whether the given host pattern was resolved to one
	// or more IP Addresses. This is false for IP Addresses and true for
	// hostname or FQDN values which successfully resolve to one or more IP
	// Addresses.
	Resolved bool
}
