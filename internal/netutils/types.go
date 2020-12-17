// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package netutils

import "net"

// PortCheckResult indicates whether a TCP port is open and what error (if
// any) occurred checking the port.
type PortCheckResult struct {
	IPAddress net.IPAddr
	Port      int
	Open      bool
	Err       error
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
