// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package config

import "time"

// Timeout converts the user-specified connection timeout value in
// seconds to an appropriate time duration value for use with setting
// net.Dial timeout.
func (c Config) Timeout() time.Duration {
	return time.Duration(c.timeout) * time.Second
}

// TimeoutPortScan converts the user-specified port scan timeout value in
// milliseconds to an appropriate time duration value for use with setting
// net.Dial timeout.
func (c Config) TimeoutPortScan() time.Duration {
	return time.Duration(c.timeoutPortScan) * time.Millisecond
}

// TimeoutAppInactivity converts the user-specified application inactivity
// timeout value in seconds to an appropriate time duration value for use with
// setting automatic context cancellation.
func (c Config) TimeoutAppInactivity() time.Duration {
	return time.Duration(c.timeoutAppInactivity) * time.Second
}

// CertPorts returns the user-specified list of ports to check for
// certificates or the default value if not specified.
func (c Config) CertPorts() []int {
	if c.portsList != nil {
		return c.portsList
	}

	return []int{defaultPortsListEntry}
}

// IPAddresses returns a list of individual IP Addresses expanded from any
// user-specified IP Addresses (single or ranges), hostnames or FQDNs.
func (c Config) IPAddresses() []string {
	if c.hosts.expanded != nil {
		return c.hosts.expanded
	}

	return []string{}
}
