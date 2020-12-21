// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package netutils

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// ErrUnrecognizedHostOrIPValue indicates that a given string value is
// unrecognized as a valid FQDN, single IP Address or range (partial or CIDR).
// This is usually not a temporary error condition.
var ErrUnrecognizedHostOrIPValue error = errors.New("unrecognized FQDN, single IP Address or range")

// IndexSize returns the number of entries in the index.
func (idx IPv4AddressOctetsIndex) IndexSize() int {
	var mapEntriesSize int
	for i := range idx {
		mapEntriesSize += len(idx[i])
	}

	return mapEntriesSize
}

// HasOpenPort indicates whether at least one specified port was found to be
// open for a scanned host.
func (rs PortCheckResults) HasOpenPort() bool {
	for _, r := range rs {
		if r.Open {
			return true
		}
	}

	return false
}

// Summary generates a one-line summary of port check results.
func (rs PortCheckResults) Summary() string {

	sx := make([]string, len(rs))

	for i, result := range rs {
		sx[i] = fmt.Sprintf("%v: %v", result.Port, result.Open)
	}

	return strings.Join(sx, ", ")

}

// CheckPort checks whether a specified TCP port is open. Any errors
// encountered are returned along with the port status.
func CheckPort(host string, port int, timeout time.Duration) PortCheckResult {

	// TODO: Make sure to set PortCheckResult.Err to an error which indicates
	// the severity of the issue. For example, failing to close the port is
	// different than failing to establish a connection. We can then check
	// this "severity" at the call site to determine whether to fail the scan
	// or keep going with a WARNING status for the specific host.

	ipAddress := net.ParseIP(host)

	conn, connErr := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if connErr != nil {
		return PortCheckResult{
			IPAddress: net.IPAddr{IP: ipAddress},
			Port:      port,
			Open:      false,
			Err:       connErr,
		}
	}

	closeErr := conn.Close()
	if closeErr != nil {
		return PortCheckResult{
			IPAddress: net.IPAddr{IP: ipAddress},
			Port:      port,
			Open:      true,
			Err:       closeErr,
		}
	}

	return PortCheckResult{
		IPAddress: net.IPAddr{IP: ipAddress},
		Port:      port,
		Open:      true,
		Err:       nil,
	}

}

// CIDRHosts converts a CIDR network pattern into a slice of hosts within that
// network, the total count of hosts and an error if any occurred.
//
// https://stackoverflow.com/questions/60540465/go-how-to-list-all-ips-in-a-network
// https://play.golang.org/p/fe-F2k6prlA
// https://gist.github.com/kotakanbe/d3059af990252ba89a82
func CIDRHosts(cidr string) ([]string, int, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, 0, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// remove network address and broadcast address
	lenIPs := len(ips)
	switch {
	case lenIPs < 2:
		return ips, lenIPs, nil

	default:
		return ips[1 : len(ips)-1], lenIPs - 2, nil
	}
}

// inc is a helper function used to increment a given IP Address (presumably
// to the next available IP Address).
//
// https://stackoverflow.com/questions/60540465/go-how-to-list-all-ips-in-a-network
// https://play.golang.org/p/fe-F2k6prlA
// https://gist.github.com/kotakanbe/d3059af990252ba89a82
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// GetCerts retrieves and returns the certificate chain from the specified
// host & port or an error if one occurs. Enforced certificate verification is
// intentionally disabled in order to successfully retrieve and examine all
// certificates in the certificate chain.
func GetCerts(server string, port int, timeout time.Duration, logger zerolog.Logger) ([]*x509.Certificate, error) {

	var certChain []*x509.Certificate

	logger = logger.With().
		Str("server", server).
		Int("port", port).
		Str("timeout", timeout.String()).
		Logger()

	logger.Debug().Msg("Connecting to remote server")
	tlsConfig := tls.Config{
		// Permit insecure connection.
		//
		// This is needed so that we can examine not only valid certificates,
		// but certs that are expired, self-signed or having other properties
		// which make them invalid. This is also needed so that we can examine
		// not only the initial certificate, but others in the chain also.
		// This allows us to flag any intermediate or root certs which may
		// also be expired.
		//
		// Ignore security (gosec) linting warnings re this choice.
		// nolint:gosec
		InsecureSkipVerify: true,
	}

	// Create custom dialer with user-specified timeout value
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	serverConnStr := fmt.Sprintf("%s:%d", server, port)
	conn, connErr := tls.DialWithDialer(dialer, "tcp", serverConnStr, &tlsConfig)
	if connErr != nil {
		// logger.Error().Err(connErr).Msgf("error connecting to server")
		return nil, fmt.Errorf("error connecting to server: %w", connErr)
	}
	logger.Debug().Msg("Connected")

	// grab certificate chain as presented by remote peer
	certChain = conn.ConnectionState().PeerCertificates
	logger.Debug().Msg("Retrieved certificate chain")

	// close connection once we're finished with it
	if err := conn.Close(); err != nil {
		errMsg := "error closing connection to server"
		logger.Error().Err(err).Msg(errMsg)

		return nil, fmt.Errorf("%s: %w", errMsg, err)
	}
	logger.Debug().Msg("Successfully closed connection to server")

	return certChain, nil
}

// IsCIDR indicates whether a specified string is a CIDR notation IP address
// and prefix length, like "192.0.2.0/24" or "2001:db8::/32", as defined in
// RFC 4632 and RFC 4291.
func IsCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)

	return err == nil
}

// octetWithinBounds indicates whether a specified value is within the lower
// and upper ranges of an IPv4 octet.
func octetWithinBounds(i int) bool {

	return i >= 0 && i <= 255
}

// isIPv4AddrCandidate asserts that provided string can be converted directly
// to an integer after any octet separators and partial range dash specifiers
// are removed.
func isIPv4AddrCandidate(s string) bool {

	s = strings.Trim(s, ".-")
	_, err := strconv.Atoi(s)

	return err == nil
}

// ExpandIPAddress accepts a string value representing either an individual IP
// Address, a CIDR IP range or a partial (dash-separated) range (e.g.,
// 192.168.2.10-15). IP Address ranges  and expands to scan for certificates.
func ExpandIPAddress(s string) ([]string, error) {

	givenIPsList := make([]string, 0, 1024)

	switch {

	// assume that user specified a CIDR mask
	case strings.Contains(s, "/"):

		if IsCIDR(s) {
			ipAddrs, _, err := CIDRHosts(s)
			if err != nil {
				return nil, fmt.Errorf("error parsing CIDR range: %s", err)
			}
			// fmt.Printf("%q is a CIDR rangeof %d IPs\n", s, count)
			givenIPsList = append(givenIPsList, ipAddrs...)

			return givenIPsList, nil
		}

		return nil, fmt.Errorf("%q contains slash, but fails CIDR parsing", s)

	// valid (presumably single) IPv4 or IPv6 address
	case net.ParseIP(s) != nil:

		// fmt.Printf("%q is an IP Address\n", s)
		givenIPsList = append(givenIPsList, s)

		return givenIPsList, nil

	// no CIDR mask, not a single IP Address (earlier check would have
	// triggered), and so potentially a partial range of IPv4 Addresses
	case isIPv4AddrCandidate(s) && strings.Contains(s, "."):

		octets := strings.Split(s, ".")

		if len(octets) != 4 {
			return nil, fmt.Errorf(
				"%q (%d octets) not IPv4 Address; does not contain 4 octets",
				s,
				len(octets),
			)
		}

		// fmt.Printf("%q is a potential IP Address range\n", s)

		// reminder: at this point single IP Address was handled by earlier
		// switch case. We are either dealing with a partial range or invalid
		// value.

		// check for dash character used to specify partial IP range
		if !strings.Contains(s, "-") {
			return nil, fmt.Errorf(
				"%q not IP Address range; does not contain dash character",
				s,
			)
		}

		ipAddrOctIdx := make(IPv4AddressOctetsIndex)

		for octIdx := range octets {

			// split on dashes, loop over that
			halves := strings.Split(octets[octIdx], "-")

			switch {

			// dash is not present
			case len(halves) == 1:

				// fmt.Printf("DEBUG: octet %d does not have a dash\n", octIdx)

				num, err := strconv.Atoi(halves[0])
				if err != nil {
					return nil, fmt.Errorf(
						"octet %q of IP pattern %q invalid; "+
							"non-numeric values present",
						octets[octIdx],
						s,
					)
				}

				if !octetWithinBounds(num) {
					return nil, fmt.Errorf(
						"octet %q of IP pattern %q outside lower (0), upper (255) bounds",
						octets[octIdx],
						s,
					)
				}

				// extend values for this octet
				ipAddrOctIdx[octIdx] = append(ipAddrOctIdx[octIdx], num)

				// fmt.Printf("DEBUG: %+v\n", ipAddrOctIdx)

			// one dash present, this is a range separator
			case len(halves) == 2:

				rangeStart, err := strconv.Atoi(halves[0])
				if err != nil {
					return nil, fmt.Errorf(
						"octet %q of IP pattern %q invalid; "+
							"non-numeric values present",
						octets[octIdx],
						s,
					)
				}

				rangeEnd, err := strconv.Atoi(halves[1])
				if err != nil {
					return nil, fmt.Errorf(
						"octet %q of IP pattern %q invalid; "+
							"non-numeric values present",
						octets[octIdx],
						s,
					)
				}

				switch {
				case rangeStart > rangeEnd:
					return nil, fmt.Errorf(
						"%q is invalid octet range; "+
							"given start value %d greater than end value %d",
						octets[octIdx],
						rangeStart,
						rangeEnd,
					)

				case rangeStart == rangeEnd:
					return nil, fmt.Errorf(
						"%q is invalid octet range; "+
							"given start value %d equal to end value %d",
						octets[octIdx],
						rangeStart,
						rangeEnd,
					)
				}

				for i := rangeStart; i <= rangeEnd; i++ {
					if !octetWithinBounds(i) {
						return nil, fmt.Errorf(
							"octet %q of IP pattern %q outside lower (0), upper (255) bounds",
							octets[octIdx],
							s,
						)
					}

					// extend values for this octet
					ipAddrOctIdx[octIdx] = append(ipAddrOctIdx[octIdx], i)
					// fmt.Printf("DEBUG: %+v\n", ipAddrOctIdx)
				}

			// more than one dash present in octet, malformed range
			default:

				numDashes := strings.Count(octets[octIdx], "-")
				return nil, fmt.Errorf(
					"%d dash separators in octet %q (%d of %d); expected one",
					numDashes,
					octIdx,
					octIdx+1,
					len(octets),
				)
			}

		}

		// internal state validity check
		if len(ipAddrOctIdx) != len(octets) {
			return nil, fmt.Errorf(
				"ipAddress octet map size incorrect; got %d, wanted %d",
				len(ipAddrOctIdx),
				len(octets),
			)
		}

		// Ex IP: 192.168.5.10
		// 192(w).168(x).5(y).10(z)
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

						// TODO: Is this worth failing execution, or should we
						// emit a WARNING level message instead? Probably best
						// to implement a specific error type that we can
						// match on to determine severity.
						if net.ParseIP(ipAddrString) == nil {
							return nil, fmt.Errorf(
								"%q (from parsed range) is an invalid IP Address",
								ipAddrString,
							)
						}

						givenIPsList = append(givenIPsList, ipAddrString)
					}
				}
			}
		}

		return givenIPsList, nil

	// not a CIDR range, IP Address or partial IP Address range, so
	// potentially a hostname or FQDN (or completely invalid)
	default:

		// attempt to parse the value as a hostname or FQDN
		results, lookupErr := net.LookupHost(s)
		if lookupErr != nil {
			return nil, fmt.Errorf(
				"%q invalid; %w: %s",
				s,
				ErrUnrecognizedHostOrIPValue,
				lookupErr.Error(),
			)
		}

		givenIPsList = append(givenIPsList, results...)

		return givenIPsList, nil

	}
}
