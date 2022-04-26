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
// unrecognized as a valid hostname or IP Address.
var ErrUnrecognizedHostOrIPValue = errors.New("unrecognized hostname or IP Address")

// ErrUnrecognizedIPRange indicates that a given string value is unrecognized
// as a valid IP Address range (partial or CIDR).
var ErrUnrecognizedIPRange = errors.New("unrecognized IP Address range")

// ErrUnrecognizedIPAddress indicates that a given string value is
// unrecognized as a valid IP Address.
var ErrUnrecognizedIPAddress = errors.New("unrecognized IP Address")

// ErrHostnameFailsNameResolution indicates that a given string value fails
// name to IP Address resolution.
var ErrHostnameFailsNameResolution = errors.New("failed to resolve name to IP Address")

// ErrIPAddrOctectIdxValidityFailure indicates that the internal state of an
// IP Address octet map failed a validity check.
var ErrIPAddrOctectIdxValidityFailure = errors.New("invalid index of IP Address to octets")

// ErrMissingValue indicates that an expected value was missing.
var ErrMissingValue = errors.New("missing expected value")

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

// Host returns the (single) host associated with port check results.
func (rs PortCheckResults) Host() string {
	if rs == nil {
		return ""
	}

	return rs[0].IPAddress.String()

}

// Summary generates a one-line summary of port check results.
func (rs PortCheckResults) Summary() string {

	sx := make([]string, len(rs))

	for i, result := range rs {
		sx[i] = fmt.Sprintf("%v: %v", result.Port, result.Open)
	}

	return strings.Join(sx, ", ")

}

// Summary generates a one-line summary of port check result.
func (rs PortCheckResult) Summary() string {
	return fmt.Sprintf("%v: %v", rs.Port, rs.Open)
}

// CheckPort checks whether a specified TCP port for a given host is open.
//
// The given host value must provide a valid IP Address and optionally a
// resolvable hostname. If provided, the hostname is recorded to enable SNI
// support when retrieving certificates later.
//
// Any errors encountered are returned along with the port status.
//
// NOTE: This function explicitly returns real values for host & port instead
// of zero values so that they may be used in summary output by callers.
func CheckPort(host PortCheckTarget, port int, timeout time.Duration) PortCheckResult {

	if strings.TrimSpace(host.IPAddress) == "" {
		return PortCheckResult{
			Host:      host.Name,
			IPAddress: net.IPAddr{IP: nil},
			Port:      port,
			Open:      false,
			Err:       ErrUnrecognizedHostOrIPValue,
		}
	}

	// TODO: Make sure to set PortCheckResult.Err to an error which indicates
	// the severity of the issue. For example, failing to close the port is
	// different than failing to establish a connection. We can then check
	// this "severity" at the call site to determine whether to fail the scan
	// or keep going with a WARNING status for the specific host.

	serverConnStr := net.JoinHostPort(host.IPAddress, strconv.Itoa(port))
	conn, connErr := net.DialTimeout("tcp", serverConnStr, timeout)
	if connErr != nil {
		// fmt.Printf("connErr: %v\n", connErr)
		return PortCheckResult{
			Host:      host.Name,
			IPAddress: net.IPAddr{IP: net.ParseIP(host.IPAddress)},
			Port:      port,
			Open:      false,
			Err:       connErr,
		}
	}

	// explicitly disable Keep Alive in an effort to force connections to
	// stop hanging around after checking remote port
	disableKeepAliveErr := conn.(*net.TCPConn).SetKeepAlive(false)
	if disableKeepAliveErr != nil {
		return PortCheckResult{
			Host:      host.Name,
			IPAddress: net.IPAddr{IP: net.ParseIP(host.IPAddress)},
			Port:      port,
			Open:      true,
			Err:       disableKeepAliveErr,
		}
	}

	closeErr := conn.Close()
	if closeErr != nil {
		// fmt.Println("connection close error")
		return PortCheckResult{
			Host:      host.Name,
			IPAddress: net.IPAddr{IP: net.ParseIP(host.IPAddress)},
			Port:      port,
			Open:      true,
			Err:       closeErr,
		}
	}

	result := PortCheckResult{
		Host:      host.Name,
		IPAddress: net.IPAddr{IP: net.ParseIP(host.IPAddress)},
		Port:      port,
		Open:      true,
		Err:       nil,
	}

	// fmt.Println("Returning PortCheckResult:", result)

	return result

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

// GetCerts retrieves and returns the certificate chain from the specified IP
// Address & port or an error if one occurs. If specified, the given host Name
// or FQDN is included in the client's handshake to support virtual hosting
// (SNI).
//
// Enforced certificate verification is intentionally disabled in order to
// successfully retrieve and examine all certificates in the certificate
// chain.
func GetCerts(host string, ipAddr string, port int, timeout time.Duration, logger zerolog.Logger) ([]*x509.Certificate, error) {

	if strings.TrimSpace(ipAddr) == "" {
		return nil, fmt.Errorf(
			"target IP Address not specified: %w",
			ErrMissingValue,
		)
	}

	// Explicitly trim to prevent (nearly) empty string from unintentionally
	// breaking SNI support when setting TLS client configuration.
	host = strings.TrimSpace(host)

	var certChain []*x509.Certificate

	logger = logger.With().
		Str("host", host).
		Str("ip_address", ipAddr).
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

		// ServerName is included in the client's handshake to support virtual
		// hosting. Specifying the value here allows us to connect to a
		// specific IP Address while also retrieving a certificate chain for a
		// specific host value.
		ServerName: host,
	}

	// Create custom dialer with user-specified timeout value
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	serverConnStr := net.JoinHostPort(ipAddr, strconv.Itoa(port))
	conn, connErr := tls.DialWithDialer(dialer, "tcp", serverConnStr, &tlsConfig)
	if connErr != nil {
		// logger.Error().Err(connErr).Msgf("error connecting to server")
		return nil, fmt.Errorf(
			"error connecting to server (host: %s, IP: %s): %w",
			host,
			ipAddr,
			connErr,
		)
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
	s = strings.ReplaceAll(s, ".", "")
	s = strings.ReplaceAll(s, "-", "")

	_, err := strconv.Atoi(s)

	return err == nil
}

// ExpandHost accepts a host pattern as a string value that represents
// either an individual IP Address, a CIDR IP range or a partial
// (dash-separated) range (e.g., 192.168.2.10-15) and returns a collection of
// Host values. Each Host value represents the original host pattern and a
// collection of IP Addresses expanded from the original pattern.
//
// An error is returned if an invalid host pattern is provided (e.g., invalid
// IP Address range) or if it fails name resolution (e.g., invalid hostname or
// FQDN).
func ExpandHost(hostPattern string) ([]HostPattern, error) {

	expandedIPandHostValues := make([]HostPattern, 0, 1024)

	switch {

	// assume that user specified a CIDR mask
	case strings.Contains(hostPattern, "/"):

		if IsCIDR(hostPattern) {
			ipAddrs, _, err := CIDRHosts(hostPattern)
			if err != nil {
				return nil, fmt.Errorf("error parsing CIDR range: %s", err)
			}
			// fmt.Printf("%q is a CIDR rangeof %d IPs\n", s, count)
			expandedIPandHostValues = append(expandedIPandHostValues, HostPattern{
				Given:    hostPattern,
				Expanded: ipAddrs,
			},
			)

			return expandedIPandHostValues, nil
		}

		return nil, fmt.Errorf("%q contains slash, but fails CIDR parsing", hostPattern)

	// valid (presumably single) IPv4 or IPv6 address
	case net.ParseIP(hostPattern) != nil:

		// fmt.Printf("%q is an IP Address\n", s)
		expandedIPandHostValues = append(expandedIPandHostValues, HostPattern{
			Given:    hostPattern,
			Expanded: []string{hostPattern},
		},
		)

		return expandedIPandHostValues, nil

	// no CIDR mask, not a single IP Address (earlier check would have
	// triggered), and so potentially a partial range of IPv4 Addresses
	case isIPv4AddrCandidate(hostPattern) && strings.Contains(hostPattern, "."):

		octets := strings.Split(hostPattern, ".")

		if len(octets) != 4 {
			return nil, fmt.Errorf(
				"%q (%d octets) not IPv4 Address; does not contain 4 octets: %w",
				hostPattern,
				len(octets),
				ErrUnrecognizedIPAddress,
			)
		}

		// fmt.Printf("%q is a potential IP Address range\n", s)

		// reminder: at this point single IP Address was handled by earlier
		// switch case. We are either dealing with a partial range or invalid
		// value.

		// check for dash character used to specify partial IP range
		if !strings.Contains(hostPattern, "-") {
			return nil, fmt.Errorf(
				"%q not IP Address range; does not contain dash character: %w",
				hostPattern,
				ErrUnrecognizedIPRange,
			)
		}

		ipAddrOctIdx := make(IPv4AddressOctetsIndex)

		// Validate each octet of IP Address pattern.
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
							"non-numeric values present: %w",
						octets[octIdx],
						hostPattern,
						ErrUnrecognizedIPRange,
					)
				}

				if !octetWithinBounds(num) {
					return nil, fmt.Errorf(
						"octet %q of IP pattern %q outside lower (0), upper (255) bounds: %w",
						octets[octIdx],
						hostPattern,
						ErrUnrecognizedIPRange,
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
							"non-numeric values present: %w",
						octets[octIdx],
						hostPattern,
						ErrUnrecognizedIPRange,
					)
				}

				rangeEnd, err := strconv.Atoi(halves[1])
				if err != nil {
					return nil, fmt.Errorf(
						"octet %q of IP pattern %q invalid; "+
							"non-numeric values present: %w",
						octets[octIdx],
						hostPattern,
						ErrUnrecognizedIPRange,
					)
				}

				switch {
				case rangeStart > rangeEnd:
					return nil, fmt.Errorf(
						"%q is invalid octet range; "+
							"given start value %d greater than end value %d: %w",
						octets[octIdx],
						rangeStart,
						rangeEnd,
						ErrUnrecognizedIPRange,
					)

				case rangeStart == rangeEnd:
					return nil, fmt.Errorf(
						"%q is invalid octet range; "+
							"given start value %d equal to end value %d: %w",
						octets[octIdx],
						rangeStart,
						rangeEnd,
						ErrUnrecognizedIPRange,
					)
				}

				for i := rangeStart; i <= rangeEnd; i++ {
					if !octetWithinBounds(i) {
						return nil, fmt.Errorf(
							"octet %q of IP pattern %q outside lower (0), upper (255) bounds: %w",
							octets[octIdx],
							hostPattern,
							ErrUnrecognizedIPRange,
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
					"%d dash separators in octet %q (%d of %d); expected one: %w",
					numDashes,
					octIdx,
					octIdx+1,
					len(octets),
					ErrUnrecognizedIPRange,
				)
			}

		}

		// internal state validity check
		if len(ipAddrOctIdx) != len(octets) {
			return nil, fmt.Errorf(
				"ipAddress octet map size incorrect; got %d, wanted %d: %w",
				len(ipAddrOctIdx),
				len(octets),
				ErrIPAddrOctectIdxValidityFailure,
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
								"%q (from parsed range) invalid: %w",
								ipAddrString,

								// TODO: Do we need a more specific error?
								ErrUnrecognizedIPAddress,
							)
						}

						expandedIPandHostValues = append(
							expandedIPandHostValues, HostPattern{
								Given:    hostPattern,
								Expanded: []string{ipAddrString},
							},
						)
					}
				}
			}
		}

		return expandedIPandHostValues, nil

	// not a CIDR range, IP Address or partial IP Address range, so
	// potentially a hostname or FQDN (or completely invalid)
	default:

		// Attempt resolution of host pattern/string to IP Address. If
		// successful, indicate as much. The given host pattern can be used to
		// provide SNI support for valid cert retrieval (instead of just the
		// default cert on a port).
		ipAddrs, lookupErr := net.LookupHost(hostPattern)
		if lookupErr != nil {
			return nil, fmt.Errorf(
				"%q invalid; %w: %s",
				hostPattern,
				ErrHostnameFailsNameResolution,
				lookupErr.Error(),
			)
		}

		expandedIPandHostValues = append(
			expandedIPandHostValues, HostPattern{
				Given:    hostPattern,
				Expanded: ipAddrs,
				Resolved: true,
			},
		)

		return expandedIPandHostValues, nil

	}
}

// DedupeHosts accepts a collection of HostPattern values and returns an
// unordered, but deduped/unique collection of HostPattern values.
//
// NOTE: Each HostPattern value consists of the user-specified host pattern
// and a collection of IP Addresses that were expanded from the given host
// pattern. Deduping only takes place for the given host patterns, not the IP
// Addresses that the host patterns resolve to.
//
// For example, if www1.example.com and www2.example.com both resolve to the
// same IP Address both given host patterns remain after deduping. This allows
// a user to check certificate chains for specific FQDNs. Likewise, if the IP
// Address for www1.example.com and www2.example.com is given alongside those
// FQDNs (three values total) all three host patterns remain after deduping.
// This allows retrieving a default certificate chain alongside FQDN-specific
// certificate chains. This is intended to be stable behavior.
//
// However, if two IP Address ranges such as 192.168.5.10-15 and
// 192.168.5.10-20 are given, both are treated as separate values and not
// deduped. Because this is a potential source of confusion, this behavior is
// not considered stable and may change in the future.
func DedupeHosts(hosts []HostPattern) []HostPattern {
	uniqHostsIdx := make(map[string]HostPattern)
	uniqHosts := make([]HostPattern, 0, len(hosts))

	for _, host := range hosts {
		if _, inMap := uniqHostsIdx[host.Given]; !inMap {
			uniqHosts = append(uniqHosts, host)
		}
		uniqHostsIdx[host.Given] = host
	}

	return uniqHosts
}
