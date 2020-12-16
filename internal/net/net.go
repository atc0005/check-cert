// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package net

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

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

// Hosts converts a CIDR network pattern into a slice of hosts within that
// network, the total count of hosts and an error if any occurred.
//
// https://stackoverflow.com/questions/60540465/go-how-to-list-all-ips-in-a-network
// https://play.golang.org/p/fe-F2k6prlA
// https://gist.github.com/kotakanbe/d3059af990252ba89a82
func Hosts(cidr string) ([]string, int, error) {
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
