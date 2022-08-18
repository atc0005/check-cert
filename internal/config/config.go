// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/atc0005/check-cert/internal/netutils"
	"github.com/atc0005/check-cert/internal/textutils"
	"github.com/rs/zerolog"
)

// Updated via Makefile builds. Setting placeholder value here so that
// something resembling a version string will be provided for non-Makefile
// builds.
var version = "x.y.z"

// ErrVersionRequested indicates that the user requested application version
// information.
var ErrVersionRequested = errors.New("version information requested")

// AppType represents the type of application that is being
// configured/initialized. Not all application types will use the same
// features and as a result will not accept the same flags. Unless noted
// otherwise, each of the application types are incompatible with each other,
// though some flags are common to all types.
type AppType struct {

	// Scanner represents an application intended for bulk operations across a
	// range of hosts.
	Scanner bool

	// Plugin represents an application used as a Nagios plugin.
	Plugin bool

	// Inspecter represents an application used for one-off or isolated
	// checks. Unlike a Nagios plugin which is focused on specific attributes
	// resulting in a severity-based outcome, an Inspecter application is
	// intended for examining a small set of targets for
	// informational/troubleshooting purposes.
	Inspecter bool
}

// multiValueStringFlag is a custom type that satisfies the flag.Value
// interface in order to accept multiple string values for some of our flags.
type multiValueStringFlag []string

// multiValueIntFlag is a custom type that satisfies the flag.Value interface
// in order to accept multiple int values (initially as strings) for some of
// our flags.
type multiValueIntFlag []int

// multiValueHostsFlag is a custom type that satisfies the flag.Value
// interface in order to accept multiple IP Addresses, hostnames or FQDNs for
// some of our flags.
type multiValueHostsFlag struct {
	// hostValues represents an original specified host pattern provided by
	// the caller and the collection of IP Addresses expanded from the
	// pattern.
	hostValues []netutils.HostPattern
}

// String returns a comma separated string consisting of all slice elements.
func (mvs *multiValueStringFlag) String() string {

	// From the `flag` package docs:
	// "The flag package may call the String method with a zero-valued
	// receiver, such as a nil pointer."
	if mvs == nil {
		return ""
	}

	return strings.Join(*mvs, ", ")
}

// String returns a comma separated string consisting of all slice elements.
func (mvi *multiValueIntFlag) String() string {

	// From the `flag` package docs:
	// "The flag package may call the String method with a zero-valued
	// receiver, such as a nil pointer."
	if mvi == nil {
		return ""
	}

	return strings.Join(textutils.IntSliceToStringSlice(*mvi), ", ")
}

// String returns a comma separated string consisting of all slice elements.
// This implementation of the Stringer interface intentionally references the
// slice of user-specified values. A separate getter method is used to
// retrieve the resolved host values.
func (mvh *multiValueHostsFlag) String() string {

	switch {

	// From the `flag` package docs:
	// "The flag package may call the String method with a zero-valued
	// receiver, such as a nil pointer."
	case mvh == nil:
		return ""

	case len(mvh.hostValues) > mvhPrintLimit:
		return fmt.Sprintf(
			"Provided host list has %d entries (skipping printing of large list)",
			len(mvh.hostValues),
		)

	default:

		givenHostPatterns := make([]string, len(mvh.hostValues))
		for i := range mvh.hostValues {
			givenHostPatterns[i] = mvh.hostValues[i].Given
		}

		return fmt.Sprintf(
			"Provided hosts list (%d entries): %v",
			len(mvh.hostValues),
			strings.Join(givenHostPatterns, ", "),
		)

	}
}

// Set is called once by the flag package, in command line order, for each
// flag present.
func (mvh *multiValueHostsFlag) Set(value string) error {

	// split comma-separated string into multiple values, toss whitespace
	items := strings.Split(value, ",")
	for index, item := range items {
		items[index] = strings.TrimSpace(item)
	}

	// convert given host patterns
	for _, givenPattern := range items {
		host, err := netutils.ExpandHost(givenPattern)
		if err != nil {
			return err
		}
		mvh.hostValues = append(mvh.hostValues, host)
	}

	return nil
}

// Set is called once by the flag package, in command line order, for each
// flag present.
func (mvi *multiValueIntFlag) Set(value string) error {

	// split comma-separated string into multiple values, toss whitespace,
	// then convert port in string format to integer for later use
	items := strings.Split(value, ",")
	for i, v := range items {
		items[i] = strings.TrimSpace(v)

		port, strConvErr := strconv.Atoi(strings.TrimSpace(v))
		if strConvErr != nil {
			return fmt.Errorf(
				"error processing flag; failed to convert string %q to int: %v",
				v,
				strConvErr,
			)
		}

		*mvi = append(*mvi, port)
	}

	return nil
}

// Set is called once by the flag package, in command line order, for each
// flag present.
func (mvs *multiValueStringFlag) Set(value string) error {

	// split comma-separated string into multiple values, toss whitespace
	items := strings.Split(value, ",")
	for index, item := range items {
		items[index] = strings.TrimSpace(item)
	}

	// add them to the collection
	*mvs = append(*mvs, items...)

	return nil
}

// Config represents the application configuration as specified via
// command-line flags.
type Config struct {

	// SANsEntries is the list of Subject Alternate Names (SANs) to verify are
	// present on the examined certificate. This value is provided as a
	// comma-separated list.
	SANsEntries multiValueStringFlag

	// Filename is the fully-qualified path to a file containing one or more
	// certificates.
	Filename string

	// Server is the fully-qualified domain name of the system running a
	// certificate-enabled service.
	Server string

	// hosts is the list of IP Addresses (single and ranges), hostnames or
	// FQDNs to scan for certs.
	hosts multiValueHostsFlag

	// ScanRateLimit is the maximum number of concurrent port scan attempts.
	ScanRateLimit int

	// DNSName is the fully-qualified domain name associated with the
	// certificate. This is usually specified when the FQDN or IP used to make
	// the connection is different than the Common Name or Subject Alternate
	// Names entries associated with the certificate.
	DNSName string

	// Port is the TCP port used by the certificate-enabled service.
	Port int

	// PortsList is the list of ports to be checked for certificates.
	portsList multiValueIntFlag

	// LoggingLevel is the supported logging level for this application.
	LoggingLevel string

	// AgeWarning is the number of days remaining before certificate
	// expiration when this application will flag the NotAfter certificate
	// field as a WARNING state.
	AgeWarning int

	// AgeCritical is the number of days remaining before certificate
	// expiration when this application will flag the NotAfter certificate
	// field as a CRITICAL state.
	AgeCritical int

	// timeout is the number of seconds allowed before the connection attempt
	// to a remote certificate-enabled service is abandoned and an error
	// returned.
	timeout int

	// timeoutPortScan is the number of milliseconds allowed before the port
	// connection attempt is abandoned and an error returned. This timeout is
	// used specifically to quickly determine port state as part of bulk
	// operations where speed is crucial.
	timeoutPortScan int

	// timeoutAppInactivity is the timeout in seconds that occurs when the
	// scanning process gets "stuck" for one reason or another (e.g., older
	// devices or systems with non-compliant TCP stacks).
	timeoutAppInactivity int

	// EmitBranding controls whether "generated by" text is included at the
	// bottom of application output. This output is included in the Nagios
	// dashboard and notifications. This output may not mix well with branding
	// output from other tools such as atc0005/send2teams which also insert
	// their own branding output.
	EmitBranding bool

	// VerboseOutput controls whether detailed certificate metadata is emitted
	// along with standard certificate details.
	VerboseOutput bool

	// EmitCertText controls whether x509 TLS certificates are printed to
	// stdout using an OpenSSL-inspired text format. There is a good bit of
	// output text, so this setting defaults to false.
	EmitCertText bool

	// ShowVersion is a flag indicating whether the user opted to display only
	// the version string and then immediately exit the application.
	ShowVersion bool

	// ShowHostsWithClosedPorts indicates whether hosts without any open ports
	// are included in the port scan results summary output.
	ShowHostsWithClosedPorts bool

	// ShowHostsWithValidCerts indicates whether hosts with valid certificates
	// are included in the overview summary output.
	ShowHostsWithValidCerts bool

	// ShowValidCerts indicates whether all certificates are included in
	// output summary, even certificates which have passed all validity
	// checks.
	ShowValidCerts bool

	// ShowOverview indicates whether a brief overview of certificate scan
	// findings is provided, or whether the detailed certificate results list
	// is shown at the end of scanning specified hosts.
	ShowOverview bool

	// ShowResultsDuringScan indicates whether host scan results should be
	// shown during a port scan. See also ShowHostsWithClosedPorts. Enabling
	// either of these options results in live scan result details being
	// shown.
	ShowPortScanResults bool

	// IgnoreHostnameVerificationFailureIfEmptySANsList indicates whether
	// hostname verification failure should be ignored if a certificate has an
	// empty SANs list.
	//
	// Go 1.17 removed support for the legacy behavior of treating the
	// CommonName field on X.509 certificates as a host name when no Subject
	// Alternative Names are present. Go 1.17 also removed support for
	// re-enabling the behavior by way of adding the value x509ignoreCN=0 to
	// the GODEBUG environment variable.
	//
	// This setting is provided in order to still allow validating a
	// certificate's expiration date for older certificates when a SANs list
	// is empty and would otherwise result in validation check results
	// failure.
	IgnoreHostnameVerificationFailureIfEmptySANsList bool

	// ListIgnoredValidationCheckResultErrors indicates whether validation
	// check result errors should be included in the final plugin report
	// output. By default, ignored errors are not included as this may prove
	// confusing (e.g., when all results are either successful or ignored).
	ListIgnoredValidationCheckResultErrors bool

	// ignoreValidationResults is a list of validation check results that
	// should be explicitly ignored and not used when determining overall
	// validation state of a certificate chain.
	ignoreValidationResults multiValueStringFlag

	// applyValidationResults is a list of validation check results that
	// should be explicitly applied when determining overall validation state
	// of a certificate chain.
	applyValidationResults multiValueStringFlag

	// Log is an embedded zerolog Logger initialized via config.New().
	Log zerolog.Logger
}

// Version emits application name, version and repo location.
func Version() string {
	return fmt.Sprintf("%s %s (%s)", myAppName, version, myAppURL)
}

// Branding accepts a message and returns a function that concatenates that
// message with version information. This function is intended to be called as
// a final step before application exit after any other output has already
// been emitted.
func Branding(msg string) func() string {
	return func() string {
		return strings.Join([]string{msg, Version()}, "")
	}
}

// New is a factory function that produces a new Config object based on user
// provided flag and config file values. It is responsible for validating
// user-provided values and initializing the logging settings used by this
// application.
func New(appType AppType) (*Config, error) {
	var config Config

	config.handleFlagsConfig(appType)

	if config.ShowVersion {
		return nil, ErrVersionRequested
	}

	if err := config.handlePositionalArgs(appType); err != nil {
		return nil, fmt.Errorf("failed to process positional arguments: %w", err)
	}

	if err := config.validate(appType); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// initialize logging just as soon as validation is complete
	if err := config.setupLogging(appType); err != nil {
		return nil, fmt.Errorf(
			"failed to set logging configuration: %w",
			err,
		)
	}

	return &config, nil

}
