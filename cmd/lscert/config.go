// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/atc0005/check-certs/internal/logging"
)

// Updated via Makefile builds. Setting placeholder value here so that
// something resembling a version string will be provided for non-Makefile
// builds.
var version string = "x.y.z"

const myAppName string = "lscert"
const myAppURL string = "https://github.com/atc0005/check-cert"

// SkipSANSCheckKeyword is used as the sole argument to `--sans-entries` if
// the user wishes to disable SANs entry verification. This seemingly
// illogical option allows defining the `--sans-entries` flag in a command
// definition used by a group-based service check even though some systems
// targeted by that service check may use a certificate which does not have
// any SANs entries present.
const SkipSANSCheckKeyword string = "SKIPSANSCHECKS"

const (
	versionFlagHelp               string = "Whether to display application version and then immediately exit application."
	sansEntriesFlagHelp           string = "One or many Subject Alternate Names (SANs) expected for the certificate used by the remote service. If provided, this list of comma-separated (optional) values is required for the certificate to pass validation. If the case-insensitive SKIPSANSCHECKS keyword is provided this validation will be skipped, effectively turning the use of this flag into a NOOP."
	dnsNameFlagHelp               string = "The fully-qualified domain name of the remote system to be used for hostname verification. This option can be used for cases where make the initial connection using a name or IP not associated with the certificate."
	logLevelFlagHelp              string = "Sets log level to one of disabled, panic, fatal, error, warn, info, debug or trace."
	serverFlagHelp                string = "The fully-qualified domain name or IP Address of the remote system whose cert(s) will be monitored. The value provided will be validated against the Common Name and Subject Alternate Names fields."
	portFlagHelp                  string = "TCP port of the remote certificate-enabled service. This is usually 443 (HTTPS) or 636 (LDAPS)."
	timeoutFlagHelp               string = "Timeout value in seconds allowed before the connection attempt to a remote certificate-enabled service is abandoned and an error returned."
	emitCertTextFlagHelp          string = "Toggles emission of x509 TLS certificates in an OpenSSL-inspired text format. This output is disabled by default."
	filenameFlagHelp              string = "Fully-qualified path to a file containing one or more certificates."
	certExpireAgeWarningFlagHelp  string = "The number of days remaining before certificate expiration when this application will will flag the NotAfter certificate field as a WARNING state."
	certExpireAgeCriticalFlagHelp string = "The number of days remaining before certificate expiration when this application will will flag the NotAfter certificate field as a CRITICAL state."
)

// Default flag settings if not overridden by user input
const (
	defaultLogLevel              string = "info"
	defaultServer                string = ""
	defaultDNSName               string = ""
	defaultPort                  int    = 443
	defaultTimeout               int    = 10
	defaultEmitCertText          bool   = false
	defaultFilename              string = ""
	defaultDisplayVersionAndExit bool   = false

	// Default WARNING threshold is 30 days
	defaultCertExpireAgeWarning int = 30

	// Default CRITICAL threshold is 15 days
	defaultCertExpireAgeCritical int = 15
)

// var (

// 	// Default WARNING threshold is 30 days
// 	defaultCertExpireAgeWarning = time.Now().Add(time.Hour * 24 * 30)

// 	// Default CRITICAL threshold is 15 days
// 	defaultCertExpireAgeCritical = time.Now().Add(time.Hour * 24 * 15)
// )

// multiValueFlag is a custom type that satisfies the flag.Value interface in
// order to accept multiple values for some of our flags.
type multiValueFlag []string

// String returns a comma separated string consisting of all slice elements.
func (i *multiValueFlag) String() string {

	// From the `flag` package docs:
	// "The flag package may call the String method with a zero-valued
	// receiver, such as a nil pointer."
	if i == nil {
		return ""
	}

	return strings.Join(*i, ", ")
}

// Set is called once by the flag package, in command line order, for each
// flag present.
func (i *multiValueFlag) Set(value string) error {

	// split comma-separated string into multiple folders, toss whitespace
	items := strings.Split(value, ",")
	for index, item := range items {
		items[index] = strings.TrimSpace(item)
	}

	// add them to the collection
	*i = append(*i, items...)
	return nil
}

// Config represents the application configuration as specified via
// command-line flags.
type Config struct {

	// SANsEntries is the list of Subject Alternate Names (SANs) to verify are
	// present on the examined certificate. This value is provided a
	// comma-separated list.
	SANsEntries multiValueFlag

	// Filename is the fully-qualified path to a file containing one or more
	// certificates
	Filename string

	// Server is the fully-qualified domain name of the system running a
	// certificate-enabled service.
	Server string

	// DNSName is the fully-qualified domain name associated with the
	// certificate. This is usually specified when the FQDN or IP used to make
	// the connection is different than the Common Name or Subject Alternate
	// Names entries associated with the certificate.
	DNSName string

	// Port is the TCP port used by the certifcate-enabled service.
	Port int

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

	// Timeout is the number of seconds allowed before the connection attempt
	// to a remote certificate-enabled service is abandoned and an error
	// returned.
	Timeout int

	// EmitBranding controls whether "generated by" text is included at the
	// bottom of application output. This output is included in the Nagios
	// dashboard and notifications. This output may not mix well with branding
	// output from other tools such as atc0005/send2teams which also insert
	// their own branding output.
	EmitBranding bool

	// EmitCertText controls whether x509 TLS certificates are printed to
	// stdout using an OpenSSL-inspired text format. There is a good bit of
	// output text, so this setting defaults to false.
	EmitCertText bool

	// showVersion is a flag indicating whether the user opted to display only
	// the version string and then immediately exit the application
	ShowVersion bool
}

// Usage is a custom override for the default Help text provided by the flag
// package. Here we prepend some additional metadata to the existing output.
var Usage = func() {
	fmt.Fprintln(flag.CommandLine.Output(), "\n"+Version()+"\n")
	fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
}

// Version emits application name, version and repo location.
func Version() string {
	return fmt.Sprintf("%s %s (%s)", myAppName, version, myAppURL)
}

func (c *Config) handleFlagsConfig() {

	flag.Var(&c.SANsEntries, "se", sansEntriesFlagHelp)
	flag.Var(&c.SANsEntries, "sans-entries", sansEntriesFlagHelp)

	flag.IntVar(&c.AgeWarning, "w", defaultCertExpireAgeWarning, certExpireAgeWarningFlagHelp)
	flag.IntVar(&c.AgeWarning, "age-warning", defaultCertExpireAgeWarning, certExpireAgeWarningFlagHelp)

	flag.IntVar(&c.AgeCritical, "c", defaultCertExpireAgeCritical, certExpireAgeCriticalFlagHelp)
	flag.IntVar(&c.AgeCritical, "age-critical", defaultCertExpireAgeCritical, certExpireAgeCriticalFlagHelp)

	flag.StringVar(&c.Server, "s", defaultServer, serverFlagHelp)
	flag.StringVar(&c.Server, "server", defaultServer, serverFlagHelp)

	flag.StringVar(&c.DNSName, "dn", defaultDNSName, dnsNameFlagHelp)
	flag.StringVar(&c.DNSName, "dns-name", defaultDNSName, dnsNameFlagHelp)

	flag.IntVar(&c.Port, "p", defaultPort, portFlagHelp)
	flag.IntVar(&c.Port, "port", defaultPort, portFlagHelp)

	flag.IntVar(&c.Timeout, "t", defaultTimeout, timeoutFlagHelp)
	flag.IntVar(&c.Timeout, "timeout", defaultTimeout, timeoutFlagHelp)

	flag.StringVar(&c.LoggingLevel, "ll", defaultLogLevel, logLevelFlagHelp)
	flag.StringVar(&c.LoggingLevel, "log-level", defaultLogLevel, logLevelFlagHelp)

	flag.BoolVar(&c.ShowVersion, "v", defaultDisplayVersionAndExit, versionFlagHelp)
	flag.BoolVar(&c.ShowVersion, "version", defaultDisplayVersionAndExit, versionFlagHelp)

	flag.StringVar(&c.Filename, "filename", defaultFilename, filenameFlagHelp)
	flag.BoolVar(&c.EmitCertText, "text", defaultEmitCertText, emitCertTextFlagHelp)

	// Allow our function to override the default Help output
	flag.Usage = Usage

	// parse flag definitions from the argument list
	flag.Parse()

}

// Validate verifies all Config struct fields have been provided acceptable
// values.
func (c Config) Validate() error {

	// User can specify one of filename or server, but not both (mostly in
	// order to keep the logic simpler)
	switch {
	case c.Filename == "" && c.Server == "":
		return fmt.Errorf(
			"one of %q or %q flags must be specified",
			"server",
			"filename",
		)
	case c.Filename != "" && c.Server != "":
		return fmt.Errorf(
			"only one of %q or %q flags may be specified",
			"server",
			"filename",
		)
	}

	if c.Port < 0 {
		return fmt.Errorf("invalid TCP port number %d", c.Port)
	}

	if c.Timeout < 0 {
		return fmt.Errorf("invalid timeout value %d provided", c.Timeout)
	}

	if c.AgeWarning < 0 {
		return fmt.Errorf(
			"invalid cert expiration WARNING threshold number: %d",
			c.AgeWarning,
		)
	}

	if c.AgeCritical < 0 {
		return fmt.Errorf(
			"invalid cert expiration CRITICAL threshold number: %d",
			c.AgeCritical,
		)
	}

	if c.AgeCritical > c.AgeWarning {
		return fmt.Errorf(
			"critical threshold set higher than warning threshold",
		)
	}

	requestedLoggingLevel := strings.ToLower(c.LoggingLevel)
	if _, ok := logging.LoggingLevels[requestedLoggingLevel]; !ok {
		return fmt.Errorf("invalid logging level %q", c.LoggingLevel)
	}

	// Optimist
	return nil

}
