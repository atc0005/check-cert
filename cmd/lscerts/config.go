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

const myAppName string = "lscerts"
const myAppURL string = "https://github.com/atc0005/check-cert"

const (
	logLevelFlagHelp     string = "Sets log level to one of disabled, panic, fatal, error, warn, info, debug or trace."
	serverHelp           string = "The fully-qualified domain name of the remote system whose cert(s) will be monitored."
	portHelp             string = "TCP port of the remote certificate-enabled service. This is usually 443 (HTTPS) or 636 (LDAPS)."
	emitBrandingFlagHelp string = "Toggles emission of branding details with plugin status details. This output is disabled by default."
	emitCertTextFlagHelp string = "Toggles emission of x509 TLS certificates in an OpenSSL-inspired text format. This output is disabled by default."
	filenameFlagHelp     string = "Fully-qualified path to a file containing one or more certificates"
	ageWarningFlagHelp   string = "The number of days remaining before certificate expiration when this application will will flag the NotAfter certificate field as a WARNING state."
	ageCriticalFlagHelp  string = "The number of days remaining before certificate expiration when this application will will flag the NotAfter certificate field as a CRITICAL state."
)

// Default flag settings if not overridden by user input
const (
	defaultLogLevel     string = "info"
	defaultServer       string = ""
	defaultPort         int    = 443
	defaultEmitBranding bool   = false
	defaultEmitCertText bool   = false
	defaultFilename     string = ""

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

	// Filename is the fully-qualified path to a file containing one or more
	// certificates
	Filename string

	// Server is the fully-qualified domain name of the system running a
	// certificate-enabled service.
	Server string

	// Port is the TCP port used by the certifcate-enabled service.
	Port int

	// LoggingLevel is the supported logging level for this application.
	LoggingLevel string

	// AgeWarning is the number of days remaining before certificate
	// expiration when this application will flag the NotAfter certificate
	// field as a WARNING state.
	AgeWarning int

	// AgeWarning is the number of days remaining before certificate
	// expiration when this application will flag the NotAfter certificate
	// field as a CRITICAL state.
	AgeCritical int

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
}

// Usage is a custom override for the default Help text provided by the flag
// package. Here we prepend some additional metadata to the existing output.
var Usage = func() {
	fmt.Fprintf(flag.CommandLine.Output(), Branding())
	fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
}

// Branding emits application name, version and repo location.
func Branding() string {
	return fmt.Sprintf("\n%s (%s)\n%s\n\n", myAppName, version, myAppURL)
}

func (c *Config) handleFlagsConfig() {

	flag.StringVar(&c.Filename, "filename", defaultFilename, filenameFlagHelp)
	flag.StringVar(&c.Server, "server", defaultServer, serverHelp)
	flag.IntVar(&c.Port, "port", defaultPort, portHelp)
	flag.IntVar(&c.AgeWarning, "age-warning", defaultCertExpireAgeWarning, ageWarningFlagHelp)
	flag.IntVar(&c.AgeCritical, "age-critical", defaultCertExpireAgeCritical, ageCriticalFlagHelp)
	flag.StringVar(&c.LoggingLevel, "log-level", defaultLogLevel, logLevelFlagHelp)
	flag.BoolVar(&c.EmitBranding, "version", defaultEmitBranding, emitBrandingFlagHelp)
	flag.BoolVar(&c.EmitCertText, "text", defaultEmitCertText, emitCertTextFlagHelp)

	// Allow our function to override the default Help output
	flag.Usage = Usage

	// parse flag definitions from the argument list
	flag.Parse()

}

// Validate verifies all Config struct fields have been provided acceptable
// values.
func (c Config) Validate() error {

	// TODO: How to implement validation for optional filename using standard
	// library "flag" package (e.g., where we can't check for nil)?
	//
	// if c.Filename == "" {
	// 	return fmt.Errorf("invalid filename specified: %q", c.Filename)
	// }

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

	if c.AgeCritical < 0 {
		return fmt.Errorf(
			"invalid cert expiration CRITICAL threshold number: %d",
			c.AgeCritical,
		)
	}

	if c.AgeWarning < 0 {
		return fmt.Errorf(
			"invalid cert expiration WARNING threshold number: %d",
			c.AgeWarning,
		)
	}

	requestedLoggingLevel := strings.ToLower(c.LoggingLevel)
	if _, ok := logging.LoggingLevels[requestedLoggingLevel]; !ok {
		return fmt.Errorf("invalid logging level %q", c.LoggingLevel)
	}

	// Optimist
	return nil

}