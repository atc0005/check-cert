// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package config

const myAppName string = "check-cert"
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
	brandingFlagHelp              string = "Toggles emission of branding details with plugin status details. This output is disabled by default."
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
	defaultBranding              bool   = false
	defaultDisplayVersionAndExit bool   = false

	// Default WARNING threshold is 30 days
	defaultCertExpireAgeWarning int = 30

	// Default CRITICAL threshold is 15 days
	defaultCertExpireAgeCritical int = 15
)
