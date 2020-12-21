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
	versionFlagHelp                  string = "Whether to display application version and then immediately exit application."
	sansEntriesFlagHelp              string = "One or many Subject Alternate Names (SANs) expected for the certificate used by the remote service. If provided, this list of comma-separated (optional) values is required for the certificate to pass validation. If the case-insensitive SKIPSANSCHECKS keyword is provided this validation will be skipped, effectively turning the use of this flag into a NOOP."
	dnsNameFlagHelp                  string = "The fully-qualified domain name of the remote system to be used for hostname verification. This option can be used for cases where make the initial connection using a name or IP not associated with the certificate."
	logLevelFlagHelp                 string = "Sets log level to one of disabled, panic, fatal, error, warn, info, debug or trace."
	serverFlagHelp                   string = "The fully-qualified domain name or IP Address of the remote system whose cert(s) will be monitored. The value provided will be validated against the Common Name and Subject Alternate Names fields."
	ipAddressesFlagHelp              string = "List of comma-separated individual IP Addresses, CIDR IP ranges or partial (dash-separated) ranges (e.g., 192.168.2.10-15) to scan for certificates."
	portFlagHelp                     string = "TCP port of the remote certificate-enabled service. This is usually 443 (HTTPS) or 636 (LDAPS)."
	portsListFlagHelp                string = "List of comma-separated TCP ports to check for certificates. If not specified, the list defaults to 443 only."
	timeoutFlagHelp                  string = "Timeout value in seconds allowed before a connection attempt to a remote certificate-enabled service (in order to retrieve the certificate) is abandoned and an error returned."
	timeoutPortScanFlagHelp          string = "The number of milliseconds before a connection attempt during a port scan is abandoned and an error returned. This timeout value is separate from the general `timeout` value used when retrieving certificates. This setting is used specifically to quickly determine port state as part of bulk operations where speed is crucial."
	portScanRateLimitFlagHelp        string = "Maximum concurrent port scans. Remaining port scans are queued until an existing scan completes."
	emitCertTextFlagHelp             string = "Toggles emission of x509 TLS certificates in an OpenSSL-inspired text format. This output is disabled by default."
	filenameFlagHelp                 string = "Fully-qualified path to a file containing one or more certificates."
	certExpireAgeWarningFlagHelp     string = "The number of days remaining before certificate expiration when this application will will flag the NotAfter certificate field as a WARNING state."
	certExpireAgeCriticalFlagHelp    string = "The number of days remaining before certificate expiration when this application will will flag the NotAfter certificate field as a CRITICAL state."
	brandingFlagHelp                 string = "Toggles emission of branding details with plugin status details. This output is disabled by default."
	showHostsWithClosedPortsFlagHelp string = "Toggles listing all host port scan results, even for hosts without any specified ports in an open state."
	showHostsWithValidCertsFlagHelp  string = "Toggles listing all cert check results in overview output, even for hosts with valid certificates."
	showValidCertsFlagHelp           string = "Toggles listing all certificates in output summary, even certificates which have passed all validity checks."
	showOverviewFlagHelp             string = "Toggles summary output view from detailed to overview."
	showPortScanResultsFlagHelp      string = "Toggles listing host port scan results."
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

	// Default timeout (in milliseconds) used when testing whether a TCP port
	// is open or closed.
	defaultPortScanTimeout = 200

	defaultPortScanRateLimit int = 100

	// For the "scanner", this flag value is required.
	// defaultCIDRRange string = ""
	// FIXME
	// Update: this is handled due to the underlying slice type which can
	// either be nil or contain content

	// the sole entry in the list of ports to be checked by the scanner
	defaultPortsListEntry int = 443

	// list port open/close scan results (false == exclude)
	defaultShowPortScanResults bool = false

	// list hosts with specified ports in closed state (false == exclude)
	defaultShowHostsWithClosedPorts bool = false

	// list hosts with valid certs (false == exclude)
	defaultShowHostsWithValidCerts bool = false

	// list valid certs in summary output (false == exclude)
	defaultShowValidCerts bool = false

	// show overview instead of detailed view (false == show detailed view)
	defaultShowOverview bool = false
)

const (
	appTypePlugin    string = "plugin"
	appTypeInspecter string = "inspecter"
	appTypeScanner   string = "scanner"
)

// limit number of IP Address "printed" by the Stringer interface to a
// human-readable number
const mvipPrintLimit int = 50
