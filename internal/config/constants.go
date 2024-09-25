// Copyright 2020 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package config

const myAppName string = "check-cert"
const myAppURL string = "https://github.com/atc0005/check-cert"

// SkipSANSCheckKeyword is used as the sole argument to SANsEntriesFlagLong if
// the user wishes to ignore SANs entry validation check results. This
// seemingly illogical option allows defining the SANsEntriesFlagLong flag in
// a command definition used by a group-based service check even though some
// systems targeted by that service check may use a certificate which does not
// have any SANs entries present.
const SkipSANSCheckKeyword string = "SKIPSANSCHECKS"

// ExitCodeCatchall indicates a general or miscellaneous error has occurred.
// This exit code is not directly used by monitoring plugins in this project.
// See https://tldp.org/LDP/abs/html/exitcodes.html for additional details.
const ExitCodeCatchall int = 1

const (
	versionFlagHelp                                          string = "Whether to display application version and then immediately exit application."
	sansEntriesFlagHelp                                      string = "One or many names required to be in the Subject Alternate Names (SANs) list for a leaf certificate. If provided, this list of comma-separated values is required for the certificate to pass validation. If the case-insensitive " + SkipSANSCheckKeyword + " keyword is provided the results from this validation check will be flagged as ignored."
	dnsNameFlagHelp                                          string = "A fully-qualified domain name or IP Address in the Subject Alternate Names (SANs) list for the leaf certificate. If specified, this value will be used when retrieving the certificate chain (SNI support) and for hostname verification. Required when evaluating certificate files."
	logLevelFlagHelp                                         string = "Sets log level."
	serverFlagHelp                                           string = "The fully-qualified domain name or IP Address used for certificate chain retrieval. This value should appear in the Subject Alternate Names (SANs) list for the leaf certificate unless also using the " + DNSNameFlagLong + " flag."
	hostsFlagHelp                                            string = "List of comma-separated individual IP Addresses, CIDR IP ranges, partial (dash-separated) ranges (e.g., 192.168.2.10-15), hostnames or FQDNs to scan for certificates."
	portFlagHelp                                             string = "TCP port of the remote certificate-enabled service. This is usually 443 (HTTPS) or 636 (LDAPS)."
	portsListFlagHelp                                        string = "List of comma-separated TCP ports to check for certificates. If not specified, the list defaults to 443 only."
	timeoutConnectFlagHelp                                   string = "Timeout value in seconds allowed before a connection attempt to a remote certificate-enabled service (in order to retrieve the certificate) is abandoned and an error returned."
	timeoutPortScanFlagHelp                                  string = "The number of milliseconds before a connection attempt during a port scan is abandoned and an error returned. This timeout value is separate from the general `timeout` value used when retrieving certificates. This setting is used specifically to quickly determine port state as part of bulk operations where speed is crucial."
	timeoutAppInactivityFlagHelp                             string = "The number of seconds the application is allowed to remain inactive (i.e., \"hung\") before it is automatically terminated."
	scanRateLimitFlagHelp                                    string = "Maximum concurrent port and certificate scans. Remaining scans are queued until an existing scan completes."
	emitCertTextFlagHelp                                     string = "Toggles emission of x509 TLS certificates in an OpenSSL-inspired text format. This output is disabled by default."
	filenameFlagHelp                                         string = "Fully-qualified path to a PEM formatted certificate file containing one or more certificates."
	certExpireAgeWarningFlagHelp                             string = "The number of days remaining before certificate expiration when this application will will flag the NotAfter certificate field as a WARNING state."
	certExpireAgeCriticalFlagHelp                            string = "The number of days remaining before certificate expiration when this application will will flag the NotAfter certificate field as a CRITICAL state."
	brandingFlagHelp                                         string = "Toggles emission of branding details with plugin status details. This output is disabled by default."
	verboseOutputFlagHelp                                    string = "Toggles emission of detailed certificate metadata. This level of output is disabled by default."
	showHostsWithClosedPortsFlagHelp                         string = "Toggles listing all host port scan results, even for hosts without any specified ports in an open state."
	showHostsWithValidCertsFlagHelp                          string = "Toggles listing all cert check results in overview output, even for hosts with valid certificates."
	showValidCertsFlagHelp                                   string = "Toggles listing all certificates in output summary, even certificates which have passed all validity checks."
	showOverviewFlagHelp                                     string = "Toggles summary output view from detailed to overview."
	showPortScanResultsFlagHelp                              string = "Toggles listing host port scan results."
	ignoreHostnameVerificationFailureIfEmptySANsListFlagHelp string = "Whether a hostname verification failure should be ignored if Subject Alternate Names (SANs) list is empty."
	ignoreValidationResultsFlagHelp                          string = "List of keywords for certificate chain validation check result that should be explicitly ignored and not used to determine final validation state."
	applyValidationResultsFlagHelp                           string = "List of keywords for certificate chain validation check results that should be explicitly applied and used to determine final validation state."
	listIgnoredErrorsFlagHelp                                string = "Toggles emission of ignored validation check result errors. Disabled by default to reduce confusion."
	ignoreExpiredIntermediateCertificatesFlagHelp            string = "Whether expired intermediate certificates should be ignored."
	ignoreExpiredRootCertificatesFlagHelp                    string = "Whether expired root certificates should be ignored."
	ignoreExpiringIntermediateCertificatesFlagHelp           string = "Whether expiring intermediate certificates should be ignored."
	ignoreExpiringRootCertificatesFlagHelp                   string = "Whether expiring root certificates should be ignored."
)

// shorthandFlagSuffix is appended to short flag help text to emphasize that
// the flag is a shorthand version of a longer flag.
const shorthandFlagSuffix = " (shorthand)"

// Flag names for consistent references. Exported so that they're available
// from tests.
const (
	// HelpFlagLong      string = "help"
	// HelpFlagShort     string = "h"
	// VersionFlagShort  string = "v"

	// This flag uses "ignore" wording to make clear that the validation check
	// is still applied, but the results ignored when determining overall
	// certificate chain validation state.
	IgnoreHostnameVerificationFailureIfEmptySANsListFlag string = "ignore-hostname-verification-if-empty-sans"

	IgnoreExpiredIntermediateCertificatesFlag  string = "ignore-expired-intermediate-certs"
	IgnoreExpiredRootCertificatesFlag          string = "ignore-expired-root-certs"
	IgnoreExpiringIntermediateCertificatesFlag string = "ignore-expiring-intermediate-certs"
	IgnoreExpiringRootCertificatesFlag         string = "ignore-expiring-root-certs"

	VersionFlagLong  string = "version"
	VerboseFlagLong  string = "verbose"
	VerboseFlagShort string = "v"
	BrandingFlag     string = "branding"
	ServerFlagLong   string = "server"
	ServerFlagShort  string = "s"
	PortFlagLong     string = "port"
	PortFlagShort    string = "p"
	DNSNameFlagLong  string = "dns-name"
	DNSNameFlagShort string = "dn"

	// Flags used for specifying a list of keywords used to explicitly ignore
	// or apply validation check results when determining final plugin state.
	IgnoreValidationResultFlag string = "ignore-validation-result"
	ApplyValidationResultFlag  string = "apply-validation-result"

	ListIgnoredErrorsFlag             string = "list-ignored-errors"
	FilenameFlagLong                  string = "filename"
	EmitCertTextFlagLong              string = "text"
	TimeoutFlagLong                   string = "timeout"
	TimeoutFlagShort                  string = "t"
	LogLevelFlagLong                  string = "log-level"
	LogLevelFlagShort                 string = "ll"
	TimeoutPortScanFlagLong           string = "scan-timeout"
	TimeoutPortScanFlagShort          string = "st"
	HostsFlagLong                     string = "hosts"
	HostsFlagAlt                      string = "ips"
	ScanRateLimitFlagLong             string = "scan-rate-limit"
	ScanRateLimitFlagShort            string = "srl"
	AppTimeoutFlagLong                string = "app-timeout"
	AppTimeoutFlagShort               string = "at"
	PortsFlagLong                     string = "ports"
	PortsFlagShort                    string = "p"
	ShowPortScanResultsFlagLong       string = "show-port-scan-results"
	ShowPortScanResultsFlagShort      string = "spsr"
	ShowHostsWithClosedPortsFlagLong  string = "show-closed-ports"
	ShowHostsWithClosedPortsFlagShort string = "scp"
	ShowHostsWithValidCertsFlagLong   string = "show-hosts-with-valid-certs"
	ShowHostsWithValidCertsFlagShort  string = "shwvc"
	ShowValidCertsFlagLong            string = "show-valid-certs"
	ShowValidCertsFlagShort           string = "svc"
	ShowOverviewFlagLong              string = "show-overview"
	ShowOverviewFlagShort             string = "so"
	SANsEntriesFlagLong               string = "sans-entries"
	SANsEntriesFlagShort              string = "se"
	AgeWarningFlagLong                string = "age-warning"
	AgeWarningFlagShort               string = "w"
	AgeCriticalFlagLong               string = "age-critical"
	AgeCriticalFlagShort              string = "c"
)

// Validation keywords used when explicitly ignoring or applying validation
// check results to determine final plugin state.
//
// NOTE: These need to be manually kept in sync with Flag Help Text.
const (
	ValidationKeywordExpiration string = "expiration"
	ValidationKeywordHostname   string = "hostname"
	ValidationKeywordSANsList   string = "sans"
)

// Default flag settings if not overridden by user input
const (
	defaultLogLevel              string = "info"
	defaultServer                string = ""
	defaultDNSName               string = ""
	defaultPort                  int    = 443
	defaultEmitCertText          bool   = false
	defaultFilename              string = ""
	defaultBranding              bool   = false
	defaultVerboseOutput         bool   = false
	defaultDisplayVersionAndExit bool   = false

	// Default WARNING threshold is 30 days
	defaultCertExpireAgeWarning int = 30

	// Default CRITICAL threshold is 15 days
	defaultCertExpireAgeCritical int = 15

	// Default timeout (in seconds) used when retrieving a certificate from a
	// specified TCP port previously discovered to be open.
	defaultConnectTimeout int = 10

	// Default choice of whether Go 1.17+ behavior of failing hostname
	// verification for empty SANs list should be ignored (NOTE: only applies
	// when the SANs list for a certificate is completely empty).
	defaultIgnoreHostnameVerificationIfEmptySANsList bool = false

	// Default choice of whether expired intermediate certificates should be
	// ignored.
	defaultIgnoreExpiredIntermediateCertificates bool = false

	// Default choice of whether expired root certificates should be ignored.
	defaultIgnoreExpiredRootCertificates bool = false

	// Default choice of whether expiring intermediate certificates should be
	// ignored.
	defaultIgnoreExpiringIntermediateCertificates bool = false

	// Default choice of whether expiring root certificates should be ignored.
	defaultIgnoreExpiringRootCertificates bool = false

	// Whether validation check result errors should be included in the final
	// plugin report output. By default, ignored errors are not included as
	// this may prove confusing (e.g., when all results are either successful
	// or ignored).
	defaultListIgnoredValidationCheckResultErrors bool = false

	// Whether expiration date validation check results should be applied when
	// determining overall validation state of a certificate chain by default.
	//
	// This is set based on existing behavior in prior stable releases.
	defaultApplyCertExpirationValidationResults bool = true

	// Whether hostname validation check results should be applied when
	// determining overall validation state of a certificate chain by default.
	//
	// This is set based on existing behavior in prior stable releases.
	defaultApplyCertHostnameValidationResults bool = true

	// Whether Subject Alternate Names list validation check results should be
	// applied when determining overall validation state of a certificate
	// chain by default. Requires that SANs entries also be specified.
	//
	// This is set based on existing behavior in prior stable releases.
	defaultApplyCertSANsListValidationResults bool = true
)

// Constants specific to certsum.
const (
	// Default timeout (in milliseconds) used when testing whether a TCP port
	// is open or closed.
	defaultPortScanTimeout = 200

	// defaultAppTimeout indicates the time in seconds that a sysadmin may be
	// reasonably willing to wait before forcefully terminating the
	// application after no apparent activity has occurred.
	defaultAppTimeout = 30

	// this limit is used by port scanner per-host and per-port goroutines
	// along with certificate scanner goroutines. In an effort to prevent
	// deadlocks, per-host goroutines limits are independent of per-port
	// goroutines with each type of goroutine having their own "queue" that
	// they work from.
	defaultScanRateLimit int = 100

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
	appTypeInspector string = "inspector"
	appTypeScanner   string = "scanner"
)

// limit number of IP Addresses "printed" by the Stringer interface to a
// human-readable number
const mvhPrintLimit int = 50

// TCP port ranges
// http://www.iana.org/assignments/port-numbers
// Port numbers are assigned in various ways, based on three ranges: System
// Ports (0-1023), User Ports (1024-49151), and the Dynamic and/or Private
// Ports (49152-65535)
const (
	tcpReservedPort            int = 0
	tcpSystemPortStart         int = 1
	tcpSystemPortEnd           int = 1023
	tcpUserPortStart           int = 1024
	tcpUserPortEnd             int = 49151
	tcpDynamicPrivatePortStart int = 49152
	tcpDynamicPrivatePortEnd   int = 65535
)
