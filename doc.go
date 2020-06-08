/*

This repo contains various tools used to monitor/validate certificates.

PROJECT HOME

See our GitHub repo (https://github.com/atc0005/check-cert) for the latest
code, to file an issue or submit improvements for review and potential
inclusion into the project.

PURPOSE

Monitor/validate certificates.

FEATURES

• Nagios plugin for monitoring certificates of certificate-enabled services

• CLI tool for verifying certificates of certificate-enabled services or files

USAGE - check_cert Nagios plugin

    check_cert x.y.z (https://github.com/atc0005/check-cert)

    Usage of check_cert:
    -age-critical int
            The number of days remaining before certificate expiration when Nagios will return a CRITICAL state (default 15)
    -age-warning int
            The number of days remaining before certificate expiration when Nagios will return a WARNING state (default 30)
    -branding
            Toggles emission of branding details with plugin status details. This output is disabled by default.
    -c int
            The number of days remaining before certificate expiration when Nagios will return a CRITICAL state (default 15)
    -dn string
            The fully-qualified domain name of the remote system to be used for hostname verification. This option can be used for cases where make the initial connection using a name or IP not associated with the certificate.
    -dns-name string
            The fully-qualified domain name of the remote system to be used for hostname verification. This option can be used for cases where make the initial connection using a name or IP not associated with the certificate.
    -ll string
            Sets log level to one of disabled, panic, fatal, error, warn, info, debug or trace. (default "info")
    -log-level string
            Sets log level to one of disabled, panic, fatal, error, warn, info, debug or trace. (default "info")
    -p int
            TCP port of the remote certificate-enabled service. This is usually 443 (HTTPS) or 636 (LDAPS). (default 443)
    -port int
            TCP port of the remote certificate-enabled service. This is usually 443 (HTTPS) or 636 (LDAPS). (default 443)
    -s string
            The fully-qualified domain name or IP Address of the remote system whose cert(s) will be monitored. The value provided will be validated against the Common Name and Subject Alternate Names fields.
    -sans-entries value
            One or many Subject Alternate Names (SANs) expected for the certificate used by the remote service. If provided, this list of comma-separated (optional) values is required for the certificate to pass validation. If the case-insensitive SKIPSANSCHECKS keyword is provided this validation will be skipped, effectively turning the use of this flag into a NOOP.
    -se value
            One or many Subject Alternate Names (SANs) expected for the certificate used by the remote service. If provided, this list of comma-separated (optional) values is required for the certificate to pass validation. If the case-insensitive SKIPSANSCHECKS keyword is provided this validation will be skipped, effectively turning the use of this flag into a NOOP.
    -server string
            The fully-qualified domain name or IP Address of the remote system whose cert(s) will be monitored. The value provided will be validated against the Common Name and Subject Alternate Names fields.
    -v    Whether to display application version and then immediately exit application.
    -version
            Whether to display application version and then immediately exit application.
    -w int
            The number of days remaining before certificate expiration when Nagios will return a WARNING state (default 30)

USAGE - lscert CLI tool

    lscert x.y.z (https://github.com/atc0005/check-cert)

    Usage of lscert:
    -age-critical int
            The number of days remaining before certificate expiration when this application will will flag the NotAfter certificate field as a CRITICAL state. (default 15)
    -age-warning int
            The number of days remaining before certificate expiration when this application will will flag the NotAfter certificate field as a WARNING state. (default 30)
    -c int
            The number of days remaining before certificate expiration when this application will will flag the NotAfter certificate field as a CRITICAL state. (default 15)
    -dn string
            The fully-qualified domain name of the remote system to be used for hostname verification. This option can be used for cases where make the initial connection using a name or IP not associated with the certificate.
    -dns-name string
            The fully-qualified domain name of the remote system to be used for hostname verification. This option can be used for cases where make the initial connection using a name or IP not associated with the certificate.
    -filename string
            Fully-qualified path to a file containing one or more certificates
    -ll string
            Sets log level to one of disabled, panic, fatal, error, warn, info, debug or trace. (default "info")
    -log-level string
            Sets log level to one of disabled, panic, fatal, error, warn, info, debug or trace. (default "info")
    -p int
            TCP port of the remote certificate-enabled service. This is usually 443 (HTTPS) or 636 (LDAPS). (default 443)
    -port int
            TCP port of the remote certificate-enabled service. This is usually 443 (HTTPS) or 636 (LDAPS). (default 443)
    -s string
            The fully-qualified domain name or IP Address of the remote system whose cert(s) will be monitored. The value provided will be validated against the Common Name and Subject Alternate Names fields.
    -sans-entries value
            One or many Subject Alternate Names (SANs) expected for the certificate used by the remote service. If provided, this list of comma-separated (optional) values is required for the certificate to pass validation. If the case-insensitive SKIPSANSCHECKS keyword is provided this validation will be skipped, effectively turning the use of this flag into a NOOP.
    -se value
            One or many Subject Alternate Names (SANs) expected for the certificate used by the remote service. If provided, this list of comma-separated (optional) values is required for the certificate to pass validation. If the case-insensitive SKIPSANSCHECKS keyword is provided this validation will be skipped, effectively turning the use of this flag into a NOOP.
    -server string
            The fully-qualified domain name or IP Address of the remote system whose cert(s) will be monitored. The value provided will be validated against the Common Name and Subject Alternate Names fields.
    -text
            Toggles emission of x509 TLS certificates in an OpenSSL-inspired text format. This output is disabled by default.
    -v    Whether to display application version and then immediately exit application.
    -version
            Whether to display application version and then immediately exit application.
    -w int
            The number of days remaining before certificate expiration when this application will will flag the NotAfter certificate field as a WARNING state. (default 30)


*/
package main
