<!-- omit in toc -->
# check-cert

Go-based tooling to check/verify certs (e.g., as part of a Nagios service check)

[![Latest Release](https://img.shields.io/github/release/atc0005/check-cert.svg?style=flat-square)](https://github.com/atc0005/check-cert/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/atc0005/check-cert.svg)](https://pkg.go.dev/github.com/atc0005/check-cert)
[![Validate Codebase](https://github.com/atc0005/check-cert/workflows/Validate%20Codebase/badge.svg)](https://github.com/atc0005/check-cert/actions?query=workflow%3A%22Validate+Codebase%22)
[![Validate Docs](https://github.com/atc0005/check-cert/workflows/Validate%20Docs/badge.svg)](https://github.com/atc0005/check-cert/actions?query=workflow%3A%22Validate+Docs%22)
[![Lint and Build using Makefile](https://github.com/atc0005/check-cert/workflows/Lint%20and%20Build%20using%20Makefile/badge.svg)](https://github.com/atc0005/check-cert/actions?query=workflow%3A%22Lint+and+Build+using+Makefile%22)
[![Quick Validation](https://github.com/atc0005/check-cert/workflows/Quick%20Validation/badge.svg)](https://github.com/atc0005/check-cert/actions?query=workflow%3A%22Quick+Validation%22)

<!-- omit in toc -->
## Table of Contents

- [Project home](#project-home)
- [Overview](#overview)
  - [`check_certs`](#check_certs)
  - [`lscert`](#lscert)
  - [`fixsn`](#fixsn)
  - [`certsum`](#certsum)
- [Features](#features)
- [Changelog](#changelog)
- [Requirements](#requirements)
  - [Building source code](#building-source-code)
  - [Running](#running)
- [Installation](#installation)
- [Configuration options](#configuration-options)
  - [Threshold calculations](#threshold-calculations)
  - [Command-line arguments](#command-line-arguments)
    - [`check_cert`](#check_cert)
    - [`lscert`](#lscert-1)
    - [`fixsn`](#fixsn-1)
    - [`certsum`](#certsum-1)
  - [Configuration file](#configuration-file)
- [Examples](#examples)
  - [`check_cert` Nagios plugin](#check_cert-nagios-plugin)
    - [OK results](#ok-results)
    - [WARNING results](#warning-results)
    - [CRITICAL results](#critical-results)
      - [Expiring certificate](#expiring-certificate)
      - [Expired certificate](#expired-certificate)
  - [`lscert` CLI tool](#lscert-cli-tool)
    - [OK results](#ok-results-1)
    - [WARNING results](#warning-results-1)
    - [CRITICAL results](#critical-results-1)
  - [`fixsn` CLI tool](#fixsn-cli-tool)
    - [Invalid input](#invalid-input)
    - [Expected input](#expected-input)
  - [`certsum` CLI tool](#certsum-cli-tool)
    - [Certificates Overview](#certificates-overview)
    - [CIDR range](#cidr-range)
    - [Partial range](#partial-range)
    - [Partial range and a single IP Address](#partial-range-and-a-single-ip-address)
    - [Partial range, CIDR range and a single IP Address](#partial-range-cidr-range-and-a-single-ip-address)
    - [Single IP Address and a FQDN](#single-ip-address-and-a-fqdn)
    - [Show all scan results](#show-all-scan-results)
- [License](#license)
- [References](#references)

## Project home

See [our GitHub repo](https://github.com/atc0005/check-cert) for the latest code,
to file an issue or submit improvements for review and potential inclusion
into the project.

## Overview

This repo contains various tools used to monitor/validate certificates.

| Tool Name     | Status | Description                                                                                                |
| ------------- | ------ | ---------------------------------------------------------------------------------------------------------- |
| `check_certs` | Beta   | Nagios plugin used to monitor certificate chains.                                                          |
| `lscert`      | Beta   | Small CLI app used to generate a summary of certificate metadata and expiration status.                    |
| `fixsn`       | Alpha  | Small CLI app used to convert a given base 10 serial number to base 16, colon-delimited hex string format. |
| `certsum`     | Alpha  | CLI app used to scan one or more given CIDR IP ranges for certs and provide a summary report.              |

### `check_certs`

Nagios plugin used to monitor certificate chains. In addition to the features
shared with `lscert`, this app also validates the provided hostname against
the certificate Common Name *or* one of the available SANs entries.

The output for this application is designed to provide the one-line summary
needed by Nagios for quick identification of a problem while providing longer,
more detailed information for use in email and Teams notifications
([atc0005/send2teams](https://github.com/atc0005/send2teams)).

### `lscert`

Small CLI tool for quickly reviewing the results of replacing a certificate
and/or troubleshoot why connections to a certificate-enabled service may be
failing.

Certificate metadata can be retrieved from:

- a remote service at a specified fully-qualified domain name (e.g.,
  www.github.com) or IP Address and port (e.g., 443)
- a local certificate "bundle" or standalone leaf certificate file

If specifying a host via IP Address, a warning will be emitted unless the IP
Address is in the SANs list for the certificate. This warning can be ignored
for the purposes of reviewing the cert details, Provide a valid FQDN as the
server name or the "dns name" if you wish to apply hostname validation.

### `fixsn`

A small CLI app used to convert a given (assumed) base 10 number into a base
16, colon delimited hex string representing a certificate serial number. Prior
releases of this project improperly displayed serial numbers as base 10 values
instead of base 16, colon delimited hex strings. Using this tool can be useful
for one-off conversion of older values to the proper format (e.g., a certs
list maintained in documentation).

It is likely that this tool will be either removed or folded into another tool
at a future date, unless others find it useful.

### `certsum`

`certsum` is an IP range cert scanner prototype. This tool is currently of
"alpha" level quality; many of the exposed flags, help text and summary output
are subject to change significantly in later releases.

This tool is intended for scanning one or more given IP ranges in order to
generate a report for discovered certificates, but may be used to scan as few
as one target.

Performance is likely to be acceptable as-is for smaller IP ranges, but may be
adjusted as needed using the rate limit tuning flag (see the [configuration
options](#configuration-options) section for details). The current default
value is an attempt to balance scanning speed against OS limitations on the
number of open file handles. If adjusting this value, start with small
increments to determine best results for your environment.

A default inactivity timeout is used to terminate the application if scanning
attempts stall for a specified period of time. See the [configuration
options](#configuration-options) section for details.

IP Addresses may be specified as comma-separated values:

- individual IP Addresses
- CIDR IP ranges
- partial ranges
  - using partial implementation of octet range addressing (e.g.,
    192.168.2.10-15)
- Fully-qualified domain names (FQDNs)
- Hostnames (**fragile**)
  - this is highly dependent on your DNS configuration, particularly any
    configured search list (aka, `DNS Suffix Search List` in Windows
    terminology) entries used to qualify short/hostname values

Support is present (though limited) for filtering "OK" status hosts and certs
to either increase or reduce the amount of information provided in the
generated summary output. Two summary modes are provided to control the level
of detail in the provided output.

## Features

- Multiple tools for validating certificates
  - `lscert` CLI tool
    - verify certificate used by specified service
    - verify local certificate "bundle" or standalone leaf certificate file
  - `check_cert` Nagios plugin
    - verify certificate used by specified service
  - `certsum` CLI tool
    - generate summary of discovered certificates from given hosts (single or
      IP Address ranges, hostnames or FQDNs) and ports

- Check expiration of all certificates in the *provided* certificate chain for
  cert-enabled services
  - not expired
  - expiring "soon"
    - warning threshold
    - critical threshold

- Validate provided hostname against Common Name *or* one of the available
  SANs entries (see [configuration options](#configuration-options))

- Optional support for verifying SANs entries on a certificate against a
  provided list
  - if `SKIPSANSCHECKS` keyword is supplied as the value no SANs entry checks
    will be performed; this keyword is useful for defining a shared Nagios
    check command and service check where some hosts may not use a certificate
    which has SANs entries defined

- Detailed "report" of findings
  - certificate order
  - certificate type
  - status (OK, CRITICAL, WARNING)
  - SANs entries
  - serial number
  - issuer

- Optional generation of OpenSSL-like text output from target cert-enabled
  service or filename
  - thanks to the `grantae/certinfo` package

- Optional, leveled logging using `rs/zerolog` package
  - JSON-format output (to `stderr`)
  - choice of `disabled`, `panic`, `fatal`, `error`, `warn`, `info` (the
    default), `debug` or `trace`.

- Optional, user-specified timeout value for TCP connection attempt

## Changelog

See the [`CHANGELOG.md`](CHANGELOG.md) file for the changes associated with
each release of this application. Changes that have been merged to `master`,
but not yet an official release may also be noted in the file under the
`Unreleased` section. A helpful link to the Git commit history since the last
official release is also provided for further review.

## Requirements

The following is a loose guideline. Other combinations of Go and operating
systems for building and running tools from this repo may work, but have not
been tested.

### Building source code

- Go 1.13+
- GCC
  - if building with custom options (as the provided `Makefile` does)
- `make`
  - if using the provided `Makefile`

### Running

- Windows 7, Server 2008R2 or later
  - per official [Go install notes][go-docs-install]
- Windows 10 Version 1909
  - tested
- Ubuntu Linux 16.04, 18.04

## Installation

1. [Download][go-docs-download] Go
1. [Install][go-docs-install] Go
   - NOTE: Pay special attention to the remarks about `$HOME/.profile`
1. Clone the repo
   1. `cd /tmp`
   1. `git clone https://github.com/atc0005/check-cert`
   1. `cd check-cert`
1. Install dependencies (optional)
   - for Ubuntu Linux
     - `sudo apt-get install make gcc`
   - for CentOS Linux
     - `sudo yum install make gcc`
   - for Windows
     - Emulated environments (*easier*)
       - Skip all of this and build using the default `go build` command in
         Windows (see below for use of the `-mod=vendor` flag)
       - build using Windows Subsystem for Linux Ubuntu environment and just
         copy out the Windows binaries from that environment
       - If already running a Docker environment, use a container with the Go
         tool-chain already installed
       - If already familiar with LXD, create a container and follow the
         installation steps given previously to install required dependencies
     - Native tooling (*harder*)
       - see the StackOverflow Question `32127524` link in the
         [References](references.md) section for potential options for
         installing `make` on Windows
       - see the mingw-w64 project homepage link in the
         [References](references.md) section for options for installing `gcc`
         and related packages on Windows
1. Build binaries
   - for the current operating system, explicitly using bundled dependencies
         in top-level `vendor` folder
     - `go build -mod=vendor ./cmd/check_cert/`
     - `go build -mod=vendor ./cmd/lscert/`
     - `go build -mod=vendor ./cmd/fixsn/`
     - `go build -mod=vendor ./cmd/certsum/`
   - for all supported platforms (where `make` is installed)
      - `make all`
   - for use on Windows
      - `make windows`
   - for use on Linux
     - `make linux`
1. Copy the newly compiled binary from the applicable `/tmp` subdirectory path
   (based on the clone instructions in this section) below and deploy where
   needed.
   - if using `Makefile`
     - look in `/tmp/check-cert/release_assets/check_cert/`
     - look in `/tmp/check-cert/release_assets/lscert/`
     - look in `/tmp/check-cert/release_assets/fixsn/`
     - look in `/tmp/check-cert/release_assets/certsum/`
   - if using `go build`
     - look in `/tmp/check-cert/`

## Configuration options

### Threshold calculations

The behavior of the `check_cert`plugin differs somewhat from
`check_http` `v2.1.2`; this plugin triggers a whole day
*later* than `check_http` does for the same `WARNING` and
`CRITICAL` threshold values.

For example, if we use the default values of 30 days for `WARNING` threshold
and 15 days for the `CRITICAL` threshold:

1. The thresholds are calculated
    - `WARNING`: Now (exact time in UTC) + 30 days
    - `CRITICAL`: Now (exact time in UTC) + 15 days
1. The certificate expiration date is checked and the very first match (in
   order) determines the status of the service check
    1. if the certificate expires *before* the current time, the status is
       `EXPIRED`
    1. if the certificate expires *before* the CRITICAL threshold, the status
       is `CRITICAL`
    1. if the certificate expires *before* the WARNING threshold, the status
       is `WARNING`
    1. otherwise, the certificate is assumed to have a status of `OK`

No rounding is performed.

See GH-32 for additional info.

### Command-line arguments

- Use the `-h` or `--help` flag to display current usage information.
- Flags marked as **`required`** must be set via CLI flag.
- Flags *not* marked as required are for settings where a useful default is
  already defined, but may be overridden if desired.

#### `check_cert`

| Flag                 | Required | Default | Repeat | Possible                                                                | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| -------------------- | -------- | ------- | ------ | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `branding`           | No       | `false` | No     | `branding`                                                              | Toggles emission of branding details with plugin status details. This output is disabled by default.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `h`, `help`          | No       | `false` | No     | `h`, `help`                                                             | Show Help text along with the list of supported flags.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `v`, `verbose`       | No       | `false` | No     | `v`, `verbose`                                                          | Toggles emission of detailed certificate metadata. This level of output is disabled by default.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `version`            | No       | `false` | No     | `version`                                                               | Whether to display application version and then immediately exit application.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `c`, `age-critical`  | No       | 15      | No     | *positive whole number of days*                                         | The threshold for the certificate check's `CRITICAL` state. If the certificate expires before this number of days then the service check will be considered in a `CRITICAL` state.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `w`, `age-warning`   | No       | 30      | No     | *positive whole number of days*                                         | The threshold for the certificate check's `WARNING` state. If the certificate expires before this number of days, but not before the `age-critical` value, then the service check will be considered in a `WARNING` state.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `ll`, `log-level`    | No       | `info`  | No     | `disabled`, `panic`, `fatal`, `error`, `warn`, `info`, `debug`, `trace` | Log message priority filter. Log messages with a lower level are ignored.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `p`, `port`          | No       | `443`   | No     | *positive whole number between 1-65535, inclusive*                      | TCP port of the remote certificate-enabled service. This is usually 443 (HTTPS) or 636 (LDAPS).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `t`, `timeout`       | No       | `10`    | No     | *positive whole number of seconds*                                      | Timeout value in seconds allowed before a connection attempt to a remote certificate-enabled service (in order to retrieve the certificate) is abandoned and an error returned.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `se`, `sans-entries` | No       |         | No     | *comma-separated list of values*                                        | One or many Subject Alternate Names (SANs) expected for the certificate used by the remote service. If provided, this list of comma-separated (optional) values is required for the certificate to pass validation. If the case-insensitive SKIPSANSCHECKS keyword is provided this validation will be skipped, effectively turning the use of this flag into a NOOP.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `s`, `server`        | **Yes**  |         | No     | *fully-qualified domain name or IP Address*                             | The fully-qualified domain name or IP Address of the remote system whose cert(s) will be monitored. This value is used to make the connection to the server in order to retrieve the certificate chain. For hosts with only a single certificate, this value is often the FQDN of the host itself, but for multi-certificate servers the user-specified value will be crucial in order to allow the remote host to select the appropriate certificate ([Server Name Indication support (SNI)](https://en.wikipedia.org/wiki/Subject_Alternative_Name)). For websites hosted on those servers, it is necessary to instead provide the FQDN of the site instead of the server hostname. For example, specify `www.example.org` instead of `host7.example.com`. Specify the site FQDN if in doubt. The user-specified value will also be validated against the Common Name and Subject Alternate Names fields *unless* the `dns-name` flag is also specified, in which case *this* value is only used for making the initial connection. |
| `dn`, `dns-name`     | No       |         | No     | *fully-qualified domain name or IP Address*                             | The fully-qualified domain name of the remote system to be used for hostname verification. This option can be used for cases where the initial connection is made using a name or IP Address not associated with the certificate. See the `server` flag description for more information.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

#### `lscert`

| Flag                 | Required | Default | Repeat | Possible                                                                | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| -------------------- | -------- | ------- | ------ | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `f`, `filename`      | No       | `false` | No     | *valid file name characters*                                            | Fully-qualified path to a PEM formatted certificate file containing one or more certificates.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `text`               | No       | `false` | No     | `true`, `false`                                                         | Toggles emission of x509 TLS certificates in an OpenSSL-inspired text format. This output is disabled by default.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `h`, `help`          | No       | `false` | No     | `h`, `help`                                                             | Show Help text along with the list of supported flags.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `v`, `verbose`       | No       | `false` | No     | `v`, `verbose`                                                          | Toggles emission of detailed certificate metadata. This level of output is disabled by default.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `version`            | No       | `false` | No     | `version`                                                               | Whether to display application version and then immediately exit application.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `c`, `age-critical`  | No       | 15      | No     | *positive whole number of days*                                         | The threshold for the certificate check's `CRITICAL` state. If the certificate expires before this number of days then the service check will be considered in a `CRITICAL` state.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `w`, `age-warning`   | No       | 30      | No     | *positive whole number of days*                                         | The threshold for the certificate check's `WARNING` state. If the certificate expires before this number of days, but not before the `age-critical` value, then the service check will be considered in a `WARNING` state.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `ll`, `log-level`    | No       | `info`  | No     | `disabled`, `panic`, `fatal`, `error`, `warn`, `info`, `debug`, `trace` | Log message priority filter. Log messages with a lower level are ignored.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `p`, `port`          | No       | `443`   | No     | *positive whole number between 1-65535, inclusive*                      | TCP port of the remote certificate-enabled service. This is usually 443 (HTTPS) or 636 (LDAPS).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `t`, `timeout`       | No       | `10`    | No     | *positive whole number of seconds*                                      | Timeout value in seconds allowed before a connection attempt to a remote certificate-enabled service (in order to retrieve the certificate) is abandoned and an error returned.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `se`, `sans-entries` | No       |         | No     | *comma-separated list of values*                                        | One or many Subject Alternate Names (SANs) expected for the certificate used by the remote service. If provided, this list of comma-separated (optional) values is required for the certificate to pass validation. If the case-insensitive SKIPSANSCHECKS keyword is provided this validation will be skipped, effectively turning the use of this flag into a NOOP.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `s`, `server`        | **Yes**  |         | No     | *fully-qualified domain name or IP Address*                             | The fully-qualified domain name or IP Address of the remote system whose cert(s) will be monitored. This value is used to make the connection to the server in order to retrieve the certificate chain. For hosts with only a single certificate, this value is often the FQDN of the host itself, but for multi-certificate servers the user-specified value will be crucial in order to allow the remote host to select the appropriate certificate ([Server Name Indication support (SNI)](https://en.wikipedia.org/wiki/Subject_Alternative_Name)). For websites hosted on those servers, it is necessary to instead provide the FQDN of the site instead of the server hostname. For example, specify `www.example.org` instead of `host7.example.com`. Specify the site FQDN if in doubt. The user-specified value will also be validated against the Common Name and Subject Alternate Names fields *unless* the `dns-name` flag is also specified, in which case *this* value is only used for making the initial connection. |
| `dn`, `dns-name`     | No       |         | No     | *fully-qualified domain name or IP Address*                             | The fully-qualified domain name of the remote system to be used for hostname verification. This option can be used for cases where the initial connection is made using a name or IP Address not associated with the certificate. See the `server` flag description for more information.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

#### `fixsn`

This tool does not accept any flags. Instead, it expects to receive just one
argument: a base 10 formatted certificate serial number, handled internally as
a `*big.Int` value. This value is converted to a base 16, colon-delimited hex
string. This format is common to tooling used to examine certificates.

See the [Examples](#examples) section for usage.

#### `certsum`

This tool is in early development. Options for this tool are subject to
change, perhaps even significantly, in future releases.

| Flag                                   | Required | Default | Repeat | Possible                                                                                | Description                                                                                                                                                                                                                                                                                                                                                           |
| -------------------------------------- | -------- | ------- | ------ | --------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `h`, `help`                            | No       | `false` | No     | `h`, `help`                                                                             | Show Help text along with the list of supported flags.                                                                                                                                                                                                                                                                                                                |
| `version`                              | No       | `false` | No     | `version`                                                                               | Whether to display application version and then immediately exit application.                                                                                                                                                                                                                                                                                         |
| `c`, `age-critical`                    | No       | 15      | No     | *positive whole number of days*                                                         | The threshold for the certificate check's `CRITICAL` state. If the certificate expires before this number of days then the service check will be considered in a `CRITICAL` state.                                                                                                                                                                                    |
| `w`, `age-warning`                     | No       | 30      | No     | *positive whole number of days*                                                         | The threshold for the certificate check's `WARNING` state. If the certificate expires before this number of days, but not before the `age-critical` value, then the service check will be considered in a `WARNING` state.                                                                                                                                            |
| `ll`, `log-level`                      | No       | `info`  | No     | `disabled`, `panic`, `fatal`, `error`, `warn`, `info`, `debug`, `trace`                 | Log message priority filter. Log messages with a lower level are ignored.                                                                                                                                                                                                                                                                                             |
| `t`, `timeout`                         | No       | `10`    | No     | *positive whole number of seconds*                                                      | Timeout value in seconds allowed before a connection attempt to a remote certificate-enabled service (in order to retrieve the certificate) is abandoned and an error returned.                                                                                                                                                                                       |
| `se`, `sans-entries`                   | No       |         | No     | *comma-separated list of values*                                                        | One or many Subject Alternate Names (SANs) expected for the certificate used by the remote service. If provided, this list of comma-separated (optional) values is required for the certificate to pass validation. If the case-insensitive SKIPSANSCHECKS keyword is provided this validation will be skipped, effectively turning the use of this flag into a NOOP. |
| `st`, `scan-timeout`                   | No       | 200     | No     | *positive whole number of milliseconds, minimum 1*                                      | The number of milliseconds before a connection attempt during a port scan is abandoned and an error returned. This timeout value is separate from the general `timeout` value used when retrieving certificates. This setting is used specifically to quickly determine port state as part of bulk operations where speed is crucial.                                 |
| `at`, `app-timeout`                    | No       | 30      | No     | *positive whole number of seconds, minimum 2*                                           | The number of seconds the application is allowed to remain inactive (i.e., "hung") before it is automatically terminated.                                                                                                                                                                                                                                             |
| `srl`, `scan-rate-limit`               | No       | 100     | No     | *positive whole number*                                                                 | Maximum concurrent port and certificate scans. Remaining scans are queued until an existing scan completes.                                                                                                                                                                                                                                                           |
| `ips`, `hosts`                         | No       |         | No     | *one or more valid, comma-separated IP Addresses (single or range), hostnames or FQDNs* | List of comma-separated individual IP Addresses, CIDR IP ranges, partial (dash-separated) ranges (e.g., 192.168.2.10-15), hostnames or FQDNs to scan for certificates.                                                                                                                                                                                                |
| `p`, `ports`                           | No       | 443     | No     | *one or more valid, comma-separated TCP ports*                                          | List of comma-separated TCP ports to check for certificates. If not specified, the list defaults to 443 only.                                                                                                                                                                                                                                                         |
| `spsr`, `show-port-scan-results`       | No       | `false` | No     | `true`, `false`                                                                         | Toggles listing host port scan results.                                                                                                                                                                                                                                                                                                                               |
| `scp`, `show-closed-ports`             | No       | `false` | No     | `true`, `false`                                                                         | Toggles listing all host port scan results, even for hosts without any specified ports in an open state.                                                                                                                                                                                                                                                              |
| `shwvc`, `show-hosts-with-valid-certs` | No       | `false` | No     | `true`, `false`                                                                         | Toggles listing all cert check results in overview output, even for hosts with valid certificates.                                                                                                                                                                                                                                                                    |
| `svc`, `show-valid-certs`              | No       | `false` | No     | `true`, `false`                                                                         | Toggles listing all certificates in output summary, even certificates which have passed all validity checks.                                                                                                                                                                                                                                                          |
| `so`, `show-overview`                  | No       | `false` | No     | `true`, `false`                                                                         | Toggles summary output view from detailed to overview.                                                                                                                                                                                                                                                                                                                |

### Configuration file

Not currently supported. This feature may be added later if there is
sufficient interest.

## Examples

### `check_cert` Nagios plugin

#### OK results

This example shows using the Nagios plugin to manually check a remote
certificate-enabled port on www.google.com. We override the default `WARNING`
and `CRITICAL` age threshold values with somewhat arbitrary numbers.

NOTE: Use the `--verbose` flag to expose further details.

```ShellSession
$ ./check_cert --server www.google.com --port 443 --age-critical 30 --age-warning 50
OK: leaf cert "www.google.com" expires next with 52d 16h remaining (until 2021-09-20 04:12:57 +0000 UTC) [EXPIRED: 0, EXPIRING: 0, OK: 3]

**ERRORS**

* None

**THRESHOLDS**

* CRITICAL: Expires before 2021-08-28 11:55:42 +0000 UTC (30 days)
* WARNING: Expires before 2021-09-17 11:55:42 +0000 UTC (50 days)

**DETAILED INFO**

Certificate 1 of 3 (leaf):
        Name: CN=www.google.com
        SANs entries: [www.google.com]
        Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        Serial: 12:D4:D6:BA:D3:7B:1D:D1:0A:00:00:00:00:EB:61:08
        Issued On: 2021-06-28 04:12:58 +0000 UTC
        Expiration: 2021-09-20 04:12:57 +0000 UTC
        Status: [OK] 52d 16h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        Serial: 02:03:BC:53:59:6B:34:C7:18:F5:01:50:66
        Issued On: 2020-08-13 00:00:42 +0000 UTC
        Expiration: 2027-09-30 00:00:42 +0000 UTC
        Status: [OK] 2253d 12h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE
        Serial: 77:BD:0D:6C:DB:36:F9:1A:EA:21:0F:C4:F0:58:D3:0D
        Issued On: 2020-06-19 00:00:42 +0000 UTC
        Expiration: 2028-01-28 00:00:42 +0000 UTC
        Status: [OK] 2373d 12h remaining
```

See the `WARNING` example output for additional details.

#### WARNING results

Here we do the same thing again, but using the expiration date values returned
earlier as a starting point, we intentionally move the threshold values in
order to trigger a `WARNING` state for the leaf certificate: if the leaf
certificate is good for 52 days and 16 hours more, we indicate that warnings
that should trigger once the cert has fewer than 53 days left.

NOTE: Use the `--verbose` flag to expose further details.

```ShellSession
$ ./check_c./check_cert --server www.google.com --port 443 --age-critical 30 --age-warning 53
{"level":"error","version":"check-cert v0.4.2-6-g934c303 (https://github.com/atc0005/check-cert)","logging_level":"info","app_type":"plugin","cert_check_timeout":"10s","age_warning":53,"age_critical":30,"expected_sans_entries":"","server":"www.google.com","port":443,"error":"1 certificates expired or expiring","expired_certs":0,"expiring_certs":1,"time":"2021-07-29T06:57:11-05:00","caller":"github.com/atc0005/check-cert/cmd/check_cert/main.go:241","message":"expired or expiring certs present in chain"}
WARNING: leaf cert "www.google.com" expires next with 52d 16h remaining (until 2021-09-20 04:12:57 +0000 UTC) [EXPIRED: 0, EXPIRING: 1, OK: 2]

**ERRORS**

* 1 certificates expired or expiring

**THRESHOLDS**

* CRITICAL: Expires before 2021-08-28 11:57:11 +0000 UTC (30 days)
* WARNING: Expires before 2021-09-20 11:57:11 +0000 UTC (53 days)

**DETAILED INFO**

Certificate 1 of 3 (leaf):
        Name: CN=www.google.com
        SANs entries: [www.google.com]
        Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        Serial: 12:D4:D6:BA:D3:7B:1D:D1:0A:00:00:00:00:EB:61:08
        Issued On: 2021-06-28 04:12:58 +0000 UTC
        Expiration: 2021-09-20 04:12:57 +0000 UTC
        Status: [WARNING] 52d 16h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        Serial: 02:03:BC:53:59:6B:34:C7:18:F5:01:50:66
        Issued On: 2020-08-13 00:00:42 +0000 UTC
        Expiration: 2027-09-30 00:00:42 +0000 UTC
        Status: [OK] 2253d 12h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE
        Serial: 77:BD:0D:6C:DB:36:F9:1A:EA:21:0F:C4:F0:58:D3:0D
        Issued On: 2020-06-19 00:00:42 +0000 UTC
        Expiration: 2028-01-28 00:00:42 +0000 UTC
        Status: [OK] 2373d 12h remaining
```

Some items to note (in order of appearance):

1. JSON output providing structured logging information
   - this is sent to `stderr`
   - Nagios ignores `stderr` output from plugins; `stdout` is for Nagios,
     `stderr` is for humans
1. The one-line status output on the second line
   - this is used by Nagios for display in an overview view for all service
     checkout for a host
   - this is used by Nagios for text, email and whatever else notifications
     (if configured)
1. The `ERRORS` section notes briefly what is wrong with the cert
1. The `CERTIFICATE AGE THRESHOLDS` section notes what (calculated) thresholds
   were used to determine the current service check status (results)
1. The `DETAILED INFO` section contains an overview of the certificate chain
   - this is used by Nagios for display on the detailed service check-specific
     page (e.g., shows last check time, frequency, current state, etc)
   - as for the one-line output, this is used by Nagios for text, email and
     whatever other notifications may be configured
1. The `Status` field for the leaf certificate changed from `OK` to `WARNING`
   and this plugin set the appropriate exit code to let Nagios know of the
   state change.

#### CRITICAL results

##### Expiring certificate

As with the `WARNING` example, we use the expiration date values returned from
the initial check as a starting point and intentionally move the threshold
values in order to trigger a `CRITICAL` state for the leaf certificate: if the
leaf certificate is good for 52 days and 16 hours more, we specify 90 days for
the `WARNING` threshold and 60 days for the `CRITICAL` threshold. This
triggers a `CRITICAL` state.

NOTE: Use the `--verbose` flag to expose further details.

```ShellSession
$ ./check_c./check_cert --server www.google.com --port 443 --age-critical 60 --age-warning 90
{"level":"error","version":"check-cert v0.4.2-6-g934c303 (https://github.com/atc0005/check-cert)","logging_level":"info","app_type":"plugin","cert_check_timeout":"10s","age_warning":90,"age_critical":60,"expected_sans_entries":"","server":"www.google.com","port":443,"error":"1 certificates expired or expiring","expired_certs":0,"expiring_certs":1,"time":"2021-07-29T06:58:35-05:00","caller":"github.com/atc0005/check-cert/cmd/check_cert/main.go:241","message":"expired or expiring certs present in chain"}
CRITICAL: leaf cert "www.google.com" expires next with 52d 16h remaining (until 2021-09-20 04:12:57 +0000 UTC) [EXPIRED: 0, EXPIRING: 1, OK: 2]

**ERRORS**

* 1 certificates expired or expiring

**THRESHOLDS**

* CRITICAL: Expires before 2021-09-27 11:58:35 +0000 UTC (60 days)
* WARNING: Expires before 2021-10-27 11:58:35 +0000 UTC (90 days)

**DETAILED INFO**

Certificate 1 of 3 (leaf):
        Name: CN=www.google.com
        SANs entries: [www.google.com]
        Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        Serial: 12:D4:D6:BA:D3:7B:1D:D1:0A:00:00:00:00:EB:61:08
        Issued On: 2021-06-28 04:12:58 +0000 UTC
        Expiration: 2021-09-20 04:12:57 +0000 UTC
        Status: [CRITICAL] 52d 16h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        Serial: 02:03:BC:53:59:6B:34:C7:18:F5:01:50:66
        Issued On: 2020-08-13 00:00:42 +0000 UTC
        Expiration: 2027-09-30 00:00:42 +0000 UTC
        Status: [OK] 2253d 12h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE
        Serial: 77:BD:0D:6C:DB:36:F9:1A:EA:21:0F:C4:F0:58:D3:0D
        Issued On: 2020-06-19 00:00:42 +0000 UTC
        Expiration: 2028-01-28 00:00:42 +0000 UTC
        Status: [OK] 2373d 12h remaining
```

##### Expired certificate

Here we use the expired.badssl.com subdomain to demo the results of
encountering one or more (in this case more) expired certificates in a chain.
Aside from the FQDN, all default options (including the port) are used.

NOTE: Use the `--verbose` flag to expose further details.

```ShellSession
$ ./check_cert --server expired.badssl.com
{"level":"error","version":"check-cert v0.4.2-6-g934c303 (https://github.com/atc0005/check-cert)","logging_level":"info","app_type":"plugin","cert_check_timeout":"10s","age_warning":30,"age_critical":15,"expected_sans_entries":"","server":"expired.badssl.com","port":443,"error":"2 certificates expired or expiring","expired_certs":2,"expiring_certs":0,"time":"2021-07-29T07:02:17-05:00","caller":"github.com/atc0005/check-cert/cmd/check_cert/main.go:241","message":"expired or expiring certs present in chain"}
CRITICAL: leaf cert "*.badssl.com" expired 2299d 12h ago (on 2015-04-12 23:59:59 +0000 UTC) [EXPIRED: 2, EXPIRING: 0, OK: 1]

**ERRORS**

* 2 certificates expired or expiring

**THRESHOLDS**

* CRITICAL: Expires before 2021-08-13 12:02:16 +0000 UTC (15 days)
* WARNING: Expires before 2021-08-28 12:02:16 +0000 UTC (30 days)

**DETAILED INFO**

Certificate 1 of 3 (leaf):
        Name: CN=*.badssl.com,OU=Domain Control Validated+OU=PositiveSSL Wildcard
        SANs entries: [*.badssl.com badssl.com]
        Issuer: CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        Serial: 4A:E7:95:49:FA:9A:BE:3F:10:0F:17:A4:78:E1:69:09
        Issued On: 2015-04-09 00:00:00 +0000 UTC
        Expiration: 2015-04-12 23:59:59 +0000 UTC
        Status: [EXPIRED] 2299d 12h ago

Certificate 2 of 3 (intermediate):
        Name: CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        SANs entries: []
        Issuer: CN=COMODO RSA Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        Serial: 2B:2E:6E:EA:D9:75:36:6C:14:8A:6E:DB:A3:7C:8C:07
        Issued On: 2014-02-12 00:00:00 +0000 UTC
        Expiration: 2029-02-11 23:59:59 +0000 UTC
        Status: [OK] 2754d 11h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=COMODO RSA Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        SANs entries: []
        Issuer: CN=AddTrust External CA Root,OU=AddTrust External TTP Network,O=AddTrust AB,C=SE
        Serial: 27:66:EE:56:EB:49:F3:8E:AB:D7:70:A2:FC:84:DE:22
        Issued On: 2000-05-30 10:48:38 +0000 UTC
        Expiration: 2020-05-30 10:48:38 +0000 UTC
        Status: [EXPIRED] 425d 1h ago
```

### `lscert` CLI tool

#### OK results

This example shows using the CLI app to perform the same initial check that we
performed earlier using the Nagios plugin.

NOTE: Use the `--verbose` flag to expose further details.

```ShellSession
$ ./lscert --server www.google.com --port 443 --age-critical 50 --age-warning 55

Connecting to remote server "www.google.com" at port 443


=============================
CERTIFICATES | AGE THRESHOLDS
=============================

- WARNING:      Expires before 2020-08-30 11:12:01 +0000 UTC (55 days)
- CRITICAL:     Expires before 2020-08-25 11:12:01 +0000 UTC (50 days)


======================
CERTIFICATES | SUMMARY
======================

- OK: 2 certs found for service running on www.google.com at port 443
- OK: Provided hostname matches discovered certificate
- OK: leaf cert "www.google.com" expires next with 65d 3h remaining (until 2020-09-09 14:31:22 +0000 UTC)
- OK: [EXPIRED: 0, EXPIRING: 0, OK: 2]


============================
CERTIFICATES | CHAIN DETAILS
============================

Certificate 1 of 2 (leaf):
        Name: CN=www.google.com,O=Google LLC,L=Mountain View,ST=California,C=US
        SANs entries: [www.google.com]
        Issuer: CN=GTS CA 1O1,O=Google Trust Services,C=US
        Serial: FD:6F:3E:24:98:C2:5B:1D:08:00:00:00:00:47:F0:33
        Expiration: 2020-09-09 14:31:22 +0000 UTC
        Status: [OK] 65d 3h remaining

Certificate 2 of 2 (intermediate):
        Name: CN=GTS CA 1O1,O=Google Trust Services,C=US
        SANs entries: []
        Issuer: CN=GlobalSign,OU=GlobalSign Root CA - R2,O=GlobalSign
        Serial: 01:E3:B4:9A:A1:8D:8A:A9:81:25:69:50:B8
        Expiration: 2021-12-15 00:00:42 +0000 UTC
        Status: [OK] 526d 12h remaining
```

#### WARNING results

NOTE: Use the `--verbose` flag to expose further details.

```ShellSession
$ ./lscert --server www.google.com --port 443 --age-critical 50 --age-warning 66

Connecting to remote server "www.google.com" at port 443


=============================
CERTIFICATES | AGE THRESHOLDS
=============================

- WARNING:      Expires before 2020-09-10 11:13:11 +0000 UTC (66 days)
- CRITICAL:     Expires before 2020-08-25 11:13:11 +0000 UTC (50 days)


======================
CERTIFICATES | SUMMARY
======================

- OK: 2 certs found for service running on www.google.com at port 443
- OK: Provided hostname matches discovered certificate
- WARNING: leaf cert "www.google.com" expires next with 65d 3h remaining (until 2020-09-09 14:31:22 +0000 UTC)
- WARNING: [EXPIRED: 0, EXPIRING: 1, OK: 1]


============================
CERTIFICATES | CHAIN DETAILS
============================

Certificate 1 of 2 (leaf):
        Name: CN=www.google.com,O=Google LLC,L=Mountain View,ST=California,C=US
        SANs entries: [www.google.com]
        Issuer: CN=GTS CA 1O1,O=Google Trust Services,C=US
        Serial: FD:6F:3E:24:98:C2:5B:1D:08:00:00:00:00:47:F0:33
        Expiration: 2020-09-09 14:31:22 +0000 UTC
        Status: [WARNING] 65d 3h remaining

Certificate 2 of 2 (intermediate):
        Name: CN=GTS CA 1O1,O=Google Trust Services,C=US
        SANs entries: []
        Issuer: CN=GlobalSign,OU=GlobalSign Root CA - R2,O=GlobalSign
        Serial: 01:E3:B4:9A:A1:8D:8A:A9:81:25:69:50:B8
        Expiration: 2021-12-15 00:00:42 +0000 UTC
        Status: [OK] 526d 12h remaining
```

In general, the differences between the `OK` and `WARNING` output for the two
tools is minor. However, unlike the `check_cert` Nagios plugin where we are
limited to one line of summary output, the `lscert` CLI tool doesn't share the
same output requirements and can be more expressive (e.g., such as the summary
section to highlight particular items of interest). Like the `check_cert`
Nagios plugin, the `lscert` CLI tool also displays the thresholds used to
determine the state of the checks applied to the certificate chain.

#### CRITICAL results

Here we use the expired.badssl.com subdomain to demo the results of
encountering one or more (in this case more) expired certificates in a chain.
Aside from the FQDN, all default options (including the port) are used.

NOTE: Use the `--verbose` flag to expose further details.

```ShellSession
$ ./lscert --server expired.badssl.com

Connecting to remote server "expired.badssl.com" at port 443


=============================
CERTIFICATES | AGE THRESHOLDS
=============================

- WARNING:      Expires before 2020-08-05 11:14:32 +0000 UTC (30 days)
- CRITICAL:     Expires before 2020-07-21 11:14:32 +0000 UTC (15 days)


======================
CERTIFICATES | SUMMARY
======================

- OK: 3 certs found for service running on expired.badssl.com at port 443
- OK: Provided hostname matches discovered certificate
- CRITICAL: leaf cert "*.badssl.com" expired 1911d 11h ago (on 2015-04-12 23:59:59 +0000 UTC)
- CRITICAL: [EXPIRED: 2, EXPIRING: 0, OK: 1]


============================
CERTIFICATES | CHAIN DETAILS
============================

Certificate 1 of 3 (leaf):
        Name: CN=*.badssl.com,OU=Domain Control Validated+OU=PositiveSSL Wildcard
        SANs entries: [*.badssl.com badssl.com]
        Issuer: CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        Serial: 4A:E7:95:49:FA:9A:BE:3F:10:0F:17:A4:78:E1:69:09
        Expiration: 2015-04-12 23:59:59 +0000 UTC
        Status: [EXPIRED] 1911d 11h ago

Certificate 2 of 3 (intermediate):
        Name: CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        SANs entries: []
        Issuer: CN=COMODO RSA Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        Serial: 2B:2E:6E:EA:D9:75:36:6C:14:8A:6E:DB:A3:7C:8C:07
        Expiration: 2029-02-11 23:59:59 +0000 UTC
        Status: [OK] 3142d 12h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=COMODO RSA Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        SANs entries: []
        Issuer: CN=AddTrust External CA Root,OU=AddTrust External TTP Network,O=AddTrust AB,C=SE
        Serial: 27:66:EE:56:EB:49:F3:8E:AB:D7:70:A2:FC:84:DE:22
        Expiration: 2020-05-30 10:48:38 +0000 UTC
        Status: [EXPIRED] 37d 0h ago
```

Some items to note in the `CERTIFICATES | SUMMARY` section:

- the certificate which expired first (leaf cert `*.badssl.com`) is listed
  - chain position
  - expiration summary
  - expiration date
- a quick count of the `EXPIRED`, `EXPIRING` and `OK` certificates
- future work here might list out *all* expired certs, but the assumption
  was that listing the first one to expire and then listing out the chain
  details in the following section (with explicit notes re expiration
  status) was sufficient coverage

### `fixsn` CLI tool

#### Invalid input

```ShellSession
$ ./fixsn badinput
Error: Invalid serial number (in base 10 format)
Example expected input: 336872288293767042001244177974291853363
```

#### Expected input

```ShellSession
$ ./fixsn 336872288293767042001244177974291853363
FD:6F:3E:24:98:C2:5B:1D:08:00:00:00:00:47:F0:33
```

### `certsum` CLI tool

This tool is in early development and options available are subject to change
(perhaps even significantly) in future releases.

Please see the list of available flags/options documented earlier in this
README for further options.

#### Certificates Overview

The following options generate a one-liner, high-level overview for each host
with a certificate. Hosts without a certificate are omitted from the results.

```ShellSession
$ ./certsum --hosts 192.168.5.0/24 --show-hosts-with-valid-certs --show-overview
Beginning cert scan against 254 unique hosts using ports: [443]
...................
Completed certificates scan in 2.3670248s
19 certificates (8 issues) found.

Results (all):

IP Address            Port    Subject or SANs                       Status          Chain Summary                           Serial
---                   ---     ---                                   ---             ---                                     ---
192.168.5.22          443     VMware                                ⛔ (!!)         [EXPIRED: 1, EXPIRING: 0, OK: 0]        92:4A:AD:38:3C:DC:C1:B6
192.168.5.3           443     VMware                                ⛔ (!!)         [EXPIRED: 1, EXPIRING: 0, OK: 0]        DE:FD:50:2B:C5:7F:79:F4
192.168.5.24          443     VMware                                ✅ (OK)         [EXPIRED: 0, EXPIRING: 0, OK: 1]        9A:DF:A1:A6:60:16:4E:C0
192.168.5.11          443     VMware                                ⛔ (!!)         [EXPIRED: 1, EXPIRING: 0, OK: 0]        8D:2C:61:CF:AE:57:58:98
192.168.5.83          443     HP Jetdirect 4639304E                 ⛔ (!!)         [EXPIRED: 1, EXPIRING: 0, OK: 0]        47:F0:56:50
192.168.5.109         443     HP LaserJet M506 F2A68A               ⛔ (!!)         [EXPIRED: 1, EXPIRING: 0, OK: 0]        -29:25:F5:A8:D5:E2:FC:C3:71:77:F4:48:3A:09:2E:24:0F:0E:37:1A
192.168.5.93          443     NPI25BC25                             ✅ (OK)         [EXPIRED: 0, EXPIRING: 0, OK: 1]        -61:CE:BD:13
192.168.5.113         443     NPI253CDE                             ✅ (OK)         [EXPIRED: 0, EXPIRING: 0, OK: 1]        38:BC:BD:21
192.168.5.136         443     HP Jetdirect BAC74492                 ✅ (OK)         [EXPIRED: 0, EXPIRING: 0, OK: 1]        20:46:94:C0
192.168.5.104         443     HP Jetdirect 7FE7AF22                 ⛔ (!!)         [EXPIRED: 1, EXPIRING: 0, OK: 0]        02
192.168.5.165         443     192.168.5.165                         ⛔ (!!)         [EXPIRED: 1, EXPIRING: 0, OK: 0]        EF:E5:A3:0E:2F:FA:C1:3A
192.168.5.183         443     192.168.5.183                         ⛔ (!!)         [EXPIRED: 1, EXPIRING: 0, OK: 0]        F7:A2:CD:4A:F2:A0:63:10
192.168.5.182         443     192.168.5.182                         ✅ (OK)         [EXPIRED: 0, EXPIRING: 0, OK: 1]        AC:53:68:BB:38:5E:5A:6C
192.168.5.105         443     192.168.5.105                         ✅ (OK)         [EXPIRED: 0, EXPIRING: 0, OK: 1]        64:36:33:33:32:36:37:38:30:31:64:66:37:31:31:62:32:62:37:63
```

Of note:

- implicitly use the default port of `443/tcp`
- scan the entire `192.168.5.0/24` range
- generate output in the *overview* or summary format
- show "OK" hosts alongside problem hosts (usually omitted for brevity)

#### CIDR range

```ShellSession
$ ./certsum --ports 443 --hosts 192.168.5.0/24
Total IPs from all ranges before deduping: 254
Total IPs from all ranges after deduping: 254
Beginning scan of ports: [443]
Completed port scan
Beginning certificate analysis
..........................
Completed certificate analysis

Results:

IP Address              Port    Subject or SANs                 Status (Type)                   Summary                         Serial
---                     ---     ---                             ---                             ---                             ---
192.168.5.104           443     HP Jetdirect 7FE7AF22           ⛔ (leaf; self-signed)          [EXPIRED] 3942d 12h ago         02
192.168.5.3             443     VMware                          ⛔ (root)                       [EXPIRED] 571d 23h ago          DE:FD:50:2B:C5:7F:79:F4
192.168.5.109           443     HP LaserJet M506 F2A68A         ⛔ (leaf; self-signed)          [CRITICAL] 1d 7h remaining      -29:25:F5:A8:D5:E2:FC:C3:71:77:F4:48:3A:09:2E:24:0F:0E:37:1A
192.168.5.83            443     HP Jetdirect 4639304E           ⛔ (leaf; self-signed)          [EXPIRED] 2175d 12h ago         47:F0:56:50
192.168.5.165           443     192.168.5.165                   ⛔ (leaf; self-signed)          [EXPIRED] 1519d 7h ago          EF:E5:A3:0E:2F:FA:C1:3A
192.168.5.183           443     192.168.5.183                   ⛔ (leaf; self-signed)          [EXPIRED] 1034d 19h ago         F7:A2:CD:4A:F2:A0:63:10
```

Of note:

- explicitly specify port `443/tcp` (the default)
- scan the entire `192.168.5.0/24` range
- only emit "problem" entries

#### Partial range

Here we specify a partial range using a syntax intentionally similar to the
*octet based addressing* syntax accepted by [nmap](https://nmap.org/) (an
amazing tool). Commas within an octet (in order to exclude IPs) are not
supported at this time.

```ShellSession
$ ./certsum --ports 443 --hosts 192.168.5.104-110
Total IPs from all ranges before deduping: 6
Total IPs from all ranges after deduping: 6
Beginning scan of ports: [443]
Completed port scan
Beginning certificate analysis
..........................
Completed certificate analysis

Results:

IP Address              Port    Subject or SANs                 Status (Type)                   Summary                         Serial
---                     ---     ---                             ---                             ---                             ---
192.168.5.104           443     HP Jetdirect 7FE7AF22           ⛔ (leaf; self-signed)          [EXPIRED] 3942d 12h ago         02
192.168.5.109           443     HP LaserJet M506 F2A68A         ⛔ (leaf; self-signed)          [CRITICAL] 1d 7h remaining      -29:25:F5:A8:D5:E2:FC:C3:71:77:F4:48:3A:09:2E:24:0F:0E:37:1A
```

#### Partial range and a single IP Address

```ShellSession
$ ./certsum --ports 443 --hosts 192.168.5.3,192.168.5.104-110
Total IPs from all ranges before deduping: 7
Total IPs from all ranges after deduping: 7
Beginning scan of ports: [443]
Completed port scan
Beginning certificate analysis
..........................
Completed certificate analysis

Results:

IP Address              Port    Subject or SANs                 Status (Type)                   Summary                         Serial
---                     ---     ---                             ---                             ---                             ---
192.168.5.3             443     VMware                          ⛔ (root)                       [EXPIRED] 577d 0h ago           DE:FD:50:2B:C5:7F:79:F4
192.168.5.104           443     HP Jetdirect 7FE7AF22           ⛔ (leaf; self-signed)          [EXPIRED] 3942d 12h ago         02
192.168.5.109           443     HP LaserJet M506 F2A68A         ⛔ (leaf; self-signed)          [CRITICAL] 1d 7h remaining      -29:25:F5:A8:D5:E2:FC:C3:71:77:F4:48:3A:09:2E:24:0F:0E:37:1A
```

#### Partial range, CIDR range and a single IP Address

```ShellSession
$ ./certsum --ports 443 --hosts 192.168.5.3,192.168.5.104-110,192.168.2.0/24
Total IPs from all ranges before deduping: 260
Total IPs from all ranges after deduping: 260
Beginning scan of ports: [443]
Completed port scan
Beginning certificate analysis
...............................................................
```

Only the lead-in text is included as the output closely matches the other
examples.

#### Single IP Address and a FQDN

Of note:

- Default HTTPS port (because we did not specify one)
- We are using a FQDN

```ShellSession
$ ./certsum --hosts 192.168.5.3,expired.badssl.com
Total IPs from all ranges before deduping: 2
Total IPs from all ranges after deduping: 2
Beginning scan of ports: [443]
Completed port scan
Beginning certificate analysis
..
Completed certificate analysis

Results:

IP Address              Port    Subject or SANs                                 Status (Type)           Summary                         Serial
---                     ---     ---                                             ---                     ---                             ---
192.168.5.3             443     VMware                                          ⛔ (root)               [EXPIRED] 577d 0h ago           DE:FD:50:2B:C5:7F:79:F4
104.154.89.105          443     badssl-fallback-unknown-subdomain-or-no-sni     ⛔ (leaf)               [EXPIRED] 865d 13h ago          CD:BC:5A:4A:EC:97:67:B1
```

#### Show all scan results

We include an additional scan target without a certificate to illustrate what
would normally be muted/hidden away with the default scan results.

```ShellSession
$ ./certsum --hosts 192.168.5.3,expired.badssl.com,scanme.nmap.org --show-valid-certs --show-port-scan-results --show-hosts-with-valid-certs --show-closed-ports
Total IPs from all ranges before deduping: 4
Total IPs from all ranges after deduping: 4
Beginning scan of ports: [443]
Completed port scan
Beginning certificate analysis
192.168.5.3: [443: true]
104.154.89.105: [443: true]
45.33.32.156: [None]
2600:3c01::f03c:91ff:fe18:bb2f: [None]
Completed certificate analysis

Results:

IP Address              Port    Subject or SANs                                 Status (Type)           Summary                         Serial
---                     ---     ---                                             ---                     ---                             ---
192.168.5.3             443     VMware                                          ⛔ (root)               [EXPIRED] 577d 21h ago          DE:FD:50:2B:C5:7F:79:F4
104.154.89.105          443     badssl-fallback-unknown-subdomain-or-no-sni     ⛔ (leaf)               [EXPIRED] 865d 13h ago          CD:BC:5A:4A:EC:97:67:B1
```

## License

From the [LICENSE](LICENSE) file:

```license
MIT License

Copyright (c) 2020 Adam Chalkley

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## References

- <https://github.com/grantae/certinfo>
- <https://github.com/rs/zerolog>
- <https://github.com/atc0005/go-nagios>
- <https://nagios-plugins.org/doc/guidelines.html>

- nmap "octet range addressing"
  - <https://nmap.org/book/man-target-specification.html>

- badssl.com
  - <https://github.com/chromium/badssl.com>
  - <https://expired.badssl.com/>
    - useful test target to demo output of tools, confirm expiration
      validation works as intended

- <https://utcc.utoronto.ca/~cks/space/blog/tech/TLSHowMultipleChains>
  - good overview of the AddTrust Root CA expiration of 2020
  - *As a practical matter, monitoring the expiry time of all certificates
    provided by a TLS server seems very likely to be enough to detect multiple
    chain problems such as the AddTrust issue. Competent Certificate
    Authorities shouldn't issue server or intermediate certificates with
    expiry times later than their root (or intermediate) certificates, so we
    don't need to try to find and explicitly check those root certificates.
    This will also alert on expiring certificates that were provided but that
    can't be used to construct any chain, but you probably want to get rid of
    those anyway.*

<!-- Footnotes here  -->

[repo-url]: <https://github.com/atc0005/check-cert>  "This project's GitHub repo"

[go-docs-download]: <https://golang.org/dl>  "Download Go"

[go-docs-install]: <https://golang.org/doc/install>  "Install Go"

<!-- []: PLACEHOLDER "DESCRIPTION_HERE" -->
