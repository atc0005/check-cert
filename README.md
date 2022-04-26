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
  - [`certsum`](#certsum)
- [Features](#features)
- [Changelog](#changelog)
- [Requirements](#requirements)
  - [Building source code](#building-source-code)
  - [Running](#running)
- [Installation](#installation)
  - [From source](#from-source)
  - [Using release binaries](#using-release-binaries)
- [Configuration options](#configuration-options)
  - [Threshold calculations](#threshold-calculations)
  - [Command-line arguments](#command-line-arguments)
    - [`check_cert`](#check_cert)
    - [`lscert`](#lscert-1)
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

See [our GitHub repo][repo-url] for the latest code, to file an issue or
submit improvements for review and potential inclusion into the project.

## Overview

This repo contains various tools used to monitor/validate certificates.

| Tool Name     | Description                                                                                   |
| ------------- | --------------------------------------------------------------------------------------------- |
| `check_certs` | Nagios plugin used to monitor certificate chains.                                             |
| `lscert`      | Small CLI app used to generate a summary of certificate metadata and expiration status.       |
| `certsum`     | CLI app used to scan one or more given CIDR IP ranges for certs and provide a summary report. |

### `check_certs`

Nagios plugin used to monitor certificate chains. In addition to the features
shared with `lscert`, this app also validates the provided hostname against
one of the available SANs entries.

Optional support is available to skip hostname verification if a certificate
is missing SANs entries.

- in version v0.5.4 and earlier, support was available for validating a given
  hostname against the Common Name field of a certificate, regardless of
  whether SANs entries were present
  - Go 1.15 marked this support as deprecated
  - Go 1.16 noted that it would be dropped in Go 1.17
  - Go 1.17 dropped this support
- in version 0.6.0 and later, support is available (if specified) to skip
  hostname verification if a certificate is missing SANs entries

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
for the purposes of reviewing the cert details. Provide a valid FQDN as the
server name or the "dns name" if you wish to apply hostname validation.

### `certsum`

`certsum` is a cert scanner prototype. This tool is currently of "beta" level
quality; many of the exposed flags, help text and summary output are subject
to change significantly in later releases.

This tool is intended for scanning one or more given IP ranges or collection
of name/FQDN values in order to generate a report for discovered certificates.
While intended for mass discovery this tool may be used to scan as few as one
target.

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
  - needed if retrieving a non-default certificate chain
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
    - verify local certificate "bundle" or standalone leaf certificate file
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
    check command and service check where SANs list validation may not be
    desired for some certificate chains (e.g., those with a very long list of
    entries)

- Optional support for skipping hostname verification for a certificate when
  the SANs list is empty

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
  - [`logfmt`][logfmt] format output
    - to `stderr` for `check_cert`
    - to `stdout` for `lscert` & `certsum`
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

- Go
  - see this project's `go.mod` file for *preferred* version
  - this project tests against [officially supported Go
    releases][go-supported-releases]
    - the most recent stable release (aka, "stable")
    - the prior, but still supported release (aka, "oldstable")
- GCC
  - if building with custom options (as the provided `Makefile` does)
- `make`
  - if using the provided `Makefile`

### Running

- Windows 10
- Ubuntu Linux 18.04+
- Red Hat Enterprise Linux 7+

## Installation

### From source

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
     - look in `/tmp/check-cert/release_assets/certsum/`
   - if using `go build`
     - look in `/tmp/check-cert/`

### Using release binaries

1. Download the [latest
   release](https://github.com/atc0005/check-cert/releases/latest) binaries
1. Deploy
   - Place `check_cert` alongside your other Nagios plugins
     - e.g., `/usr/lib/nagios/plugins/` or `/usr/lib64/nagios/plugins/`
   - Place `lscert`, `certsum` in a location of your choice
     - e.g., `/usr/local/bin/`

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

| Flag                                          | Required | Default | Repeat | Possible                                                                | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --------------------------------------------- | -------- | ------- | ------ | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `f`, `filename`                               | No       | `false` | No     | *valid file name characters*                                            | Fully-qualified path to a PEM formatted certificate file containing one or more certificates.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `branding`                                    | No       | `false` | No     | `branding`                                                              | Toggles emission of branding details with plugin status details. This output is disabled by default.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `h`, `help`                                   | No       | `false` | No     | `h`, `help`                                                             | Show Help text along with the list of supported flags.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `v`, `verbose`                                | No       | `false` | No     | `v`, `verbose`                                                          | Toggles emission of detailed certificate metadata. This level of output is disabled by default.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `version`                                     | No       | `false` | No     | `version`                                                               | Whether to display application version and then immediately exit application.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `c`, `age-critical`                           | No       | 15      | No     | *positive whole number of days*                                         | The threshold for the certificate check's `CRITICAL` state. If the certificate expires before this number of days then the service check will be considered in a `CRITICAL` state.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `w`, `age-warning`                            | No       | 30      | No     | *positive whole number of days*                                         | The threshold for the certificate check's `WARNING` state. If the certificate expires before this number of days, but not before the `age-critical` value, then the service check will be considered in a `WARNING` state.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `ll`, `log-level`                             | No       | `info`  | No     | `disabled`, `panic`, `fatal`, `error`, `warn`, `info`, `debug`, `trace` | Log message priority filter. Log messages with a lower level are ignored.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `p`, `port`                                   | No       | `443`   | No     | *positive whole number between 1-65535, inclusive*                      | TCP port of the remote certificate-enabled service. This is usually 443 (HTTPS) or 636 (LDAPS).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `t`, `timeout`                                | No       | `10`    | No     | *positive whole number of seconds*                                      | Timeout value in seconds allowed before a connection attempt to a remote certificate-enabled service (in order to retrieve the certificate) is abandoned and an error returned.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `se`, `sans-entries`                          | No       |         | No     | *comma-separated list of values*                                        | One or many Subject Alternate Names (SANs) expected for the certificate used by the remote service. If provided, this list of comma-separated (optional) values is required for the certificate to pass validation. If the case-insensitive SKIPSANSCHECKS keyword is provided this validation will be skipped, effectively turning the use of this flag into a NOOP.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `s`, `server`                                 | **Yes**  |         | No     | *fully-qualified domain name or IP Address*                             | The fully-qualified domain name or IP Address of the remote system whose cert(s) will be monitored. This value is used to make the connection to the server in order to retrieve the certificate chain. For hosts with only a single certificate, this value is often the FQDN of the host itself, but for multi-certificate servers the user-specified value will be crucial in order to allow the remote host to select the appropriate certificate ([Server Name Indication support (SNI)](https://en.wikipedia.org/wiki/Subject_Alternative_Name)). For websites hosted on those servers, it is necessary to instead provide the FQDN of the site instead of the server hostname. For example, specify `www.example.org` instead of `host7.example.com`. Specify the site FQDN if in doubt. The user-specified value will also be validated against the Common Name and Subject Alternate Names fields *unless* the `dns-name` flag is also specified, in which case *this* value is only used for making the initial connection. |
| `dn`, `dns-name`                              | No       |         | No     | *fully-qualified domain name or IP Address*                             | The fully-qualified domain name of the remote system to be used for hostname verification. This option can be used for cases where the initial connection is made using a name or IP Address not associated with the certificate. See the `server` flag description for more information.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `disable-hostname-verification-if-empty-sans` | No       | `false` | No     | `true`, `false`                                                         | Whether hostname verification should be skipped if Subject Alternate Names (SANs) list is empty.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |

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
OK: leaf cert "www.google.com" expires next with 69d 23h remaining (until 2022-07-04 09:43:40 +0000 UTC) [EXPIRED: 0, EXPIRING: 0, OK: 3]

**ERRORS**

* None

**THRESHOLDS**

* CRITICAL: Expires before 2022-05-25 10:28:38 +0000 UTC (30 days)
* WARNING: Expires before 2022-06-14 10:28:38 +0000 UTC (50 days)

**DETAILED INFO**

3 certs found for service running on www.google.com (74.125.136.147) at port 443

Certificate 1 of 3 (leaf):
        Name: CN=www.google.com
        SANs entries: [www.google.com]
        Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        Serial: 50:69:89:19:16:59:07:17:0A:54:D0:54:F5:95:1D:3B
        Issued On: 2022-04-11 09:43:41 +0000 UTC
        Expiration: 2022-07-04 09:43:40 +0000 UTC
        Status: [OK] 69d 23h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        Serial: 02:03:BC:53:59:6B:34:C7:18:F5:01:50:66
        Issued On: 2020-08-13 00:00:42 +0000 UTC
        Expiration: 2027-09-30 00:00:42 +0000 UTC
        Status: [OK] 1983d 13h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE
        Serial: 77:BD:0D:6C:DB:36:F9:1A:EA:21:0F:C4:F0:58:D3:0D
        Issued On: 2020-06-19 00:00:42 +0000 UTC
        Expiration: 2028-01-28 00:00:42 +0000 UTC
        Status: [OK] 2103d 13h remaining
```

See the `WARNING` example output for additional details.

#### WARNING results

Here we do the same thing again, but using the expiration date values returned
earlier as a starting point, we intentionally move the threshold values in
order to trigger a `WARNING` state for the leaf certificate: if the leaf
certificate is good for 69 days and 23 hours more, we indicate that warnings
that should trigger once the cert has fewer than 70 days left.

NOTE: Use the `--verbose` flag to expose further details.

```ShellSession
$ ./check_cert --server www.google.com --port 443 --age-critical 30 --age-warning 70
5:29AM ERR cmd/check_cert/main.go:516 > expired or expiring certs present in chain error="1 certificates expired or expiring" age_critical=30 age_warning=70 app_type=plugin cert_check_timeout=10s expected_sans_entries= expired_certs=0 expiring_certs=1 filename= logging_level=info port=443 server=www.google.com version="check-cert x.y.z (https://github.com/atc0005/check-cert)"
WARNING: leaf cert "www.google.com" expires next with 69d 23h remaining (until 2022-07-04 09:43:40 +0000 UTC) [EXPIRED: 0, EXPIRING: 1, OK: 2]

**ERRORS**

* 1 certificates expired or expiring

**THRESHOLDS**

* CRITICAL: Expires before 2022-05-25 10:29:46 +0000 UTC (30 days)
* WARNING: Expires before 2022-07-04 10:29:46 +0000 UTC (70 days)

**DETAILED INFO**

3 certs found for service running on www.google.com (74.125.136.147) at port 443

Certificate 1 of 3 (leaf):
        Name: CN=www.google.com
        SANs entries: [www.google.com]
        Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        Serial: 50:69:89:19:16:59:07:17:0A:54:D0:54:F5:95:1D:3B
        Issued On: 2022-04-11 09:43:41 +0000 UTC
        Expiration: 2022-07-04 09:43:40 +0000 UTC
        Status: [WARNING] 69d 23h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        Serial: 02:03:BC:53:59:6B:34:C7:18:F5:01:50:66
        Issued On: 2020-08-13 00:00:42 +0000 UTC
        Expiration: 2027-09-30 00:00:42 +0000 UTC
        Status: [OK] 1983d 13h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE
        Serial: 77:BD:0D:6C:DB:36:F9:1A:EA:21:0F:C4:F0:58:D3:0D
        Issued On: 2020-06-19 00:00:42 +0000 UTC
        Expiration: 2028-01-28 00:00:42 +0000 UTC
        Status: [OK] 2103d 13h remaining
```

Some items to note (in order of appearance):

1. `logfmt` output providing human-readable, structured logging information
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
leaf certificate is good for 69 days and 23 hours more, we specify 90 days for
the `WARNING` threshold and 70 days for the `CRITICAL` threshold. This
triggers a `CRITICAL` state.

NOTE: Use the `--verbose` flag to expose further details.

```ShellSession
$ ./check_cert --server www.google.com --port 443 --age-critical 70 --age-warning 90
5:35AM ERR cmd/check_cert/main.go:516 > expired or expiring certs present in chain error="1 certificates expired or expiring" age_critical=70 age_warning=90 app_type=plugin cert_check_timeout=10s expected_sans_entries= expired_certs=0 expiring_certs=1 filename= logging_level=info port=443 server=www.google.com version="check-cert x.y.z (https://github.com/atc0005/check-cert)"
CRITICAL: leaf cert "www.google.com" expires next with 69d 23h remaining (until 2022-07-04 09:43:40 +0000 UTC) [EXPIRED: 0, EXPIRING: 1, OK: 2]

**ERRORS**

* 1 certificates expired or expiring

**THRESHOLDS**

* CRITICAL: Expires before 2022-07-04 10:35:46 +0000 UTC (70 days)
* WARNING: Expires before 2022-07-24 10:35:46 +0000 UTC (90 days)

**DETAILED INFO**

3 certs found for service running on www.google.com (74.125.136.106) at port 443

Certificate 1 of 3 (leaf):
        Name: CN=www.google.com
        SANs entries: [www.google.com]
        Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        Serial: 50:69:89:19:16:59:07:17:0A:54:D0:54:F5:95:1D:3B
        Issued On: 2022-04-11 09:43:41 +0000 UTC
        Expiration: 2022-07-04 09:43:40 +0000 UTC
        Status: [CRITICAL] 69d 23h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        Serial: 02:03:BC:53:59:6B:34:C7:18:F5:01:50:66
        Issued On: 2020-08-13 00:00:42 +0000 UTC
        Expiration: 2027-09-30 00:00:42 +0000 UTC
        Status: [OK] 1983d 13h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE
        Serial: 77:BD:0D:6C:DB:36:F9:1A:EA:21:0F:C4:F0:58:D3:0D
        Issued On: 2020-06-19 00:00:42 +0000 UTC
        Expiration: 2028-01-28 00:00:42 +0000 UTC
        Status: [OK] 2103d 13h remaining
```

##### Expired certificate

Here we use the expired.badssl.com subdomain to demo the results of
encountering one or more (in this case more) expired certificates in a chain.
Aside from the FQDN, all default options (including the port) are used.

NOTE: Use the `--verbose` flag to expose further details.

```ShellSession
$ ./check_cert --server expired.badssl.com
5:36AM ERR cmd/check_cert/main.go:516 > expired or expiring certs present in chain error="2 certificates expired or expiring" age_critical=15 age_warning=30 app_type=plugin cert_check_timeout=10s expected_sans_entries= expired_certs=2 expiring_certs=0 filename= logging_level=info port=443 server=expired.badssl.com version="check-cert x.y.z (https://github.com/atc0005/check-cert)"
CRITICAL: leaf cert "*.badssl.com" expired 2569d 10h ago (on 2015-04-12 23:59:59 +0000 UTC) [EXPIRED: 2, EXPIRING: 0, OK: 1]

**ERRORS**

* 2 certificates expired or expiring

**THRESHOLDS**

* CRITICAL: Expires before 2022-05-10 10:36:26 +0000 UTC (15 days)
* WARNING: Expires before 2022-05-25 10:36:26 +0000 UTC (30 days)

**DETAILED INFO**

3 certs found for service running on expired.badssl.com (104.154.89.105) at port 443

Certificate 1 of 3 (leaf):
        Name: CN=*.badssl.com,OU=Domain Control Validated+OU=PositiveSSL Wildcard
        SANs entries: [*.badssl.com badssl.com]
        Issuer: CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        Serial: 4A:E7:95:49:FA:9A:BE:3F:10:0F:17:A4:78:E1:69:09
        Issued On: 2015-04-09 00:00:00 +0000 UTC
        Expiration: 2015-04-12 23:59:59 +0000 UTC
        Status: [EXPIRED] 2569d 10h ago

Certificate 2 of 3 (intermediate):
        Name: CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        SANs entries: []
        Issuer: CN=COMODO RSA Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        Serial: 2B:2E:6E:EA:D9:75:36:6C:14:8A:6E:DB:A3:7C:8C:07
        Issued On: 2014-02-12 00:00:00 +0000 UTC
        Expiration: 2029-02-11 23:59:59 +0000 UTC
        Status: [OK] 2484d 13h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=COMODO RSA Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        SANs entries: []
        Issuer: CN=AddTrust External CA Root,OU=AddTrust External TTP Network,O=AddTrust AB,C=SE
        Serial: 27:66:EE:56:EB:49:F3:8E:AB:D7:70:A2:FC:84:DE:22
        Issued On: 2000-05-30 10:48:38 +0000 UTC
        Expiration: 2020-05-30 10:48:38 +0000 UTC
        Status: [EXPIRED] 694d 23h ago
```

### `lscert` CLI tool

#### OK results

This example shows using the CLI app to perform the same initial check that we
performed earlier using the Nagios plugin.

NOTE: Use the `--verbose` flag to expose further details.

```ShellSession
$ ./lscert --server www.google.com --port 443 --age-critical 30 --age-warning 50


=============================
CERTIFICATES | AGE THRESHOLDS
=============================

- WARNING:      Expires before 2022-06-14 10:38:35 +0000 UTC (50 days)
- CRITICAL:     Expires before 2022-05-25 10:38:35 +0000 UTC (30 days)


======================
CERTIFICATES | SUMMARY
======================

- OK: 3 certs found for service running on www.google.com (74.125.136.147) at port 443
- OK: Provided hostname matches discovered certificate
- OK: leaf cert "www.google.com" expires next with 69d 23h remaining (until 2022-07-04 09:43:40 +0000 UTC)
- OK: [EXPIRED: 0, EXPIRING: 0, OK: 3]


============================
CERTIFICATES | CHAIN DETAILS
============================

Certificate 1 of 3 (leaf):
        Name: CN=www.google.com
        SANs entries: [www.google.com]
        Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        Serial: 50:69:89:19:16:59:07:17:0A:54:D0:54:F5:95:1D:3B
        Issued On: 2022-04-11 09:43:41 +0000 UTC
        Expiration: 2022-07-04 09:43:40 +0000 UTC
        Status: [OK] 69d 23h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        Serial: 02:03:BC:53:59:6B:34:C7:18:F5:01:50:66
        Issued On: 2020-08-13 00:00:42 +0000 UTC
        Expiration: 2027-09-30 00:00:42 +0000 UTC
        Status: [OK] 1983d 13h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE
        Serial: 77:BD:0D:6C:DB:36:F9:1A:EA:21:0F:C4:F0:58:D3:0D
        Issued On: 2020-06-19 00:00:42 +0000 UTC
        Expiration: 2028-01-28 00:00:42 +0000 UTC
        Status: [OK] 2103d 13h remaining
```

#### WARNING results

NOTE: Use the `--verbose` flag to expose further details.

```ShellSession
$ ./lscert --server www.google.com --port 443 --age-critical 30 --age-warning 70


=============================
CERTIFICATES | AGE THRESHOLDS
=============================

- WARNING:      Expires before 2022-07-04 10:40:01 +0000 UTC (70 days)
- CRITICAL:     Expires before 2022-05-25 10:40:01 +0000 UTC (30 days)


======================
CERTIFICATES | SUMMARY
======================

- OK: 3 certs found for service running on www.google.com (74.125.136.147) at port 443
- OK: Provided hostname matches discovered certificate
- WARNING: leaf cert "www.google.com" expires next with 69d 23h remaining (until 2022-07-04 09:43:40 +0000 UTC)
- WARNING: [EXPIRED: 0, EXPIRING: 1, OK: 2]


============================
CERTIFICATES | CHAIN DETAILS
============================

Certificate 1 of 3 (leaf):
        Name: CN=www.google.com
        SANs entries: [www.google.com]
        Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        Serial: 50:69:89:19:16:59:07:17:0A:54:D0:54:F5:95:1D:3B
        Issued On: 2022-04-11 09:43:41 +0000 UTC
        Expiration: 2022-07-04 09:43:40 +0000 UTC
        Status: [WARNING] 69d 23h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        Serial: 02:03:BC:53:59:6B:34:C7:18:F5:01:50:66
        Issued On: 2020-08-13 00:00:42 +0000 UTC
        Expiration: 2027-09-30 00:00:42 +0000 UTC
        Status: [OK] 1983d 13h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE
        Serial: 77:BD:0D:6C:DB:36:F9:1A:EA:21:0F:C4:F0:58:D3:0D
        Issued On: 2020-06-19 00:00:42 +0000 UTC
        Expiration: 2028-01-28 00:00:42 +0000 UTC
        Status: [OK] 2103d 13h remaining
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


=============================
CERTIFICATES | AGE THRESHOLDS
=============================

- WARNING:      Expires before 2022-05-25 10:40:41 +0000 UTC (30 days)
- CRITICAL:     Expires before 2022-05-10 10:40:41 +0000 UTC (15 days)


======================
CERTIFICATES | SUMMARY
======================

- OK: 3 certs found for service running on expired.badssl.com (104.154.89.105) at port 443
- OK: Provided hostname matches discovered certificate
- CRITICAL: leaf cert "*.badssl.com" expired 2569d 10h ago (on 2015-04-12 23:59:59 +0000 UTC)
- CRITICAL: [EXPIRED: 2, EXPIRING: 0, OK: 1]


============================
CERTIFICATES | CHAIN DETAILS
============================

Certificate 1 of 3 (leaf):
        Name: CN=*.badssl.com,OU=Domain Control Validated+OU=PositiveSSL Wildcard
        SANs entries: [*.badssl.com badssl.com]
        Issuer: CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        Serial: 4A:E7:95:49:FA:9A:BE:3F:10:0F:17:A4:78:E1:69:09
        Issued On: 2015-04-09 00:00:00 +0000 UTC
        Expiration: 2015-04-12 23:59:59 +0000 UTC
        Status: [EXPIRED] 2569d 10h ago

Certificate 2 of 3 (intermediate):
        Name: CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        SANs entries: []
        Issuer: CN=COMODO RSA Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        Serial: 2B:2E:6E:EA:D9:75:36:6C:14:8A:6E:DB:A3:7C:8C:07
        Issued On: 2014-02-12 00:00:00 +0000 UTC
        Expiration: 2029-02-11 23:59:59 +0000 UTC
        Status: [OK] 2484d 13h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=COMODO RSA Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        SANs entries: []
        Issuer: CN=AddTrust External CA Root,OU=AddTrust External TTP Network,O=AddTrust AB,C=SE
        Serial: 27:66:EE:56:EB:49:F3:8E:AB:D7:70:A2:FC:84:DE:22
        Issued On: 2000-05-30 10:48:38 +0000 UTC
        Expiration: 2020-05-30 10:48:38 +0000 UTC
        Status: [EXPIRED] 694d 23h ago
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

### `certsum` CLI tool

This tool is in early development and options available are subject to change
(perhaps even significantly) in future releases.

Please see the list of available flags/options documented earlier in this
README for further options.

#### Certificates Overview

The following options generate a one-liner, high-level overview for each host
with a certificate. Hosts without a certificate are omitted from the results.

```ShellSession
$ ./certsum --hosts www.google.com,expired.badssl.com,scanme.nmap.org --show-hosts-with-valid-certs --show-overview
Beginning cert scan against 13 IPs expanded from 3 unique host patterns using ports: [443]
.......
Completed certificates scan in 371.6517ms
7 certificate chains (1 issues) found.

Results (all):

Host (Name/FQDN)        IP Addr         Port    Subject or SANs         Status  Chain Summary                           Serial
---                     ---             ---     ---                     ---     ---                                     ---
www.google.com          74.125.136.147  443     www.google.com          ✅ (OK) [EXPIRED: 0, EXPIRING: 0, OK: 3]        50:69:89:19:16:59:07:17:0A:54:D0:54:F5:95:1D:3B
www.google.com          74.125.136.99   443     www.google.com          ✅ (OK) [EXPIRED: 0, EXPIRING: 0, OK: 3]        50:69:89:19:16:59:07:17:0A:54:D0:54:F5:95:1D:3B
www.google.com          74.125.136.103  443     www.google.com          ✅ (OK) [EXPIRED: 0, EXPIRING: 0, OK: 3]        50:69:89:19:16:59:07:17:0A:54:D0:54:F5:95:1D:3B
www.google.com          74.125.136.105  443     www.google.com          ✅ (OK) [EXPIRED: 0, EXPIRING: 0, OK: 3]        50:69:89:19:16:59:07:17:0A:54:D0:54:F5:95:1D:3B
www.google.com          74.125.136.106  443     www.google.com          ✅ (OK) [EXPIRED: 0, EXPIRING: 0, OK: 3]        50:69:89:19:16:59:07:17:0A:54:D0:54:F5:95:1D:3B
www.google.com          74.125.136.104  443     www.google.com          ✅ (OK) [EXPIRED: 0, EXPIRING: 0, OK: 3]        50:69:89:19:16:59:07:17:0A:54:D0:54:F5:95:1D:3B
expired.badssl.com      104.154.89.105  443     *.badssl.com            ⛔ (!!) [EXPIRED: 2, EXPIRING: 0, OK: 1]        4A:E7:95:49:FA:9A:BE:3F:10:0F:17:A4:78:E1:69:09
```

Of note:

- implicitly use the default port of `443/tcp`
- specify multiple given host patterns (which expand to multiple IP Addresses)
- generate output in the *overview* or summary format
- show "OK" hosts alongside problem hosts (usually omitted for brevity)

#### CIDR range

```ShellSession
$ ./certsum --ports 443 --hosts 192.168.5.0/24
Beginning cert scan against 254 IPs expanded from 1 unique host patterns using ports: [443]
............
6:00AM ERR ../../mnt/t/github/check-cert/cmd/certsum/certcheck.go:234 > error fetching certificates chain error="error connecting to server (host: , IP: 192.168.5.125): read tcp 192.168.5.90:33582->192.168.5.125:443: read: connection reset by peer" age_critical=15 age_warning=30 app_timeout=30s app_type=scanner cert_check_timeout=10s filename= host= ip_address=192.168.5.125 logging_level=info port=443 port_scan_timeout=200ms ports=[443] version="check-cert x.y.z (https://github.com/atc0005/check-cert)"

6:00AM ERR ../../mnt/t/github/check-cert/cmd/certsum/certcheck.go:234 > error fetching certificates chain error="error connecting to server (host: , IP: 192.168.5.141): read tcp 192.168.5.90:57634->192.168.5.141:443: read: connection reset by peer" age_critical=15 age_warning=30 app_timeout=30s app_type=scanner cert_check_timeout=10s filename= host= ip_address=192.168.5.141 logging_level=info port=443 port_scan_timeout=200ms ports=[443] version="check-cert x.y.z (https://github.com/atc0005/check-cert)"
.....
Completed certificates scan in 1.007037835s
15 certificate chains (4 issues) found.

Results (issues only):

Host                    Port    Subject or SANs                 Status (Type)                    Summary                        Serial
---                     ---     ---                             ---                              ---                            ---
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
Beginning cert scan against 7 IPs expanded from 1 unique host patterns using ports: [443]
..
Completed certificates scan in 200.475679ms
2 certificate chains (2 issues) found.

Results (issues only):

Host                    Port    Subject or SANs                 Status (Type)                    Summary                        Serial
---                     ---     ---                             ---                              ---                            ---
192.168.5.104           443     HP Jetdirect 7FE7AF22           ⛔ (leaf; self-signed)          [EXPIRED] 3942d 12h ago         02
192.168.5.109           443     HP LaserJet M506 F2A68A         ⛔ (leaf; self-signed)          [CRITICAL] 1d 7h remaining      -29:25:F5:A8:D5:E2:FC:C3:71:77:F4:48:3A:09:2E:24:0F:0E:37:1A
```

#### Partial range and a single IP Address

```ShellSession
$ ./certsum --ports 443 --hosts 192.168.5.3,192.168.5.104-110
Beginning cert scan against 8 IPs expanded from 2 unique host patterns using ports: [443]
...
Completed certificates scan in 201.044547ms
3 certificate chains (3 issues) found.

Results (issues only):

Host                    Port    Subject or SANs                 Status (Type)                    Summary                        Serial
---                     ---     ---                             ---                              ---                            ---
192.168.5.3             443     VMware                          ⛔ (root)                       [EXPIRED] 577d 0h ago           DE:FD:50:2B:C5:7F:79:F4
192.168.5.104           443     HP Jetdirect 7FE7AF22           ⛔ (leaf; self-signed)          [EXPIRED] 3942d 12h ago         02
192.168.5.109           443     HP LaserJet M506 F2A68A         ⛔ (leaf; self-signed)          [CRITICAL] 1d 7h remaining      -29:25:F5:A8:D5:E2:FC:C3:71:77:F4:48:3A:09:2E:24:0F:0E:37:1A
```

#### Partial range, CIDR range and a single IP Address

NOTE: As of the v0.7.0 release, deduping is only applied to literal given host
patterns and not when IP ranges overlap.

For example, these given host values are deduped:

- exact IPs
  1. 192.168.5.3
  1. 192.168.5.3
- FQDNs
  1. www.example.com
  1. www.example.com
- exact IP ranges (CIDR or partial)
  1. 192.168.5.0/24
  1. 192.168.5.0/24

whereas overlap is not handled:

- 192.168.5.0/24
- 192.168.5.3
- 192.168.5.10-15

In this scenario, `192.168.5.3` will be scanned twice as would `192.168.5.11`.

```ShellSession
$ ./certsum --ports 443 --hosts 192.168.5.3,192.168.5.104-110,192.168.2.0/24
Beginning cert scan against 261 IPs expanded from 3 unique host patterns using ports: [443]
..............
```

Only the lead-in text is included as the output closely matches the other
examples.

#### Single IP Address and a FQDN

Of note:

- Default HTTPS port (because we did not specify one)
- We are using a FQDN

```ShellSession
$ ./certsum --hosts 192.168.5.3,expired.badssl.com
Beginning cert scan against 2 IPs expanded from 2 unique host patterns using ports: [443]
..
Completed certificates scan in 115.808542ms
2 certificate chains (2 issues) found.

Results (issues only):

Host (Name/FQDN)        IP Addr         Port    Subject or SANs                         Status (Type)           Summary                         Serial
---                     ---             ---     ---                                     ---                     ---                             ---
                        192.168.5.3     443     VMware                                  ⛔ (root)               [EXPIRED] 577d 0h ago           DE:FD:50:2B:C5:7F:79:F4
expired.badssl.com      104.154.89.105  443     *.badssl.com                            ⛔ (leaf)               [EXPIRED] 2570d 11h ago         4A:E7:95:49:FA:9A:BE:3F:10:0F:17:A4:78:E1:69:09
expired.badssl.com      104.154.89.105  443     COMODO RSA Certification Authority      ⛔ (intermediate)       [EXPIRED] 696d 0h ago           27:66:EE:56:EB:49:F3:8E:AB:D7:70:A2:FC:84:DE:22
```

#### Show all scan results

We include an additional scan target without a certificate to illustrate what
would normally be muted/hidden away with the default scan results.

```ShellSession
$ ./certsum --hosts 192.168.5.3,expired.badssl.com,scanme.nmap.org --show-valid-certs --show-port-scan-results --show-hosts-with-valid-certs --show-closed-ports
Beginning cert scan against 4 IPs expanded from 3 unique host patterns using ports: [443]
scanme.nmap.org (2600:3c01::f03c:91ff:fe18:bb2f): [443: false]
192.168.5.3: [443: true]
expired.badssl.com (104.154.89.105): [443: true]
scanme.nmap.org (45.33.32.156): [443: false]
Completed certificates scan in 114.645878ms
2 certificate chains (2 issues) found.

Results (all):

Host (Name/FQDN)        IP Addr         Port    Subject or SANs                                 Status (Type)           Summary                         Serial
---                     ---             ---     ---                                             ---                     ---                             ---
                        192.168.5.3     443     VMware                                          ⛔ (root)               [EXPIRED] 577d 21h ago          DE:FD:50:2B:C5:7F:79:F4
expired.badssl.com      104.154.89.105  443     *.badssl.com                                    ⛔ (leaf)               [EXPIRED] 2570d 11h ago         4A:E7:95:49:FA:9A:BE:3F:10:0F:17:A4:78:E1:69:09
expired.badssl.com      104.154.89.105  443     COMODO RSA Domain Validation Secure Server CA   ✅ (intermediate)       [OK] 2483d 12h remaining        2B:2E:6E:EA:D9:75:36:6C:14:8A:6E:DB:A3:7C:8C:07
expired.badssl.com      104.154.89.105  443     COMODO RSA Certification Authority              ⛔ (intermediate)       [EXPIRED] 696d 0h ago           27:66:EE:56:EB:49:F3:8E:AB:D7:70:A2:FC:84:DE:22
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

[go-supported-releases]: <https://go.dev/doc/devel/release#policy> "Go Release Policy"

[logfmt]: <https://brandur.org/logfmt>

<!-- []: PLACEHOLDER "DESCRIPTION_HERE" -->
