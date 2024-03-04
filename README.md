<!-- omit in toc -->
# check-cert

Go-based tooling to check/verify certs (e.g., as part of a Nagios service check)

[![Latest Release](https://img.shields.io/github/release/atc0005/check-cert.svg?style=flat-square)](https://github.com/atc0005/check-cert/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/atc0005/check-cert.svg)](https://pkg.go.dev/github.com/atc0005/check-cert)
[![go.mod Go version](https://img.shields.io/github/go-mod/go-version/atc0005/check-cert)](https://github.com/atc0005/check-cert)
[![Lint and Build](https://github.com/atc0005/check-cert/actions/workflows/lint-and-build.yml/badge.svg)](https://github.com/atc0005/check-cert/actions/workflows/lint-and-build.yml)
[![Project Analysis](https://github.com/atc0005/check-cert/actions/workflows/project-analysis.yml/badge.svg)](https://github.com/atc0005/check-cert/actions/workflows/project-analysis.yml)

<!-- omit in toc -->
## Table of Contents

- [Project home](#project-home)
- [Overview](#overview)
  - [`check_certs`](#check_certs)
    - [Performance Data](#performance-data)
  - [`lscert`](#lscert)
  - [`certsum`](#certsum)
- [Features](#features)
  - [`check_cert`](#check_cert)
  - [`lscert`](#lscert-1)
  - [`certsum`](#certsum-1)
  - [common](#common)
- [Changelog](#changelog)
- [Requirements](#requirements)
  - [Building source code](#building-source-code)
  - [Running](#running)
- [Installation](#installation)
  - [From source](#from-source)
    - [Quick Start guide](#quick-start-guide)
    - [Detailed guide](#detailed-guide)
  - [Using release binaries](#using-release-binaries)
- [Configuration options](#configuration-options)
  - [Expiration threshold calculations](#expiration-threshold-calculations)
  - [Asserting that expected Subject Alternate Names (SANs) are present](#asserting-that-expected-subject-alternate-names-sans-are-present)
  - [Skip hostname verification when leaf cert is missing SANs entries](#skip-hostname-verification-when-leaf-cert-is-missing-sans-entries)
  - [Applying or ignoring validation check results](#applying-or-ignoring-validation-check-results)
    - [`check_cert` plugin](#check_cert-plugin)
    - [`lscert` CLI tool](#lscert-cli-tool)
    - [`certsum` CLI tool](#certsum-cli-tool)
  - [Command-line arguments](#command-line-arguments)
    - [`check_cert`](#check_cert-1)
    - [`lscert`](#lscert-2)
      - [Flags](#flags)
      - [Positional Argument](#positional-argument)
    - [`certsum`](#certsum-2)
  - [Configuration file](#configuration-file)
- [Examples](#examples)
  - [`check_cert` Nagios plugin](#check_cert-nagios-plugin)
    - [OK results](#ok-results)
    - [WARNING results](#warning-results)
    - [CRITICAL results](#critical-results)
      - [Expiring certificate](#expiring-certificate)
      - [Expired certificate](#expired-certificate)
    - [Explicitly applying validation check results](#explicitly-applying-validation-check-results)
      - [`expiration`](#expiration)
      - [`hostname`](#hostname)
      - [`sans`](#sans)
    - [Explicitly ignoring validation check results](#explicitly-ignoring-validation-check-results)
      - [`expiration`](#expiration-1)
      - [`hostname`](#hostname-1)
      - [`sans`](#sans-1)
      - [`expiration`, `hostname`, `sans`](#expiration-hostname-sans)
    - [Reviewing a certificate file](#reviewing-a-certificate-file)
  - [`lscert` CLI tool](#lscert-cli-tool-1)
    - [Positional Argument](#positional-argument-1)
      - [Simple](#simple)
      - [Flags and Argument](#flags-and-argument)
    - [OK results](#ok-results-1)
    - [WARNING results](#warning-results-1)
    - [CRITICAL results](#critical-results-1)
    - [Reviewing a certificate file](#reviewing-a-certificate-file-1)
  - [`certsum` CLI tool](#certsum-cli-tool-1)
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

This repo contains various tools used to review, monitor & validate
certificates.

| Tool Name     | Description                                                                                                                |
| ------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `check_certs` | Nagios plugin used to monitor & validate certificate chains.                                                               |
| `lscert`      | CLI app used to generate a summary of certificate chain metadata and validation results.                                   |
| `certsum`     | CLI app used to scan one or more given IP ranges or collection of name/FQDN values for certs and provide a summary report. |

### `check_certs`

Nagios plugin used to monitor & perform validation checks of certificate
chains.

The output is designed to provide the one-line summary needed by Nagios for
quick identification of a problem while providing longer, more detailed
information for use in email and Teams notifications
([atc0005/send2teams](https://github.com/atc0005/send2teams)).

Validation checks are applied in layers, with support for explicitly marking
or flagging specific validation check results as "ignored". Ignored results
are still listed, but in a separate section of the check results output (aka,
"report") and are not considered when performing final plugin state (i.e.,
`OK`, `WARNING`, `CRITICAL`).

Some validation check results are ignored by default unless additional
information is supplied. For example, the SANs list validation check result is
ignored unless the sysadmin provides a list of required SANs entries. Other
check results may be ignored by default, but can be explicitly requested via a
supported flag keyword (see [configuration options](#configuration-options)
for more information).

See the [features list](#features) for the validation checks currently
supported by this plugin.

---

NOTE: The validation check behavior changes for `v0.8.0` are intended to be
fully compatible with existing deployments. Please file a bug report if you
find that this is not the case.

For future releases, please review the release notes carefully for any
breaking changes.

---

#### Performance Data

Initial support has been added for emitting Performance Data / Metrics, but
refinement suggestions are welcome.

Consult the tables below for the metrics implemented thus far.

Please add to an existing
[Discussion](https://github.com/atc0005/check-cert/discussions) thread
(if applicable) or [open a new
one](https://github.com/atc0005/check-cert/discussions/new) with any
feedback that you may have. Thanks in advance!

| Emitted Performance Data / Metric | Meaning                                                                                                                                                                                                                             |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `time`                            | Runtime for plugin                                                                                                                                                                                                                  |
| `expires_leaf`                    | Days remaining before leaf (aka, "server") certificate expires. If multiple leaf certificates are present (invalid configuration), the one expiring soonest is reported.                                                            |
| `expires_intermediate`            | Days remaining before the next to expire intermediate certificate expires.                                                                                                                                                          |
| `certs_present_leaf`              | Number of leaf (aka, "server") certificates present in the chain.                                                                                                                                                                   |
| `certs_present_intermediate`      | Number of intermediate certificates present in the chain.                                                                                                                                                                           |
| `certs_present_root`              | Number of root certificates present in the chain.                                                                                                                                                                                   |
| `certs_present_unknown`           | Number of certificates present in the chain with an unknown scope (i.e., the plugin cannot determine whether a leaf, intermediate or root). Please [report this scenario](https://github.com/atc0005/check-cert/issues/new/choose). |

### `lscert`

The `lscert` CLI app is used to generate a summary of certificate chain
metadata and validation results for quick review.

It can be used to quickly review the results of replacing a certificate
and/or troubleshoot why connections to a certificate-enabled service may be
failing.

Certificate metadata can be retrieved from:

- a remote service at a specified fully-qualified domain name (e.g.,
  `www.github.com`) or IP Address and port (e.g., 443)
- a local certificate "bundle" or standalone leaf certificate file

If specifying a host via IP Address, a hostname validation failure will be
noted unless:

- you also specify the `DNS Name` or `hostname` that you wish to retrieve the
  certificate for
- the IP Address is in the Subject Alternate Name (SANs) list for the
  certificate

This hostname validation failure can be ignored if you are only interested in
viewing the details for the default certificate associated with the IP
Address.

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
  - needed if retrieving a non-default certificate chain (via
    [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication) support)
- Hostnames (**fragile**)
  - this is highly dependent on your DNS configuration, particularly any
    configured search list (aka, `DNS Suffix Search List` in Windows
    terminology) entries used to qualify short/hostname values

Support is present (though limited) for filtering "OK" status hosts and certs
to either increase or reduce the amount of information provided in the
generated summary output. Two summary modes are provided to control the level
of detail in the provided output.

NOTE: If using IP Addresses (or ranges), only the default certificate will be
accessible to this tool. Use FQDNs in order to retrieve certificates using
[SNI](https://en.wikipedia.org/wiki/Server_Name_Indication).

## Features

### `check_cert`

- Verify certificate used by specified service

- Verify local certificate "bundle" or standalone leaf certificate file

- Detailed "report" of findings
  - certificate order
  - certificate type
  - status (OK, CRITICAL, WARNING)
  - SANs entries
  - serial number
  - issuer

- Multiple certificate validation checks
  - Expiration status for all certificates in a chain
    - not expired
    - expiring "soon"
      - warning threshold
      - critical threshold
  - Hostname value for the leaf certificate in a chain
    - see subsection for skipping hostname verification when the leaf
      certificate is missing SANs entries in the [configuration
      options](#configuration-options) section for details
  - Subject Alternate Names (SANs) for the leaf certificate in a chain
    - if `SKIPSANSCHECKS` keyword is supplied as the value no SANs entry
      checks will be performed; this keyword is useful for defining a shared
      Nagios check command and service check where SANs list validation may
      not be desired for some certificate chains (e.g., those with a very long
      list of entries)

- Optional support for skipping hostname verification for a certificate when
  the SANs list is empty
- Optional support for ignoring expiration of intermediate certificates
- Optional support for ignoring expiration of root certificates

### `lscert`

- Verify certificate used by specified service

- Verify local certificate "bundle" or standalone leaf certificate file

- Optional generation of OpenSSL-like text output from target cert-enabled
  service or filename
  - thanks to the `grantae/certinfo` package

- Detailed "report" of findings
  - certificate order
  - certificate type
  - status (OK, CRITICAL, WARNING)
  - SANs entries
  - serial number
  - issuer

- Multiple certificate validation checks
  - Expiration status for all certificates in a chain
  - Hostname value for the leaf certificate in a chain
  - Subject Alternate Names (SANs) for the leaf certificate in a chain

### `certsum`

- Generate summary of discovered certificates from given hosts (single or IP
  Address ranges, hostnames or FQDNs) and ports

- Configurable rate limit

- Specify one or many ports to scan for certificate chains

- Configurable display of just "problem" results or all results

- Choice of high-level summary/overview or separate output for each
  certificate in a chain

- Configurable application timeout (i.e., help prevent stalling out)

### common

Features common to all tools provided by this project.

- Retrieve certificate chain using
  [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication) support
  - attempted by default if the given server name/FQDN value was resolvable
  - server value can be overridden via the `dns-name` flag (see the
    [configuration options](#configuration-options) section for details)

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

#### Quick Start guide

This provides binaries based on the latest stable tag generated using the
equivalent of `go build`.

1. [Download][go-docs-download] Go
1. [Install][go-docs-install] Go
1. `go install github.com/atc0005/check-cert/cmd/certsum@latest`
1. `go install github.com/atc0005/check-cert/cmd/lscert@latest`
1. `GOBIN="${PWD}" go install github.com/atc0005/check-cert/cmd/check_cert@latest`
1. `sudo mv check_cert /path/to/plugins/`
   - e.g., `/usr/lib/nagios/plugins/` or `/usr/lib64/nagios/plugins/`,
     depending on what distro you are running

Per `go help install`:

> Executables are installed in the directory named by the GOBIN environment
> variable, which defaults to $GOPATH/bin or $HOME/go/bin if the GOPATH
> environment variable is not set. Executables in $GOROOT
> are installed in $GOROOT/bin or $GOTOOLDIR instead of $GOBIN.

#### Detailed guide

This provides binaries based on the state of the current checked out branch
(or tag) using either `go build` or if using the provided Makefile, build
settings intended to optimize for size and to prevent dynamic linkage.

1. [Download][go-docs-download] Go
1. [Install][go-docs-install] Go
   - NOTE: Pay special attention to the remarks about `$HOME/.profile`
1. Clone the repo
   1. `cd /tmp`
   1. `git clone https://github.com/atc0005/check-cert`
   1. `cd check-cert`
   1. (Optional) `git checkout vX.Y.Z`
      - where `vX.Y.Z` is a tag such as `v0.8.0`
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
   - for the detected current operating system and architecture, explicitly
     using bundled dependencies in top-level `vendor` folder
     - `go build -mod=vendor ./cmd/check_cert/`
     - `go build -mod=vendor ./cmd/lscert/`
     - `go build -mod=vendor ./cmd/certsum/`
   - for all supported platforms (where `make` is installed)
      - `make all`
   - for use on Windows amd64
      - `make windows-x64-build`
   - for use on Linux amd64
     - `make linux-x64-build`
   - for use on Linux arm64
     - `make linux-arm64-build`
1. Copy the newly compiled binary from the applicable `/tmp` subdirectory path
   (based on the clone instructions in this section) below and deploy where
   needed.
   - if using `Makefile`
     - look in `/tmp/check-cert/release_assets/check_cert/`
     - look in `/tmp/check-cert/release_assets/lscert/`
     - look in `/tmp/check-cert/release_assets/certsum/`
   - if using `go build`
     - look in `/tmp/check-cert/`

**NOTE**: Depending on which `Makefile` recipe you use the generated binary
may be compressed and have an `xz` extension. If so, you should decompress the
binary first before deploying it (e.g., `xz -d check_cert-linux-amd64.xz`).

### Using release binaries

1. Download the [latest
   release](https://github.com/atc0005/check-cert/releases/latest) binaries
1. Decompress binaries
   - e.g., `xz -d check_cert-linux-amd64.xz`
1. Rename binaries
   - e.g., `mv check_cert-linux-amd64 check_cert`
1. Deploy
   - Place `check_cert` alongside your other Nagios plugins
     - e.g., `/usr/lib/nagios/plugins/` or `/usr/lib64/nagios/plugins/`
   - Place `lscert`, `certsum` in a location of your choice
     - e.g., `/usr/local/bin/`

**NOTE**:

As of the v0.11.0 release, DEB and RPM packages are provided as an alternative
to manually deploying binaries.

## Configuration options

### Expiration threshold calculations

This applies to all tools provided by this project.

The behavior of the `check_cert`plugin differs somewhat from `check_http`
`v2.1.2`; this plugin triggers a whole day *later* than `check_http` does for
the same `WARNING` and `CRITICAL` threshold values.

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

### Asserting that expected Subject Alternate Names (SANs) are present

Among other validation checks, the `check_cert` plugin and `lscert` CLI tool
both support SANs list validation by accepting a CSV list of expected SANs
entries and assert that:

- all provided SANs entries are present on the leaf certificate
- all SANs entries present on the leaf certificate are in the provided SANs
  entries list

Problem scenarios covered:

- the cert provider omitted a requested/expected SANs entry
- the monitoring configuration has not been updated to look for new SANs
  entries present on the leaf cert

As a real-world use case, applying SANs list validation helped catch an
unapproved DNS record (CNAME) change for a public service. The DNS record
change resulted in the service redirecting from the original (intended)
pre-production system to a development box used by a different team in another
business unit. While this would have likely been detected before the system
was deployed to production, it would have caused unnecessary confusion/delays
while the issue was worked out. Instead, the monitoring system caught the
issue and the service owner was able to reach out immediately and coordinate
reverting the unauthorized change.

### Skip hostname verification when leaf cert is missing SANs entries

This is specific to the `check_cert` plugin.

Optional support is available to skip hostname verification if a certificate
is missing SANs entries.

- in version v0.5.3 and earlier, support was available for validating a given
  hostname against the Common Name field of a certificate, regardless of
  whether SANs entries were present
  - Go 1.15 marked this support as deprecated
  - Go 1.16 noted that it would be dropped in Go 1.17
  - Go 1.17 dropped this support
- in version 0.6.0 and later, support is available (if specified) to skip
  hostname verification if a certificate is missing Subject Alternate Names
    (SANs) entries
  - this support is intended as a temporary workaround until the certificate
    expires and is replaced with a certificate containing a valid SANs list

See the flags table for the `check_cert` plugin for more information.

### Applying or ignoring validation check results

#### `check_cert` plugin

As of v0.8.0, all available validation checks are now performed regardless of
what flags and flag values are specified.

Whereas the previous behavior was to both apply a validation check *and*
hard-code the behavior of applying the result against the final plugin state,
support has been added to explicitly *apply* or *ignore* individual validation
check results.

This support is provided via new flags and a set of keywords that may be
specified as a comma-separated value list.

Most validation check results are applied by default, provided that required
configuration settings are applied. Some are ignored by default.

| Validation Check Result | Applied by default | Requirements              |
| ----------------------- | ------------------ | ------------------------- |
| `Expiration`            | Yes                | Expiration thresholds     |
| `Hostname`              | Yes                | Server or DNS Name values |
| `SANs list`             | Yes`*`             | SANs entries              |

The certificate expiration validation check is applied using default
thresholds if not specified by the sysadmin. The hostname verification check
is applied using either the server (fallback) or DNS Name (preferred) value.

The SANs list validation check`*` is applied *if* SANs entries are provided.
If SANs entries are not specified, this validation check is performed, but
noted as ignored in the output (and not used when determining final plugin
state); without SANs entries to validate the SANs list validation check result
is of limited value. If explicitly requested and SANs entries are not provided
a configuration error is emitted and the plugin terminates.

#### `lscert` CLI tool

All validation checks are applied with output streamlined for quick pass/fail
evaluation. While flags are not currently offered to explicitly *apply* or
*ignore* validation check results this support may be added in the future if
there is sufficient interest.

#### `certsum` CLI tool

No changes to validation check results have been made as of the v0.8.0
release. This tool continues to focus on identifying problem certificates by
way of expiration date thresholds. Future versions may incorporate additional
validation checks and any behavior changes at that time noted.

### Command-line arguments

- Use the `-h` or `--help` flag to display current usage information.
- Flags marked as **`required`** must be set via CLI flag.
- Flags *not* marked as required are for settings where a useful default is
  already defined, but may be overridden if desired.

#### `check_cert`

| Flag                                         | Required  | Default | Repeat | Possible                                                                | Description                                                                                                                                                                                                                                                                                                                                          |
| -------------------------------------------- | --------- | ------- | ------ | ----------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `f`, `filename`                              | No        | `false` | No     | *valid file name characters*                                            | Fully-qualified path to a PEM formatted certificate file containing one or more certificates.                                                                                                                                                                                                                                                        |
| `branding`                                   | No        | `false` | No     | `branding`                                                              | Toggles emission of branding details with plugin status details. This output is disabled by default.                                                                                                                                                                                                                                                 |
| `h`, `help`                                  | No        | `false` | No     | `h`, `help`                                                             | Show Help text along with the list of supported flags.                                                                                                                                                                                                                                                                                               |
| `v`, `verbose`                               | No        | `false` | No     | `v`, `verbose`                                                          | Toggles emission of detailed certificate metadata. This level of output is disabled by default.                                                                                                                                                                                                                                                      |
| `version`                                    | No        | `false` | No     | `version`                                                               | Whether to display application version and then immediately exit application.                                                                                                                                                                                                                                                                        |
| `c`, `age-critical`                          | No        | 15      | No     | *positive whole number of days*                                         | The threshold for the certificate check's `CRITICAL` state. If the certificate expires before this number of days then the service check will be considered in a `CRITICAL` state.                                                                                                                                                                   |
| `w`, `age-warning`                           | No        | 30      | No     | *positive whole number of days*                                         | The threshold for the certificate check's `WARNING` state. If the certificate expires before this number of days, but not before the `age-critical` value, then the service check will be considered in a `WARNING` state.                                                                                                                           |
| `ll`, `log-level`                            | No        | `info`  | No     | `disabled`, `panic`, `fatal`, `error`, `warn`, `info`, `debug`, `trace` | Log message priority filter. Log messages with a lower level are ignored.                                                                                                                                                                                                                                                                            |
| `p`, `port`                                  | No        | `443`   | No     | *positive whole number between 1-65535, inclusive*                      | TCP port of the remote certificate-enabled service. This is usually 443 (HTTPS) or 636 (LDAPS).                                                                                                                                                                                                                                                      |
| `t`, `timeout`                               | No        | `10`    | No     | *positive whole number of seconds*                                      | Timeout value in seconds allowed before a connection attempt to a remote certificate-enabled service (in order to retrieve the certificate) is abandoned and an error returned.                                                                                                                                                                      |
| `se`, `sans-entries`                         | No        |         | No     | *comma-separated list of values*                                        | One or many names required to be in the Subject Alternate Names (SANs) list for a leaf certificate. If provided, this list of comma-separated values is required for the certificate to pass validation. If the case-insensitive " + SkipSANSCheckKeyword + " keyword is provided the results from this validation check will be flagged as ignored. |
| `s`, `server`                                | **Maybe** |         | No     | *fully-qualified domain name or IP Address*                             | The fully-qualified domain name or IP Address used for certificate chain retrieval. This value should appear in the Subject Alternate Names (SANs) list for the leaf certificate unless also using the `dns-name` flag.                                                                                                                              |
| `dn`, `dns-name`                             | **Maybe** |         | No     | *fully-qualified domain name or IP Address*                             | A fully-qualified domain name or IP Address in the Subject Alternate Names (SANs) list for the leaf certificate. If specified, this value will be used when retrieving the certificate chain (SNI support) and for hostname verification. Required when evaluating certificate files. See the `server` flag description for more information.        |
| `ignore-hostname-verification-if-empty-sans` | No        | `false` | No     | `true`, `false`                                                         | Whether a hostname verification failure should be ignored if Subject Alternate Names (SANs) list is empty.                                                                                                                                                                                                                                           |
| `ignore-expired-intermediate-certs`          | No        | `false` | No     | `true`, `false`                                                         | Whether expired intermediate certificates should be ignored.                                                                                                                                                                                                                                                                                         |
| `ignore-expired-root-certs`                  | No        | `false` | No     | `true`, `false`                                                         | Whether expired root certificates should be ignored.                                                                                                                                                                                                                                                                                                 |
| `ignore-validation-result`                   | No        |         | No     | `sans`, `expiration`, `hostname`                                        | List of keywords for certificate chain validation check result that should be explicitly ignored and not used to determine final validation state.                                                                                                                                                                                                   |
| `apply-validation-result`                    | No        |         | No     | `sans`, `expiration`, `hostname`                                        | List of keywords for certificate chain validation check results that should be explicitly applied and used to determine final validation state.                                                                                                                                                                                                      |
| `list-ignored-errors`                        | No        | `false` | No     | `true`, `false`                                                         | Toggles emission of ignored validation check result errors. Disabled by default to reduce confusion.                                                                                                                                                                                                                                                 |

#### `lscert`

##### Flags

| Flag                 | Required  | Default | Repeat | Possible                                                                | Description                                                                                                                                                                                                                                                                                                                                          |
| -------------------- | --------- | ------- | ------ | ----------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `f`, `filename`      | No        | `false` | No     | *valid file name characters*                                            | Fully-qualified path to a PEM formatted certificate file containing one or more certificates.                                                                                                                                                                                                                                                        |
| `text`               | No        | `false` | No     | `true`, `false`                                                         | Toggles emission of x509 TLS certificates in an OpenSSL-inspired text format. This output is disabled by default.                                                                                                                                                                                                                                    |
| `h`, `help`          | No        | `false` | No     | `h`, `help`                                                             | Show Help text along with the list of supported flags.                                                                                                                                                                                                                                                                                               |
| `v`, `verbose`       | No        | `false` | No     | `v`, `verbose`                                                          | Toggles emission of detailed certificate metadata. This level of output is disabled by default.                                                                                                                                                                                                                                                      |
| `version`            | No        | `false` | No     | `version`                                                               | Whether to display application version and then immediately exit application.                                                                                                                                                                                                                                                                        |
| `c`, `age-critical`  | No        | 15      | No     | *positive whole number of days*                                         | The threshold for the certificate check's `CRITICAL` state. If the certificate expires before this number of days then the service check will be considered in a `CRITICAL` state.                                                                                                                                                                   |
| `w`, `age-warning`   | No        | 30      | No     | *positive whole number of days*                                         | The threshold for the certificate check's `WARNING` state. If the certificate expires before this number of days, but not before the `age-critical` value, then the service check will be considered in a `WARNING` state.                                                                                                                           |
| `ll`, `log-level`    | No        | `info`  | No     | `disabled`, `panic`, `fatal`, `error`, `warn`, `info`, `debug`, `trace` | Log message priority filter. Log messages with a lower level are ignored.                                                                                                                                                                                                                                                                            |
| `p`, `port`          | No        | `443`   | No     | *positive whole number between 1-65535, inclusive*                      | TCP port of the remote certificate-enabled service. This is usually 443 (HTTPS) or 636 (LDAPS).                                                                                                                                                                                                                                                      |
| `t`, `timeout`       | No        | `10`    | No     | *positive whole number of seconds*                                      | Timeout value in seconds allowed before a connection attempt to a remote certificate-enabled service (in order to retrieve the certificate) is abandoned and an error returned.                                                                                                                                                                      |
| `se`, `sans-entries` | No        |         | No     | *comma-separated list of values*                                        | One or many names required to be in the Subject Alternate Names (SANs) list for a leaf certificate. If provided, this list of comma-separated values is required for the certificate to pass validation. If the case-insensitive " + SkipSANSCheckKeyword + " keyword is provided the results from this validation check will be flagged as ignored. |
| `s`, `server`        | **Maybe** |         | No     | *fully-qualified domain name or IP Address*                             | The fully-qualified domain name or IP Address used for certificate chain retrieval. This value should appear in the Subject Alternate Names (SANs) list for the leaf certificate unless also using the `dns-name` flag.                                                                                                                              |
| `dn`, `dns-name`     | **Maybe** |         | No     | *fully-qualified domain name or IP Address*                             | A fully-qualified domain name or IP Address in the Subject Alternate Names (SANs) list for the leaf certificate. If specified, this value will be used when retrieving the certificate chain (SNI support) and for hostname verification. Required when evaluating certificate files. See the `server` flag description for more information.        |

##### Positional Argument

As of the v0.9.0 release the `lscert` tool accepts a URL pattern as a single
positional argument. This positional argument value can be any of:

- URL
- resolvable name
- IP Address

---

**NOTE**: Due to limitations in the Go standard library's support for
command-line argument handling you *must* specify positional arguments after
all flags.

---

Valid syntax:

`lscert PATTERN`

Invalid syntax:

- `lscert --log-level debug PATTERN`
- `lscert --dns-name one.one.one.one 1.1.1.1`

Some valid examples:

- `lscert google.com`
- `lscert https://www.google.com`
- `lscert https://www.google.com:443`
- `lscert --log-level debug PATTERN`
- `lscert --dns-name one.one.one.one 1.1.1.1`

Aside from the required order of flags and positional argument noted above,
there are additional requirements to be aware of:

- if the `server` or `filename` flags are specified, the positional argument
  is ignored
- if the `port` flag is specified, its value will be ignored if a port is
  provided in the given URL pattern positional argument

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
certificate-enabled port on `www.google.com`. We override the default
`WARNING` and `CRITICAL` age threshold values with somewhat arbitrary numbers.

NOTE: Use the `--verbose` flag to expose further details.

```ShellSession
$ check_cert --server www.google.com --port 443 --age-critical 30 --age-warning 50
OK: Expiration validation successful: leaf cert "www.google.com" expires next with 65d 23h remaining (until 2022-08-29 09:39:59 +0000 UTC) [checks: 1 IGNORED (SANs List), 0 FAILED, 2 SUCCESSFUL (Hostname, Expiration)]

3 certs retrieved for service running on www.google.com (64.233.185.105) at port 443 using host value "www.google.com"


PROBLEM RESULTS:

* None


IGNORED RESULTS:

[--] SANs List validation ignored: 0 SANs entries specified, 1 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]


SUCCESS RESULTS:

[OK] Expiration validation successful: leaf cert "www.google.com" expires next with 65d 23h remaining (until 2022-08-29 09:39:59 +0000 UTC)

Certificate 1 of 3 (leaf):
        Name: CN=www.google.com
        SANs entries: [www.google.com]
        Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        Serial: 9F:07:4B:11:74:5F:16:FC:12:23:75:FA:58:79:93:F0
        Issued On: 2022-06-06 09:40:00 +0000 UTC
        Expiration: 2022-08-29 09:39:59 +0000 UTC
        Status: [OK] 65d 23h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        Serial: 02:03:BC:53:59:6B:34:C7:18:F5:01:50:66
        Issued On: 2020-08-13 00:00:42 +0000 UTC
        Expiration: 2027-09-30 00:00:42 +0000 UTC
        Status: [OK] 1923d 13h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE
        Serial: 77:BD:0D:6C:DB:36:F9:1A:EA:21:0F:C4:F0:58:D3:0D
        Issued On: 2020-06-19 00:00:42 +0000 UTC
        Expiration: 2028-01-28 00:00:42 +0000 UTC
        Status: [OK] 2043d 13h remaining

[OK] Hostname validation using value "www.google.com" successful for leaf certificate

 | 'time'=305ms;;;;
```

See the `WARNING` example output for additional details.

#### WARNING results

Here we do the same thing again, but using the expiration date values returned
earlier as a starting point, we intentionally move the threshold values in
order to trigger a `WARNING` state for the leaf certificate.

NOTE: Use the `--verbose` flag to expose further details.

```ShellSession
$ check_cert --server www.google.com --port 443 --age-critical 30 --age-warning 70
5:32AM ERR cmd/check_cert/main.go:413 > validation checks failed for certificate chain error="summary: 1 of 3 validation checks failed" age_critical=30 age_warning=70 app_type=plugin apply_expiration_validation_results=true apply_hostname_validation_results=true apply_sans_list_validation_results=false cert_check_timeout=10s checks_failed=1 checks_ignored=1 checks_successful=1 checks_total=3 expected_sans_entries= filename= logging_level=info port=443 server=www.google.com version="check-cert x.y.z (https://github.com/atc0005/check-cert)"
WARNING: Expiration validation failed: leaf cert "www.google.com" expires next with 65d 23h remaining (until 2022-08-29 09:39:59 +0000 UTC) [checks: 1 IGNORED (SANs List), 1 FAILED (Expiration), 1 SUCCESSFUL (Hostname)]

**VALIDATION ERRORS**

* expiration validation failed: expiring certificates found

**VALIDATION CHECKS REPORT**

3 certs retrieved for service running on www.google.com (64.233.185.105) at port 443 using host value "www.google.com"


PROBLEM RESULTS:

[!!] Expiration validation failed: leaf cert "www.google.com" expires next with 65d 23h remaining (until 2022-08-29 09:39:59 +0000 UTC)

Certificate 1 of 3 (leaf):
        Name: CN=www.google.com
        SANs entries: [www.google.com]
        Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        Serial: 9F:07:4B:11:74:5F:16:FC:12:23:75:FA:58:79:93:F0
        Issued On: 2022-06-06 09:40:00 +0000 UTC
        Expiration: 2022-08-29 09:39:59 +0000 UTC
        Status: [WARNING] 65d 23h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        Serial: 02:03:BC:53:59:6B:34:C7:18:F5:01:50:66
        Issued On: 2020-08-13 00:00:42 +0000 UTC
        Expiration: 2027-09-30 00:00:42 +0000 UTC
        Status: [OK] 1923d 13h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE
        Serial: 77:BD:0D:6C:DB:36:F9:1A:EA:21:0F:C4:F0:58:D3:0D
        Issued On: 2020-06-19 00:00:42 +0000 UTC
        Expiration: 2028-01-28 00:00:42 +0000 UTC
        Status: [OK] 2043d 13h remaining


IGNORED RESULTS:

[--] SANs List validation ignored: 0 SANs entries specified, 1 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]


SUCCESS RESULTS:

[OK] Hostname validation using value "www.google.com" successful for leaf certificate

 | 'time'=144ms;;;;
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
1. The `VALIDATION ERRORS` section notes briefly what is wrong with the cert
1. The `VALIDATION CHECKS REPORT` section provides an overview of the specific
   validation checks performed along with a summary of the certificate chain
   evaluated
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
values in order to trigger a `CRITICAL` state for the leaf certificate.

NOTE: Use the `--verbose` flag to expose further details.

```ShellSession
$ check_cert --server www.google.com --port 443 --age-critical 70 --age-warning 90
5:36AM ERR cmd/check_cert/main.go:413 > validation checks failed for certificate chain error="summary: 1 of 3 validation checks failed" age_critical=70 age_warning=90 app_type=plugin apply_expiration_validation_results=true apply_hostname_validation_results=true apply_sans_list_validation_results=false cert_check_timeout=10s checks_failed=1 checks_ignored=1 checks_successful=1 checks_total=3 expected_sans_entries= filename= logging_level=info port=443 server=www.google.com version="check-cert x.y.z (https://github.com/atc0005/check-cert)"
CRITICAL: Expiration validation failed: leaf cert "www.google.com" expires next with 65d 23h remaining (until 2022-08-29 09:39:59 +0000 UTC) [checks: 1 IGNORED (SANs List), 1 FAILED (Expiration), 1 SUCCESSFUL (Hostname)]

**VALIDATION ERRORS**

* expiration validation failed: expiring certificates found

**VALIDATION CHECKS REPORT**

3 certs retrieved for service running on www.google.com (64.233.185.105) at port 443 using host value "www.google.com"


PROBLEM RESULTS:

[!!] Expiration validation failed: leaf cert "www.google.com" expires next with 65d 23h remaining (until 2022-08-29 09:39:59 +0000 UTC)

Certificate 1 of 3 (leaf):
        Name: CN=www.google.com
        SANs entries: [www.google.com]
        Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        Serial: 9F:07:4B:11:74:5F:16:FC:12:23:75:FA:58:79:93:F0
        Issued On: 2022-06-06 09:40:00 +0000 UTC
        Expiration: 2022-08-29 09:39:59 +0000 UTC
        Status: [CRITICAL] 65d 23h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        Serial: 02:03:BC:53:59:6B:34:C7:18:F5:01:50:66
        Issued On: 2020-08-13 00:00:42 +0000 UTC
        Expiration: 2027-09-30 00:00:42 +0000 UTC
        Status: [OK] 1923d 13h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE
        Serial: 77:BD:0D:6C:DB:36:F9:1A:EA:21:0F:C4:F0:58:D3:0D
        Issued On: 2020-06-19 00:00:42 +0000 UTC
        Expiration: 2028-01-28 00:00:42 +0000 UTC
        Status: [OK] 2043d 13h remaining


IGNORED RESULTS:

[--] SANs List validation ignored: 0 SANs entries specified, 1 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]


SUCCESS RESULTS:

[OK] Hostname validation using value "www.google.com" successful for leaf certificate

 | 'time'=303ms;;;;
```

##### Expired certificate

Here we use the expired.badssl.com subdomain to demo the results of
encountering one or more (in this case more) expired certificates in a chain.
Aside from the FQDN, all default options (including the port) are used.

NOTE: Use the `--verbose` flag to expose further details.

```ShellSession
$ check_cert --server expired.badssl.com
5:36AM ERR cmd/check_cert/main.go:413 > validation checks failed for certificate chain error="summary: 1 of 3 validation checks failed" age_critical=15 age_warning=30 app_type=plugin apply_expiration_validation_results=true apply_hostname_validation_results=true apply_sans_list_validation_results=false cert_check_timeout=10s checks_failed=1 checks_ignored=1 checks_successful=1 checks_total=3 expected_sans_entries= filename= logging_level=info port=443 server=expired.badssl.com version="check-cert x.y.z (https://github.com/atc0005/check-cert)"
CRITICAL: Expiration validation failed: leaf cert "*.badssl.com" expired 2629d 10h ago (on 2015-04-12 23:59:59 +0000 UTC) [checks: 1 IGNORED (SANs List), 1 FAILED (Expiration), 1 SUCCESSFUL (Hostname)]

**VALIDATION ERRORS**

* expiration validation failed: expired certificates found

**VALIDATION CHECKS REPORT**

3 certs retrieved for service running on expired.badssl.com (104.154.89.105) at port 443 using host value "expired.badssl.com"


PROBLEM RESULTS:

[!!] Expiration validation failed: leaf cert "*.badssl.com" expired 2629d 10h ago (on 2015-04-12 23:59:59 +0000 UTC)

Certificate 1 of 3 (leaf):
        Name: CN=*.badssl.com,OU=Domain Control Validated+OU=PositiveSSL Wildcard
        SANs entries: [*.badssl.com badssl.com]
        Issuer: CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        Serial: 4A:E7:95:49:FA:9A:BE:3F:10:0F:17:A4:78:E1:69:09
        Issued On: 2015-04-09 00:00:00 +0000 UTC
        Expiration: 2015-04-12 23:59:59 +0000 UTC
        Status: [EXPIRED] 2629d 10h ago

Certificate 2 of 3 (intermediate):
        Name: CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        SANs entries: []
        Issuer: CN=COMODO RSA Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        Serial: 2B:2E:6E:EA:D9:75:36:6C:14:8A:6E:DB:A3:7C:8C:07
        Issued On: 2014-02-12 00:00:00 +0000 UTC
        Expiration: 2029-02-11 23:59:59 +0000 UTC
        Status: [OK] 2424d 13h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=COMODO RSA Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        SANs entries: []
        Issuer: CN=AddTrust External CA Root,OU=AddTrust External TTP Network,O=AddTrust AB,C=SE
        Serial: 27:66:EE:56:EB:49:F3:8E:AB:D7:70:A2:FC:84:DE:22
        Issued On: 2000-05-30 10:48:38 +0000 UTC
        Expiration: 2020-05-30 10:48:38 +0000 UTC
        Status: [EXPIRED] 754d 23h ago


IGNORED RESULTS:

[--] SANs List validation ignored: 0 SANs entries specified, 2 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]


SUCCESS RESULTS:

[OK] Hostname validation using value "expired.badssl.com" successful for leaf certificate

 | 'time'=391ms;;;;
```

#### Explicitly applying validation check results

##### `expiration`

Here we use the `--apply-validation-result` flag with the `expiration` keyword
in order to *explicitly* apply expiration date validation results when
determining the final plugin state.

This doesn't have much of a direct effect because this validation check result
is applied by default, but it may be useful as a means of documenting a
specific service check command definition's intent.

```console
$ check_cert --server www.google.com --port 443 --age-critical 30 --age-warning 50 --apply-validation-result expiration
OK: Expiration validation successful: leaf cert "www.google.com" expires next with 63d 20h remaining (until 2022-08-29 09:39:59 +0000 UTC) [checks: 1 IGNORED (SANs List), 0 FAILED, 2 SUCCESSFUL (Hostname, Expiration)]

3 certs retrieved for service running on www.google.com (142.251.15.99) at port 443 using host value "www.google.com"


PROBLEM RESULTS:

* None


IGNORED RESULTS:

[--] SANs List validation ignored: 0 SANs entries specified, 1 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]


SUCCESS RESULTS:

[OK] Expiration validation successful: leaf cert "www.google.com" expires next with 63d 20h remaining (until 2022-08-29 09:39:59 +0000 UTC)

Certificate 1 of 3 (leaf):
        Name: CN=www.google.com
        SANs entries: [www.google.com]
        Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        Serial: 9F:07:4B:11:74:5F:16:FC:12:23:75:FA:58:79:93:F0
        Issued On: 2022-06-06 09:40:00 +0000 UTC
        Expiration: 2022-08-29 09:39:59 +0000 UTC
        Status: [OK] 63d 20h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        Serial: 02:03:BC:53:59:6B:34:C7:18:F5:01:50:66
        Issued On: 2020-08-13 00:00:42 +0000 UTC
        Expiration: 2027-09-30 00:00:42 +0000 UTC
        Status: [OK] 1921d 10h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE
        Serial: 77:BD:0D:6C:DB:36:F9:1A:EA:21:0F:C4:F0:58:D3:0D
        Issued On: 2020-06-19 00:00:42 +0000 UTC
        Expiration: 2028-01-28 00:00:42 +0000 UTC
        Status: [OK] 2041d 10h remaining

[OK] Hostname validation using value "www.google.com" successful for leaf certificate

 | 'time'=141ms;;;;
```

##### `hostname`

Here we use the `--apply-validation-result` flag with the `hostname` keyword
in order to *explicitly* apply hostname verification/validation results when
determining the final plugin state.

This doesn't have much of a direct effect because this validation check result
is applied by default, but it may be useful as a means of documenting a
specific service check command definition's intent.

```console
$ check_cert --server wrong.host.badssl.com --port 443 --apply-validation-result hostname
8:47AM ERR cmd/check_cert/main.go:413 > validation checks failed for certificate chain error="summary: 1 of 3 validation checks failed" age_critical=15 age_warning=30 app_type=plugin apply_expiration_validation_results=true apply_hostname_validation_results=true apply_sans_list_validation_results=false cert_check_timeout=10s checks_failed=1 checks_ignored=1 checks_successful=1 checks_total=3 expected_sans_entries= filename= logging_level=info port=443 server=wrong.host.badssl.com version="check-cert x.y.z (https://github.com/atc0005/check-cert)"
CRITICAL: Hostname validation using value "wrong.host.badssl.com" failed for leaf certificate [checks: 1 IGNORED (SANs List), 1 FAILED (Hostname), 1 SUCCESSFUL (Expiration)]

**VALIDATION ERRORS**

* hostname verification failed: x509: certificate is valid for *.badssl.com, badssl.com, not wrong.host.badssl.com

**VALIDATION CHECKS REPORT**

3 certs retrieved for service running on wrong.host.badssl.com (104.154.89.105) at port 443 using host value "wrong.host.badssl.com"


PROBLEM RESULTS:

[!!] Hostname validation using value "wrong.host.badssl.com" failed for leaf certificate

Consider updating the service check or command definition to specify the website FQDN instead of the host FQDN using the DNS Name or server flags. E.g., use 'www.example.org' instead of 'host7.example.com' in order to allow the remote server to select the correct certificate instead of using the default certificate.


IGNORED RESULTS:

[--] SANs List validation ignored: 0 SANs entries specified, 2 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]


SUCCESS RESULTS:

[OK] Expiration validation successful: leaf cert "*.badssl.com" expires next with 50d 0h remaining (until 2022-08-15 14:07:55 +0000 UTC)

Certificate 1 of 3 (leaf):
        Name: CN=*.badssl.com
        SANs entries: [*.badssl.com badssl.com]
        Issuer: CN=R3,O=Let's Encrypt,C=US
        Serial: 04:B7:56:01:59:46:10:A8:D8:36:17:C8:06:C2:F9:8D:2A:46
        Issued On: 2022-05-17 14:07:56 +0000 UTC
        Expiration: 2022-08-15 14:07:55 +0000 UTC
        Status: [OK] 50d 0h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=R3,O=Let's Encrypt,C=US
        SANs entries: []
        Issuer: CN=ISRG Root X1,O=Internet Security Research Group,C=US
        Serial: 91:2B:08:4A:CF:0C:18:A7:53:F6:D6:2E:25:A7:5F:5A
        Issued On: 2020-09-04 00:00:00 +0000 UTC
        Expiration: 2025-09-15 16:00:00 +0000 UTC
        Status: [OK] 1177d 2h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=ISRG Root X1,O=Internet Security Research Group,C=US
        SANs entries: []
        Issuer: CN=DST Root CA X3,O=Digital Signature Trust Co.
        Serial: 40:01:77:21:37:D4:E9:42:B8:EE:76:AA:3C:64:0A:B7
        Issued On: 2021-01-20 19:14:03 +0000 UTC
        Expiration: 2024-09-30 18:14:03 +0000 UTC
        Status: [OK] 827d 4h remaining

 | 'time'=541ms;;;;
```

If you wish to connect using a server's FQDN value that isn't associated with
the certificate (e.g., testing a backend system with a unique FQDN), but wish
to use a specific DNS Name (aka, virtual host name) you can use the `dns-name`
flag to specify a valid hostname value for the leaf certificate.

```console
$ check_cert --server wrong.host.badssl.com --dns-name badssl.com --port 443
OK: Expiration validation successful: leaf cert "*.badssl.com" expires next with 50d 0h remaining (until 2022-08-15 14:07:55 +0000 UTC) [checks: 1 IGNORED (SANs List), 0 FAILED, 2 SUCCESSFUL (Hostname, Expiration)]

3 certs retrieved for service running on wrong.host.badssl.com (104.154.89.105) at port 443 using host value "badssl.com"


PROBLEM RESULTS:

* None


IGNORED RESULTS:

[--] SANs List validation ignored: 0 SANs entries specified, 2 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]


SUCCESS RESULTS:

[OK] Expiration validation successful: leaf cert "*.badssl.com" expires next with 50d 0h remaining (until 2022-08-15 14:07:55 +0000 UTC)

Certificate 1 of 3 (leaf):
        Name: CN=*.badssl.com
        SANs entries: [*.badssl.com badssl.com]
        Issuer: CN=R3,O=Let's Encrypt,C=US
        Serial: 04:B7:56:01:59:46:10:A8:D8:36:17:C8:06:C2:F9:8D:2A:46
        Issued On: 2022-05-17 14:07:56 +0000 UTC
        Expiration: 2022-08-15 14:07:55 +0000 UTC
        Status: [OK] 50d 0h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=R3,O=Let's Encrypt,C=US
        SANs entries: []
        Issuer: CN=ISRG Root X1,O=Internet Security Research Group,C=US
        Serial: 91:2B:08:4A:CF:0C:18:A7:53:F6:D6:2E:25:A7:5F:5A
        Issued On: 2020-09-04 00:00:00 +0000 UTC
        Expiration: 2025-09-15 16:00:00 +0000 UTC
        Status: [OK] 1177d 2h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=ISRG Root X1,O=Internet Security Research Group,C=US
        SANs entries: []
        Issuer: CN=DST Root CA X3,O=Digital Signature Trust Co.
        Serial: 40:01:77:21:37:D4:E9:42:B8:EE:76:AA:3C:64:0A:B7
        Issued On: 2021-01-20 19:14:03 +0000 UTC
        Expiration: 2024-09-30 18:14:03 +0000 UTC
        Status: [OK] 827d 4h remaining

[OK] Hostname validation using value "badssl.com" successful for leaf certificate
```

##### `sans`

Here we use the `--apply-validation-result` flag with the `sans` keyword
in order to *explicitly* apply hostname verification/validation results when
determining the final plugin state.

If you do not specify a list of SANs entries to validate, configuration
validation will cause the plugin to abort:

```console
$ check_cert --server wrong.host.badssl.com --dns-name badssl.com --port 443 --apply-validation-result sans
8:53AM ERR cmd/check_cert/main.go:59 > Error initializing application error="configuration validation failed: unsupported setting for certificate SANs list validation; providing SANs entries via the \"sans-entries\" flag is required when specifying the \"sans\" keyword via the \"apply-validation-result\" flag"
CRITICAL: Error initializing application

**VALIDATION ERRORS**

* configuration validation failed: unsupported setting for certificate SANs list validation; providing SANs entries via the "sans-entries" flag is required when specifying the "sans" keyword via the "apply-validation-result" flag
```

If providing a list of SANs entries to validate, this doesn't have much of a
direct effect because this validation check result is applied by default, but
it may be useful as a means of documenting a specific service check command
definition's intent.

```console
$ check_cert --server wrong.host.badssl.com --dns-name badssl.com --port 443 --apply-validation-result sans --sans-entries "*.badssl.com, badssl.com"
OK: Expiration validation successful: leaf cert "*.badssl.com" expires next with 50d 0h remaining (until 2022-08-15 14:07:55 +0000 UTC) [checks: 0 IGNORED, 0 FAILED, 3 SUCCESSFUL (Expiration, Hostname, SANs List)]

3 certs retrieved for service running on wrong.host.badssl.com (104.154.89.105) at port 443 using host value "badssl.com"


PROBLEM RESULTS:

* None


IGNORED RESULTS:

* None


SUCCESS RESULTS:

[OK] Expiration validation successful: leaf cert "*.badssl.com" expires next with 50d 0h remaining (until 2022-08-15 14:07:55 +0000 UTC)

Certificate 1 of 3 (leaf):
        Name: CN=*.badssl.com
        SANs entries: [*.badssl.com badssl.com]
        Issuer: CN=R3,O=Let's Encrypt,C=US
        Serial: 04:B7:56:01:59:46:10:A8:D8:36:17:C8:06:C2:F9:8D:2A:46
        Issued On: 2022-05-17 14:07:56 +0000 UTC
        Expiration: 2022-08-15 14:07:55 +0000 UTC
        Status: [OK] 50d 0h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=R3,O=Let's Encrypt,C=US
        SANs entries: []
        Issuer: CN=ISRG Root X1,O=Internet Security Research Group,C=US
        Serial: 91:2B:08:4A:CF:0C:18:A7:53:F6:D6:2E:25:A7:5F:5A
        Issued On: 2020-09-04 00:00:00 +0000 UTC
        Expiration: 2025-09-15 16:00:00 +0000 UTC
        Status: [OK] 1177d 2h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=ISRG Root X1,O=Internet Security Research Group,C=US
        SANs entries: []
        Issuer: CN=DST Root CA X3,O=Digital Signature Trust Co.
        Serial: 40:01:77:21:37:D4:E9:42:B8:EE:76:AA:3C:64:0A:B7
        Issued On: 2021-01-20 19:14:03 +0000 UTC
        Expiration: 2024-09-30 18:14:03 +0000 UTC
        Status: [OK] 827d 4h remaining

[OK] Hostname validation using value "badssl.com" successful for leaf certificate

[OK] SANs List validation successful: expected and confirmed (2) SANs entries present for leaf certificate [2 EXPECTED, 0 MISSING, 0 UNEXPECTED]

 | 'time'=384ms;;;;
```

If for example you fail to provide a SANs entry, the plugin will flag this as
a problem and reflect this in the final plugin state:

```console
$ check_cert --server wrong.host.badssl.com --dns-name badssl.com --port 443 --apply-validation-result sans --sans-entries "badssl.com"
8:56AM ERR cmd/check_cert/main.go:413 > validation checks failed for certificate chain error="summary: 1 of 3 validation checks failed" age_critical=15 age_warning=30 app_type=plugin apply_expiration_validation_results=true apply_hostname_validation_results=true apply_sans_list_validation_results=true cert_check_timeout=10s checks_failed=1 checks_ignored=0 checks_successful=2 checks_total=3 expected_sans_entries=badssl.com filename= logging_level=info port=443 server=wrong.host.badssl.com version="check-cert x.y.z (https://github.com/atc0005/check-cert)"
CRITICAL: SANs List validation failed: "leaf" certificate has unexpected SANs entries [checks: 0 IGNORED, 1 FAILED (SANs List), 2 SUCCESSFUL (Hostname, Expiration)]

**VALIDATION ERRORS**

* certificate has unexpected SANs entries

**VALIDATION CHECKS REPORT**

3 certs retrieved for service running on wrong.host.badssl.com (104.154.89.105) at port 443 using host value "badssl.com"


PROBLEM RESULTS:

[!!] SANs List validation failed: "leaf" certificate has unexpected SANs entries [1 EXPECTED, 0 MISSING, 1 UNEXPECTED]; missing: [N/A], unexpected: [*.badssl.com]


IGNORED RESULTS:

* None


SUCCESS RESULTS:

[OK] Expiration validation successful: leaf cert "*.badssl.com" expires next with 50d 0h remaining (until 2022-08-15 14:07:55 +0000 UTC)

Certificate 1 of 3 (leaf):
        Name: CN=*.badssl.com
        SANs entries: [*.badssl.com badssl.com]
        Issuer: CN=R3,O=Let's Encrypt,C=US
        Serial: 04:B7:56:01:59:46:10:A8:D8:36:17:C8:06:C2:F9:8D:2A:46
        Issued On: 2022-05-17 14:07:56 +0000 UTC
        Expiration: 2022-08-15 14:07:55 +0000 UTC
        Status: [OK] 50d 0h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=R3,O=Let's Encrypt,C=US
        SANs entries: []
        Issuer: CN=ISRG Root X1,O=Internet Security Research Group,C=US
        Serial: 91:2B:08:4A:CF:0C:18:A7:53:F6:D6:2E:25:A7:5F:5A
        Issued On: 2020-09-04 00:00:00 +0000 UTC
        Expiration: 2025-09-15 16:00:00 +0000 UTC
        Status: [OK] 1177d 2h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=ISRG Root X1,O=Internet Security Research Group,C=US
        SANs entries: []
        Issuer: CN=DST Root CA X3,O=Digital Signature Trust Co.
        Serial: 40:01:77:21:37:D4:E9:42:B8:EE:76:AA:3C:64:0A:B7
        Issued On: 2021-01-20 19:14:03 +0000 UTC
        Expiration: 2024-09-30 18:14:03 +0000 UTC
        Status: [OK] 827d 4h remaining

[OK] Hostname validation using value "badssl.com" successful for leaf certificate
```

#### Explicitly ignoring validation check results

##### `expiration`

Here we use the `--ignore-validation-result` flag with the `expiration`
keyword in order to *explicitly* ignore expiration date validation results
when determining the final plugin state.

This could be useful for setting up a service check that focuses exclusively
on another validation criteria such as hostname or SANs list entries; instead
of having a comprehensive "check everything" certificate check, this could
allow a sysadmin to check criteria separately.

```console
$ check_cert --server expired.badssl.com --port 443 --ignore-validation-result expiration
OK: Hostname validation using value "expired.badssl.com" successful for leaf certificate [checks: 2 IGNORED (SANs List, Expiration), 0 FAILED, 1 SUCCESSFUL (Hostname)]

3 certs retrieved for service running on expired.badssl.com (104.154.89.105) at port 443 using host value "expired.badssl.com"


PROBLEM RESULTS:

* None


IGNORED RESULTS:

[--] Expiration validation ignored: leaf cert "*.badssl.com" expired 2631d 14h ago (on 2015-04-12 23:59:59 +0000 UTC)

Certificate 1 of 3 (leaf):
        Name: CN=*.badssl.com,OU=Domain Control Validated+OU=PositiveSSL Wildcard
        SANs entries: [*.badssl.com badssl.com]
        Issuer: CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        Serial: 4A:E7:95:49:FA:9A:BE:3F:10:0F:17:A4:78:E1:69:09
        Issued On: 2015-04-09 00:00:00 +0000 UTC
        Expiration: 2015-04-12 23:59:59 +0000 UTC
        Status: [EXPIRED] 2631d 14h ago

Certificate 2 of 3 (intermediate):
        Name: CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        SANs entries: []
        Issuer: CN=COMODO RSA Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        Serial: 2B:2E:6E:EA:D9:75:36:6C:14:8A:6E:DB:A3:7C:8C:07
        Issued On: 2014-02-12 00:00:00 +0000 UTC
        Expiration: 2029-02-11 23:59:59 +0000 UTC
        Status: [OK] 2422d 9h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=COMODO RSA Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        SANs entries: []
        Issuer: CN=AddTrust External CA Root,OU=AddTrust External TTP Network,O=AddTrust AB,C=SE
        Serial: 27:66:EE:56:EB:49:F3:8E:AB:D7:70:A2:FC:84:DE:22
        Issued On: 2000-05-30 10:48:38 +0000 UTC
        Expiration: 2020-05-30 10:48:38 +0000 UTC
        Status: [EXPIRED] 757d 3h ago

[--] SANs List validation ignored: 0 SANs entries specified, 2 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]


SUCCESS RESULTS:

[OK] Hostname validation using value "expired.badssl.com" successful for leaf certificate

 | 'time'=493ms;;;;
```

##### `hostname`

Here we use the `--ignore-validation-result` flag with the `hostname` keyword
in order to *explicitly* ignore hostname validation results when determining
the final plugin state.

This could be useful for setting up a service check that focuses exclusively
on another validation criteria such as expiration date or SANs list entries;
instead of having a comprehensive "check everything" certificate check, this
could allow a sysadmin to check criteria separately.

```console
$ check_cert --server wrong.host.badssl.com --port 443 --ignore-validation-result hostname
OK: Expiration validation successful: leaf cert "*.badssl.com" expires next with 49d 23h remaining (until 2022-08-15 14:07:55 +0000 UTC) [checks: 2 IGNORED (Hostname, SANs List), 0 FAILED, 1 SUCCESSFUL (Expiration)]

3 certs retrieved for service running on wrong.host.badssl.com (104.154.89.105) at port 443 using host value "wrong.host.badssl.com"


PROBLEM RESULTS:

* None


IGNORED RESULTS:

[--] Hostname validation using value "wrong.host.badssl.com" ignored for leaf cert

[--] SANs List validation ignored: 0 SANs entries specified, 2 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]


SUCCESS RESULTS:

[OK] Expiration validation successful: leaf cert "*.badssl.com" expires next with 49d 23h remaining (until 2022-08-15 14:07:55 +0000 UTC)

Certificate 1 of 3 (leaf):
        Name: CN=*.badssl.com
        SANs entries: [*.badssl.com badssl.com]
        Issuer: CN=R3,O=Let's Encrypt,C=US
        Serial: 04:B7:56:01:59:46:10:A8:D8:36:17:C8:06:C2:F9:8D:2A:46
        Issued On: 2022-05-17 14:07:56 +0000 UTC
        Expiration: 2022-08-15 14:07:55 +0000 UTC
        Status: [OK] 49d 23h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=R3,O=Let's Encrypt,C=US
        SANs entries: []
        Issuer: CN=ISRG Root X1,O=Internet Security Research Group,C=US
        Serial: 91:2B:08:4A:CF:0C:18:A7:53:F6:D6:2E:25:A7:5F:5A
        Issued On: 2020-09-04 00:00:00 +0000 UTC
        Expiration: 2025-09-15 16:00:00 +0000 UTC
        Status: [OK] 1177d 1h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=ISRG Root X1,O=Internet Security Research Group,C=US
        SANs entries: []
        Issuer: CN=DST Root CA X3,O=Digital Signature Trust Co.
        Serial: 40:01:77:21:37:D4:E9:42:B8:EE:76:AA:3C:64:0A:B7
        Issued On: 2021-01-20 19:14:03 +0000 UTC
        Expiration: 2024-09-30 18:14:03 +0000 UTC
        Status: [OK] 827d 3h remaining

 | 'time'=407ms;;;;
```

##### `sans`

Here we use the `--ignore-validation-result` flag with the `sans` keyword in
order to *explicitly* ignore SANs list validation results when determining the
final plugin state.

This could be useful for setting up a service check that focuses exclusively
on another validation criteria such as expiration date or hostname; instead of
having a comprehensive "check everything" certificate check, this could allow
a sysadmin to check criteria separately.

That said, SANs list validation is performed only if the sysadmin specifies
SANs entries to validate.

```console
$ check_cert --server badssl.com --port 443 --ignore-validation-result sans
OK: Expiration validation successful: leaf cert "*.badssl.com" expires next with 49d 23h remaining (until 2022-08-15 14:07:55 +0000 UTC) [checks: 1 IGNORED (SANs List), 0 FAILED, 2 SUCCESSFUL (Hostname, Expiration)]

3 certs retrieved for service running on badssl.com (104.154.89.105) at port 443 using host value "badssl.com"


PROBLEM RESULTS:

* None


IGNORED RESULTS:

[--] SANs List validation ignored: 0 SANs entries specified, 2 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]


SUCCESS RESULTS:

[OK] Expiration validation successful: leaf cert "*.badssl.com" expires next with 49d 23h remaining (until 2022-08-15 14:07:55 +0000 UTC)

Certificate 1 of 3 (leaf):
        Name: CN=*.badssl.com
        SANs entries: [*.badssl.com badssl.com]
        Issuer: CN=R3,O=Let's Encrypt,C=US
        Serial: 04:B7:56:01:59:46:10:A8:D8:36:17:C8:06:C2:F9:8D:2A:46
        Issued On: 2022-05-17 14:07:56 +0000 UTC
        Expiration: 2022-08-15 14:07:55 +0000 UTC
        Status: [OK] 49d 23h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=R3,O=Let's Encrypt,C=US
        SANs entries: []
        Issuer: CN=ISRG Root X1,O=Internet Security Research Group,C=US
        Serial: 91:2B:08:4A:CF:0C:18:A7:53:F6:D6:2E:25:A7:5F:5A
        Issued On: 2020-09-04 00:00:00 +0000 UTC
        Expiration: 2025-09-15 16:00:00 +0000 UTC
        Status: [OK] 1177d 1h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=ISRG Root X1,O=Internet Security Research Group,C=US
        SANs entries: []
        Issuer: CN=DST Root CA X3,O=Digital Signature Trust Co.
        Serial: 40:01:77:21:37:D4:E9:42:B8:EE:76:AA:3C:64:0A:B7
        Issued On: 2021-01-20 19:14:03 +0000 UTC
        Expiration: 2024-09-30 18:14:03 +0000 UTC
        Status: [OK] 827d 3h remaining

[OK] Hostname validation using value "badssl.com" successful for leaf certificate

 | 'time'=486ms;;;;
```

##### `expiration`, `hostname`, `sans`

This example shows using the `--ignore-validation-result` flag with all
supported keywords in order to *explicitly* ignore all validation check
results.

Practical use may be limited, but support for this scenario was added in case
a sysadmin wishes to provide an "informational only" monitoring entry for a
certificate chain.

```console
$ check_cert --server wrong.host.badssl.com --dns-name badssl.com --port 443 --ignore-validation-result expiration,hostname,sans
OK: Expiration validation ignored: leaf cert "*.badssl.com" expires next with 49d 23h remaining (until 2022-08-15 14:07:55 +0000 UTC) [checks: 3 IGNORED (Expiration, Hostname, SANs List), 0 FAILED, 0 SUCCESSFUL]

3 certs retrieved for service running on wrong.host.badssl.com (104.154.89.105) at port 443 using host value "badssl.com"


PROBLEM RESULTS:

* None


IGNORED RESULTS:

[--] Expiration validation ignored: leaf cert "*.badssl.com" expires next with 49d 23h remaining (until 2022-08-15 14:07:55 +0000 UTC)

Certificate 1 of 3 (leaf):
        Name: CN=*.badssl.com
        SANs entries: [*.badssl.com badssl.com]
        Issuer: CN=R3,O=Let's Encrypt,C=US
        Serial: 04:B7:56:01:59:46:10:A8:D8:36:17:C8:06:C2:F9:8D:2A:46
        Issued On: 2022-05-17 14:07:56 +0000 UTC
        Expiration: 2022-08-15 14:07:55 +0000 UTC
        Status: [OK] 49d 23h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=R3,O=Let's Encrypt,C=US
        SANs entries: []
        Issuer: CN=ISRG Root X1,O=Internet Security Research Group,C=US
        Serial: 91:2B:08:4A:CF:0C:18:A7:53:F6:D6:2E:25:A7:5F:5A
        Issued On: 2020-09-04 00:00:00 +0000 UTC
        Expiration: 2025-09-15 16:00:00 +0000 UTC
        Status: [OK] 1177d 1h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=ISRG Root X1,O=Internet Security Research Group,C=US
        SANs entries: []
        Issuer: CN=DST Root CA X3,O=Digital Signature Trust Co.
        Serial: 40:01:77:21:37:D4:E9:42:B8:EE:76:AA:3C:64:0A:B7
        Issued On: 2021-01-20 19:14:03 +0000 UTC
        Expiration: 2024-09-30 18:14:03 +0000 UTC
        Status: [OK] 827d 4h remaining

[--] Hostname validation using value "badssl.com" ignored for leaf cert

[--] SANs List validation ignored: 0 SANs entries specified, 2 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]


SUCCESS RESULTS:

* None

 | 'time'=408ms;;;;
```

#### Reviewing a certificate file

As with the `lscert` tool, this plugin supports evaluating a certificate chain
contained within a file.

First, we obtain a cert. It's likely that there is already an abundant local
collection of certificates available to review, but here is how you could
fetch a leaf certificate from a remote system and then review it locally.

Until GH-171 is implemented we use `openssl s_client` to fetch the leaf
certificate for google.com:

```console
$ echo -n | openssl s_client -connect www.google.com:443 -servername google.com | openssl x509 > google.com.cert
depth=2 C = US, O = Google Trust Services LLC, CN = GTS Root R1
verify return:1
depth=1 C = US, O = Google Trust Services LLC, CN = GTS CA 1C3
verify return:1
depth=0 CN = *.google.com
verify return:1
DONE
```

We then use the `--filename` flag to review the cert:

```console
$ check_cert --filename google.com.cert
5:55AM ERR ../../../../../t/github/check-cert/cmd/check_cert/main.go:413 > validation checks failed for certificate chain error="summary: 1 of 3 validation checks failed" age_critical=15 age_warning=30 app_type=plugin apply_expiration_validation_results=true apply_hostname_validation_results=true apply_sans_list_validation_results=false cert_check_timeout=10s checks_failed=1 checks_ignored=1 checks_successful=1 checks_total=3 expected_sans_entries= filename=google.com.cert logging_level=info port=443 server= version="check-cert x.y.z (https://github.com/atc0005/check-cert)"
CRITICAL: Hostname validation using value "" failed for leaf certificate [checks: 1 IGNORED (SANs List), 1 FAILED (Hostname), 1 SUCCESSFUL (Expiration)]

**VALIDATION ERRORS**

* server or dns name values are required for hostname verification: missing expected value

**VALIDATION CHECKS REPORT**

1 certs found in google.com.cert


PROBLEM RESULTS:

[!!] Hostname validation using value "" failed for leaf certificate

Consider updating the service check or command definition to specify the website FQDN instead of the host FQDN using the DNS Name or server flags. E.g., use 'www.example.org' instead of 'host7.example.com' in order to allow the remote server to select the correct certificate instead of using the default certificate.


IGNORED RESULTS:

[--] SANs List validation ignored: 0 SANs entries specified, 130 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]


SUCCESS RESULTS:

[OK] Expiration validation successful: leaf cert "*.google.com" expires next with 62d 21h remaining (until 2022-08-29 08:29:45 +0000 UTC)

Certificate 1 of 1 (leaf):
        Name: CN=*.google.com
        SANs entries: [*.google.com *.appengine.google.com *.bdn.dev *.cloud.google.com *.crowdsource.google.com *.datacompute.google.com *.google.ca *.google.cl *.google.co.in *.google.co.jp *.google.co.uk *.google.com.ar *.google.com.au *.google.com.br *.google.com.co *.google.com.mx *.google.com.tr *.google.com.vn *.google.de *.google.es *.google.fr *.google.hu *.google.it *.google.nl *.google.pl *.google.pt *.googleadapis.com *.googleapis.cn *.googlevideo.com *.gstatic.cn *.gstatic-cn.com googlecnapps.cn *.googlecnapps.cn googleapps-cn.com *.googleapps-cn.com gkecnapps.cn *.gkecnapps.cn googledownloads.cn *.googledownloads.cn recaptcha.net.cn *.recaptcha.net.cn recaptcha-cn.net *.recaptcha-cn.net widevine.cn *.widevine.cn ampproject.org.cn *.ampproject.org.cn ampproject.net.cn *.ampproject.net.cn google-analytics-cn.com *.google-analytics-cn.com googleadservices-cn.com *.googleadservices-cn.com googlevads-cn.com *.googlevads-cn.com googleapis-cn.com *.googleapis-cn.com googleoptimize-cn.com *.googleoptimize-cn.com doubleclick-cn.net *.doubleclick-cn.net *.fls.doubleclick-cn.net *.g.doubleclick-cn.net doubleclick.cn *.doubleclick.cn *.fls.doubleclick.cn *.g.doubleclick.cn dartsearch-cn.net *.dartsearch-cn.net googletraveladservices-cn.com *.googletraveladservices-cn.com googletagservices-cn.com *.googletagservices-cn.com googletagmanager-cn.com *.googletagmanager-cn.com googlesyndication-cn.com *.googlesyndication-cn.com *.safeframe.googlesyndication-cn.com app-measurement-cn.com *.app-measurement-cn.com gvt1-cn.com *.gvt1-cn.com gvt2-cn.com *.gvt2-cn.com 2mdn-cn.net *.2mdn-cn.net googleflights-cn.net *.googleflights-cn.net admob-cn.com *.admob-cn.com *.gstatic.com *.metric.gstatic.com *.gvt1.com *.gcpcdn.gvt1.com *.gvt2.com *.gcp.gvt2.com *.url.google.com *.youtube-nocookie.com *.ytimg.com android.com *.android.com *.flash.android.com g.cn *.g.cn g.co *.g.co goo.gl www.goo.gl google-analytics.com *.google-analytics.com google.com googlecommerce.com *.googlecommerce.com ggpht.cn *.ggpht.cn urchin.com *.urchin.com youtu.be youtube.com *.youtube.com youtubeeducation.com *.youtubeeducation.com youtubekids.com *.youtubekids.com yt.be *.yt.be android.clients.google.com developer.android.google.cn developers.android.google.cn source.android.google.cn]
        Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        Serial: 58:AC:E5:94:0B:41:78:64:12:9D:53:1A:39:CB:00:67
        Issued On: 2022-06-06 08:29:46 +0000 UTC
        Expiration: 2022-08-29 08:29:45 +0000 UTC
        Status: [OK] 62d 21h remaining

 | 'time'=2ms;;;;
```

We received a hostname validation error, so we pick a SANs entry that the
certificate should be valid for and specify that:

```console
$ check_cert --filename google.com.cert --dns-name android.com
OK: Expiration validation successful: leaf cert "*.google.com" expires next with 62d 21h remaining (until 2022-08-29 08:29:45 +0000 UTC) [checks: 1 IGNORED (SANs List), 0 FAILED, 2 SUCCESSFUL (Hostname, Expiration)]

1 certs found in google.com.cert


PROBLEM RESULTS:

* None


IGNORED RESULTS:

[--] SANs List validation ignored: 0 SANs entries specified, 130 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]


SUCCESS RESULTS:

[OK] Expiration validation successful: leaf cert "*.google.com" expires next with 62d 21h remaining (until 2022-08-29 08:29:45 +0000 UTC)

Certificate 1 of 1 (leaf):
        Name: CN=*.google.com
        SANs entries: [*.google.com *.appengine.google.com *.bdn.dev *.cloud.google.com *.crowdsource.google.com *.datacompute.google.com *.google.ca *.google.cl *.google.co.in *.google.co.jp *.google.co.uk *.google.com.ar *.google.com.au *.google.com.br *.google.com.co *.google.com.mx *.google.com.tr *.google.com.vn *.google.de *.google.es *.google.fr *.google.hu *.google.it *.google.nl *.google.pl *.google.pt *.googleadapis.com *.googleapis.cn *.googlevideo.com *.gstatic.cn *.gstatic-cn.com googlecnapps.cn *.googlecnapps.cn googleapps-cn.com *.googleapps-cn.com gkecnapps.cn *.gkecnapps.cn googledownloads.cn *.googledownloads.cn recaptcha.net.cn *.recaptcha.net.cn recaptcha-cn.net *.recaptcha-cn.net widevine.cn *.widevine.cn ampproject.org.cn *.ampproject.org.cn ampproject.net.cn *.ampproject.net.cn google-analytics-cn.com *.google-analytics-cn.com googleadservices-cn.com *.googleadservices-cn.com googlevads-cn.com *.googlevads-cn.com googleapis-cn.com *.googleapis-cn.com googleoptimize-cn.com *.googleoptimize-cn.com doubleclick-cn.net *.doubleclick-cn.net *.fls.doubleclick-cn.net *.g.doubleclick-cn.net doubleclick.cn *.doubleclick.cn *.fls.doubleclick.cn *.g.doubleclick.cn dartsearch-cn.net *.dartsearch-cn.net googletraveladservices-cn.com *.googletraveladservices-cn.com googletagservices-cn.com *.googletagservices-cn.com googletagmanager-cn.com *.googletagmanager-cn.com googlesyndication-cn.com *.googlesyndication-cn.com *.safeframe.googlesyndication-cn.com app-measurement-cn.com *.app-measurement-cn.com gvt1-cn.com *.gvt1-cn.com gvt2-cn.com *.gvt2-cn.com 2mdn-cn.net *.2mdn-cn.net googleflights-cn.net *.googleflights-cn.net admob-cn.com *.admob-cn.com *.gstatic.com *.metric.gstatic.com *.gvt1.com *.gcpcdn.gvt1.com *.gvt2.com *.gcp.gvt2.com *.url.google.com *.youtube-nocookie.com *.ytimg.com android.com *.android.com *.flash.android.com g.cn *.g.cn g.co *.g.co goo.gl www.goo.gl google-analytics.com *.google-analytics.com google.com googlecommerce.com *.googlecommerce.com ggpht.cn *.ggpht.cn urchin.com *.urchin.com youtu.be youtube.com *.youtube.com youtubeeducation.com *.youtubeeducation.com youtubekids.com *.youtubekids.com yt.be *.yt.be android.clients.google.com developer.android.google.cn developers.android.google.cn source.android.google.cn]
        Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        Serial: 58:AC:E5:94:0B:41:78:64:12:9D:53:1A:39:CB:00:67
        Issued On: 2022-06-06 08:29:46 +0000 UTC
        Expiration: 2022-08-29 08:29:45 +0000 UTC
        Status: [OK] 62d 21h remaining

[OK] Hostname validation using value "android.com" successful for leaf certificate

 | 'time'=2ms;;;;
```

### `lscert` CLI tool

#### Positional Argument

These short examples illustrate using the support for a positional argument to
quickly examine a certificate chain. If flags are specified they *must* be
specified before the positional argument (due to limitations in the Go
standard library `flag` package).

##### Simple

```console
$ lscert pkg.go.dev


======================
CERTIFICATES | SUMMARY
======================

- OK: 3 certs retrieved for service running on pkg.go.dev (34.149.140.181) at port 443 using host value "pkg.go.dev"
- OK: Hostname validation using value "pkg.go.dev" successful for leaf certificate
- OK: SANs List validation ignored: 0 SANs entries specified, 1 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]
- OK: Expiration validation successful: leaf cert "pkg.go.dev" expires next with 47d 8h remaining (until 2022-10-03 20:00:07 +0000 UTC) [EXPIRED: 0, EXPIRING: 0, OK: 3]


============================
CERTIFICATES | CHAIN DETAILS
============================

Certificate 1 of 3 (leaf):
        Name: CN=pkg.go.dev
        SANs entries: [pkg.go.dev]
        Issuer: CN=GTS CA 1D4,O=Google Trust Services LLC,C=US
        Serial: F6:04:26:D7:51:E6:52:62:09:AE:04:7B:9C:23:F2:86
        Issued On: 2022-07-05 20:00:08 +0000 UTC
        Expiration: 2022-10-03 20:00:07 +0000 UTC
        Status: [OK] 47d 8h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=GTS CA 1D4,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        Serial: 02:00:8E:B2:02:33:36:65:8B:64:CD:DB:9B
        Issued On: 2020-08-13 00:00:42 +0000 UTC
        Expiration: 2027-09-30 00:00:42 +0000 UTC
        Status: [OK] 1869d 12h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE
        Serial: 77:BD:0D:6C:DB:36:F9:1A:EA:21:0F:C4:F0:58:D3:0D
        Issued On: 2020-06-19 00:00:42 +0000 UTC
        Expiration: 2028-01-28 00:00:42 +0000 UTC
        Status: [OK] 1989d 12h remaining
```

##### Flags and Argument

```console
$ lscert --dns-name one.one.one.one --age-warning 60 --age-critical 30 1.1.1.1


======================
CERTIFICATES | SUMMARY
======================

- OK: 2 certs retrieved for service running on 1.1.1.1 at port 443
- OK: Hostname validation using value "one.one.one.one" successful for leaf certificate
- OK: SANs List validation ignored: 0 SANs entries specified, 3 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]
- OK: Expiration validation successful: leaf cert "cloudflare-dns.com" expires next with 69d 12h remaining (until 2022-10-25 23:59:59 +0000 UTC) [EXPIRED: 0, EXPIRING: 0, OK: 2]


============================
CERTIFICATES | CHAIN DETAILS
============================

Certificate 1 of 2 (leaf):
        Name: CN=cloudflare-dns.com,O=Cloudflare\, Inc.,L=San Francisco,ST=California,C=US
        SANs entries: [cloudflare-dns.com *.cloudflare-dns.com one.one.one.one]
        Issuer: CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1,O=DigiCert Inc,C=US
        Serial: 0F:75:A3:6D:32:C1:6B:03:C7:CA:5F:5F:71:4A:03:70
        Issued On: 2021-10-25 00:00:00 +0000 UTC
        Expiration: 2022-10-25 23:59:59 +0000 UTC
        Status: [OK] 69d 12h remaining

Certificate 2 of 2 (intermediate):
        Name: CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1,O=DigiCert Inc,C=US
        SANs entries: []
        Issuer: CN=DigiCert Global Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
        Serial: 07:F2:F3:5C:87:A8:77:AF:7A:EF:E9:47:99:35:25:BD
        Issued On: 2021-04-14 00:00:00 +0000 UTC
        Expiration: 2031-04-13 23:59:59 +0000 UTC
        Status: [OK] 3161d 12h remaining
```

#### OK results

This example shows using the CLI app to perform the same initial check that we
performed earlier using the Nagios plugin.

NOTE: Use the `--verbose` flag to expose further details.

```ShellSession
$ lscert --server www.google.com --port 443 --age-critical 30 --age-warning 50


======================
CERTIFICATES | SUMMARY
======================

- OK: 3 certs retrieved for service running on www.google.com (64.233.185.99) at port 443 using host value "www.google.com"
- OK: Hostname validation using value "www.google.com" successful for leaf certificate
- OK: SANs List validation ignored: 0 SANs entries specified, 1 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]
- OK: Expiration validation successful: leaf cert "www.google.com" expires next with 65d 23h remaining (until 2022-08-29 09:39:59 +0000 UTC) [EXPIRED: 0, EXPIRING: 0, OK: 3]


============================
CERTIFICATES | CHAIN DETAILS
============================

Certificate 1 of 3 (leaf):
        Name: CN=www.google.com
        SANs entries: [www.google.com]
        Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        Serial: 9F:07:4B:11:74:5F:16:FC:12:23:75:FA:58:79:93:F0
        Issued On: 2022-06-06 09:40:00 +0000 UTC
        Expiration: 2022-08-29 09:39:59 +0000 UTC
        Status: [OK] 65d 23h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        Serial: 02:03:BC:53:59:6B:34:C7:18:F5:01:50:66
        Issued On: 2020-08-13 00:00:42 +0000 UTC
        Expiration: 2027-09-30 00:00:42 +0000 UTC
        Status: [OK] 1923d 13h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE
        Serial: 77:BD:0D:6C:DB:36:F9:1A:EA:21:0F:C4:F0:58:D3:0D
        Issued On: 2020-06-19 00:00:42 +0000 UTC
        Expiration: 2028-01-28 00:00:42 +0000 UTC
        Status: [OK] 2043d 13h remaining
```

#### WARNING results

NOTE: Use the `--verbose` flag to expose further details.

```ShellSession
$ lscert --server www.google.com --port 443 --age-critical 30 --age-warning 70


======================
CERTIFICATES | SUMMARY
======================

- OK: 3 certs retrieved for service running on www.google.com (64.233.185.99) at port 443 using host value "www.google.com"
- OK: Hostname validation using value "www.google.com" successful for leaf certificate
- OK: SANs List validation ignored: 0 SANs entries specified, 1 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]
- WARNING: Expiration validation failed: leaf cert "www.google.com" expires next with 65d 23h remaining (until 2022-08-29 09:39:59 +0000 UTC) [EXPIRED: 0, EXPIRING: 1, OK: 2]


============================
CERTIFICATES | CHAIN DETAILS
============================

Certificate 1 of 3 (leaf):
        Name: CN=www.google.com
        SANs entries: [www.google.com]
        Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        Serial: 9F:07:4B:11:74:5F:16:FC:12:23:75:FA:58:79:93:F0
        Issued On: 2022-06-06 09:40:00 +0000 UTC
        Expiration: 2022-08-29 09:39:59 +0000 UTC
        Status: [WARNING] 65d 23h remaining

Certificate 2 of 3 (intermediate):
        Name: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        Serial: 02:03:BC:53:59:6B:34:C7:18:F5:01:50:66
        Issued On: 2020-08-13 00:00:42 +0000 UTC
        Expiration: 2027-09-30 00:00:42 +0000 UTC
        Status: [OK] 1923d 13h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        SANs entries: []
        Issuer: CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE
        Serial: 77:BD:0D:6C:DB:36:F9:1A:EA:21:0F:C4:F0:58:D3:0D
        Issued On: 2020-06-19 00:00:42 +0000 UTC
        Expiration: 2028-01-28 00:00:42 +0000 UTC
        Status: [OK] 2043d 13h remaining
```

In general, the differences between the `OK` and `WARNING` output for the two
tools is minor. However, unlike the `check_cert` Nagios plugin where we are
limited to one line of summary output, the `lscert` CLI tool doesn't share the
same output requirements and can be more expressive (e.g., such as the summary
section to highlight particular items of interest).

#### CRITICAL results

Here we use the expired.badssl.com subdomain to demo the results of
encountering one or more (in this case more) expired certificates in a chain.
Aside from the FQDN, all default options (including the port) are used.

NOTE: Use the `--verbose` flag to expose further details.

```ShellSession
$ lscert --server expired.badssl.com


======================
CERTIFICATES | SUMMARY
======================

- OK: 3 certs retrieved for service running on expired.badssl.com (104.154.89.105) at port 443 using host value "expired.badssl.com"
- OK: Hostname validation using value "expired.badssl.com" successful for leaf certificate
- OK: SANs List validation ignored: 0 SANs entries specified, 2 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]
- CRITICAL: Expiration validation failed: leaf cert "*.badssl.com" expired 2629d 10h ago (on 2015-04-12 23:59:59 +0000 UTC) [EXPIRED: 2, EXPIRING: 0, OK: 1]


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
        Status: [EXPIRED] 2629d 10h ago

Certificate 2 of 3 (intermediate):
        Name: CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        SANs entries: []
        Issuer: CN=COMODO RSA Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        Serial: 2B:2E:6E:EA:D9:75:36:6C:14:8A:6E:DB:A3:7C:8C:07
        Issued On: 2014-02-12 00:00:00 +0000 UTC
        Expiration: 2029-02-11 23:59:59 +0000 UTC
        Status: [OK] 2424d 13h remaining

Certificate 3 of 3 (intermediate):
        Name: CN=COMODO RSA Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
        SANs entries: []
        Issuer: CN=AddTrust External CA Root,OU=AddTrust External TTP Network,O=AddTrust AB,C=SE
        Serial: 27:66:EE:56:EB:49:F3:8E:AB:D7:70:A2:FC:84:DE:22
        Issued On: 2000-05-30 10:48:38 +0000 UTC
        Expiration: 2020-05-30 10:48:38 +0000 UTC
        Status: [EXPIRED] 754d 23h ago
```

Some items to note in the `CERTIFICATES | SUMMARY` section:

- the certificate which expired first (leaf cert `*.badssl.com`) is listed
  - chain position
  - expiration summary
  - expiration date
- a quick count of the `EXPIRED`, `EXPIRING` and `OK` certificates
- specific validation checks and actions performed are listed with a brief
  summary of the results

#### Reviewing a certificate file

In addition to retrieving certificates from a networked system (local or
remote), this tool also supported retrieving a certificate chain (one or many
certificates) from a file.

First, we obtain a cert. It's likely that there is already an abundant local
collection of certificates available to review, but here is how you could
fetch a leaf certificate from a remote system and then review it locally.

Until GH-171 is implemented we use `openssl s_client` to fetch the leaf
certificate for google.com:

```console
$ echo -n | openssl s_client -connect www.google.com:443 -servername google.com | openssl x509 > google.com.cert
depth=2 C = US, O = Google Trust Services LLC, CN = GTS Root R1
verify return:1
depth=1 C = US, O = Google Trust Services LLC, CN = GTS CA 1C3
verify return:1
depth=0 CN = *.google.com
verify return:1
DONE
```

We then use the `--filename` flag to review the cert:

```console
$ lscert --filename google.com.cert


======================
CERTIFICATES | SUMMARY
======================

- OK: 1 certs found in google.com.cert
- CRITICAL: Hostname validation using value "" failed for leaf certificate
- OK: SANs List validation ignored: 0 SANs entries specified, 130 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]
- OK: Expiration validation successful: leaf cert "*.google.com" expires next with 62d 21h remaining (until 2022-08-29 08:29:45 +0000 UTC) [EXPIRED: 0, EXPIRING: 0, OK: 1]


============================
CERTIFICATES | CHAIN DETAILS
============================

Certificate 1 of 1 (leaf):
        Name: CN=*.google.com
        SANs entries: [*.google.com *.appengine.google.com *.bdn.dev *.cloud.google.com *.crowdsource.google.com *.datacompute.google.com *.google.ca *.google.cl *.google.co.in *.google.co.jp *.google.co.uk *.google.com.ar *.google.com.au *.google.com.br *.google.com.co *.google.com.mx *.google.com.tr *.google.com.vn *.google.de *.google.es *.google.fr *.google.hu *.google.it *.google.nl *.google.pl *.google.pt *.googleadapis.com *.googleapis.cn *.googlevideo.com *.gstatic.cn *.gstatic-cn.com googlecnapps.cn *.googlecnapps.cn googleapps-cn.com *.googleapps-cn.com gkecnapps.cn *.gkecnapps.cn googledownloads.cn *.googledownloads.cn recaptcha.net.cn *.recaptcha.net.cn recaptcha-cn.net *.recaptcha-cn.net widevine.cn *.widevine.cn ampproject.org.cn *.ampproject.org.cn ampproject.net.cn *.ampproject.net.cn google-analytics-cn.com *.google-analytics-cn.com googleadservices-cn.com *.googleadservices-cn.com googlevads-cn.com *.googlevads-cn.com googleapis-cn.com *.googleapis-cn.com googleoptimize-cn.com *.googleoptimize-cn.com doubleclick-cn.net *.doubleclick-cn.net *.fls.doubleclick-cn.net *.g.doubleclick-cn.net doubleclick.cn *.doubleclick.cn *.fls.doubleclick.cn *.g.doubleclick.cn dartsearch-cn.net *.dartsearch-cn.net googletraveladservices-cn.com *.googletraveladservices-cn.com googletagservices-cn.com *.googletagservices-cn.com googletagmanager-cn.com *.googletagmanager-cn.com googlesyndication-cn.com *.googlesyndication-cn.com *.safeframe.googlesyndication-cn.com app-measurement-cn.com *.app-measurement-cn.com gvt1-cn.com *.gvt1-cn.com gvt2-cn.com *.gvt2-cn.com 2mdn-cn.net *.2mdn-cn.net googleflights-cn.net *.googleflights-cn.net admob-cn.com *.admob-cn.com *.gstatic.com *.metric.gstatic.com *.gvt1.com *.gcpcdn.gvt1.com *.gvt2.com *.gcp.gvt2.com *.url.google.com *.youtube-nocookie.com *.ytimg.com android.com *.android.com *.flash.android.com g.cn *.g.cn g.co *.g.co goo.gl www.goo.gl google-analytics.com *.google-analytics.com google.com googlecommerce.com *.googlecommerce.com ggpht.cn *.ggpht.cn urchin.com *.urchin.com youtu.be youtube.com *.youtube.com youtubeeducation.com *.youtubeeducation.com youtubekids.com *.youtubekids.com yt.be *.yt.be android.clients.google.com developer.android.google.cn developers.android.google.cn source.android.google.cn]
        Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        Serial: 58:AC:E5:94:0B:41:78:64:12:9D:53:1A:39:CB:00:67
        Issued On: 2022-06-06 08:29:46 +0000 UTC
        Expiration: 2022-08-29 08:29:45 +0000 UTC
        Status: [OK] 62d 21h remaining
```

We received a hostname validation error, so we pick a SANs entry that the
certificate should be valid for and specify that:

```console
$ lscert --filename google.com.cert --dns-name youtube.com


======================
CERTIFICATES | SUMMARY
======================

- OK: 1 certs found in google.com.cert
- OK: Hostname validation using value "youtube.com" successful for leaf certificate
- OK: SANs List validation ignored: 0 SANs entries specified, 130 SANs entries on leaf cert [0 EXPECTED, 0 MISSING, 0 UNEXPECTED]
- OK: Expiration validation successful: leaf cert "*.google.com" expires next with 62d 21h remaining (until 2022-08-29 08:29:45 +0000 UTC) [EXPIRED: 0, EXPIRING: 0, OK: 1]


============================
CERTIFICATES | CHAIN DETAILS
============================

Certificate 1 of 1 (leaf):
        Name: CN=*.google.com
        SANs entries: [*.google.com *.appengine.google.com *.bdn.dev *.cloud.google.com *.crowdsource.google.com *.datacompute.google.com *.google.ca *.google.cl *.google.co.in *.google.co.jp *.google.co.uk *.google.com.ar *.google.com.au *.google.com.br *.google.com.co *.google.com.mx *.google.com.tr *.google.com.vn *.google.de *.google.es *.google.fr *.google.hu *.google.it *.google.nl *.google.pl *.google.pt *.googleadapis.com *.googleapis.cn *.googlevideo.com *.gstatic.cn *.gstatic-cn.com googlecnapps.cn *.googlecnapps.cn googleapps-cn.com *.googleapps-cn.com gkecnapps.cn *.gkecnapps.cn googledownloads.cn *.googledownloads.cn recaptcha.net.cn *.recaptcha.net.cn recaptcha-cn.net *.recaptcha-cn.net widevine.cn *.widevine.cn ampproject.org.cn *.ampproject.org.cn ampproject.net.cn *.ampproject.net.cn google-analytics-cn.com *.google-analytics-cn.com googleadservices-cn.com *.googleadservices-cn.com googlevads-cn.com *.googlevads-cn.com googleapis-cn.com *.googleapis-cn.com googleoptimize-cn.com *.googleoptimize-cn.com doubleclick-cn.net *.doubleclick-cn.net *.fls.doubleclick-cn.net *.g.doubleclick-cn.net doubleclick.cn *.doubleclick.cn *.fls.doubleclick.cn *.g.doubleclick.cn dartsearch-cn.net *.dartsearch-cn.net googletraveladservices-cn.com *.googletraveladservices-cn.com googletagservices-cn.com *.googletagservices-cn.com googletagmanager-cn.com *.googletagmanager-cn.com googlesyndication-cn.com *.googlesyndication-cn.com *.safeframe.googlesyndication-cn.com app-measurement-cn.com *.app-measurement-cn.com gvt1-cn.com *.gvt1-cn.com gvt2-cn.com *.gvt2-cn.com 2mdn-cn.net *.2mdn-cn.net googleflights-cn.net *.googleflights-cn.net admob-cn.com *.admob-cn.com *.gstatic.com *.metric.gstatic.com *.gvt1.com *.gcpcdn.gvt1.com *.gvt2.com *.gcp.gvt2.com *.url.google.com *.youtube-nocookie.com *.ytimg.com android.com *.android.com *.flash.android.com g.cn *.g.cn g.co *.g.co goo.gl www.goo.gl google-analytics.com *.google-analytics.com google.com googlecommerce.com *.googlecommerce.com ggpht.cn *.ggpht.cn urchin.com *.urchin.com youtu.be youtube.com *.youtube.com youtubeeducation.com *.youtubeeducation.com youtubekids.com *.youtubekids.com yt.be *.yt.be android.clients.google.com developer.android.google.cn developers.android.google.cn source.android.google.cn]
        Issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
        Serial: 58:AC:E5:94:0B:41:78:64:12:9D:53:1A:39:CB:00:67
        Issued On: 2022-06-06 08:29:46 +0000 UTC
        Expiration: 2022-08-29 08:29:45 +0000 UTC
        Status: [OK] 62d 21h remaining
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
  1. `www.example.com`
  1. `www.example.com`
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
