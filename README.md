<!-- omit in toc -->
# check-certs

Go-based tooling to check/verify certs (e.g., as part of a Nagios service check)

<!-- omit in toc -->
## Table of Contents

- [Overview](#overview)
  - [check_certs](#check_certs)
  - [lscert](#lscert)
- [Features](#features)
- [Changelog](#changelog)
- [Requirements](#requirements)
  - [Building source code](#building-source-code)
  - [Running](#running)
- [Installation](#installation)
- [Configuration options](#configuration-options)
  - [Shared](#shared)
  - [`check_cert`](#check_cert)
  - [`lscert`](#lscert-1)
- [Examples](#examples)
  - [`check_cert` Nagios plugin](#check_cert-nagios-plugin)
  - [`lscert` CLI tool](#lscert-cli-tool)
- [License](#license)
- [References](#references)

## Overview

This repo contains various tools used to monitor/validate certificates.

| Tool Name     | Status | Description                                                                            |
| ------------- | ------ | -------------------------------------------------------------------------------------- |
| `check_certs` | Alpha  | Nagios plugin used to monitor certificate chains                                       |
| `lscert`      | Alpha  | Small CLI app used to generate a summary of certificate metadata and expiration status |

### check_certs

Nagios plugin used to monitor certificate chains. In addition to the features
shared with `lscert`, this app also validates the provided hostname against
the certificate Common Name *or* one of the available SANs entries.

The output for this application is designed to provide the one-line summary
needed by Nagios for quick identification of a problem while providing longer,
more detailed information for use in email and Teams notifications
([atc0005/send2teams](https://github.com/atc0005/send2teams)).

### lscert

Small CLI tool to print a *very* basic summary of certificate metadata
provided by a remote service at the specified fully-qualified domain name
(e.g., www.github.com) and port (e.g., 443) or via a local certificate
"bundle" or standalone leaf certificate file

This tool is intended to quickly review the results of replacing a certificate
and/or troubleshoot why connections to a remote system may be failing.

## Features

- Two tools for validating certificates
  - `lscert` CLI tool
    - verify remote certificate-enabled service
    - verify local certificate "bundle" or standalone leaf certificate file
  - `check_cert` Nagios plugin
    - verify remote certificate-enabled service

- Check expiration of all certificates in the *provided* certificate chain for
  cert-enabled services
  - not expired
  - expiring "soon"
    - warning threshold
    - critical threshold

- Optional support for verifying SANs entries on a certificate against a
  provided list

- Detailed "report" of findings
  - certificate order
  - certificate type
  - status (OK, CRITICAL, WARNING)
  - SANs entries
  - serial number
  - issuer

- Optional generation of openssl-like text output from target cert-enabled
  service
  - thanks to the `grantae/certinfo` package

- Optional, leveled logging using `rs/zerolog` package
  - JSON-format output (to `stderr`)
  - choice of `disabled`, `panic`, `fatal`, `error`, `warn`, `info` (the
    default), `debug` or `trace`.

- Go modules support (vs classic `GOPATH` setup)

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
   - if using `go build`
     - look in `/tmp/check-cert/`

## Configuration options

### Shared

### `check_cert`

### `lscert`

## Examples

### `check_cert` Nagios plugin

### `lscert` CLI tool

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

<!-- Footnotes here  -->

[repo-url]: <https://github.com/atc0005/check-cert>  "This project's GitHub repo"

[go-docs-download]: <https://golang.org/dl>  "Download Go"

[go-docs-install]: <https://golang.org/doc/install>  "Install Go"

<!-- []: PLACEHOLDER "DESCRIPTION_HERE" -->
