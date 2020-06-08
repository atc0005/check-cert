# Changelog

## Overview

All notable changes to this project will be documented in this file.

The format is based on [Keep a
Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Please [open an issue](https://github.com/atc0005/check-cert/issues) for any
deviations that you spot; I'm still learning!.

## Types of changes

The following types of changes will be recorded in this file:

- `Added` for new features.
- `Changed` for changes in existing functionality.
- `Deprecated` for soon-to-be removed features.
- `Removed` for now removed features.
- `Fixed` for any bug fixes.
- `Security` in case of vulnerabilities.

## [Unreleased]

- placeholder

## [v0.1.0] - 2020-06-07

Initial release!

This release provides an early release version of a Nagios plugin used to
monitor certificate-enabled services. This plugin will be used to verify that
the certificate used by the monitored service is valid (e.g., complete
certificate chain, expiration dates, etc).

### Added

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

- Validate provided hostname against Common Name *or* one of the available
  SANs entries
  - the expected hostname can be supplied by the `--server` flag *or* the
    `--dns-name` flag

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

- Go modules support (vs classic `GOPATH` setup)

[Unreleased]: https://github.com/atc0005/check-cert/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/atc0005/check-cert/releases/tag/v0.1.0
