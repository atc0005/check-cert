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

## [v0.1.6] - 2020-09-27

### Added

- First (limited) binary release
  - Built using Go 1.15.2
  - Windows
    - x86
    - x64
  - Linux
    - x86
    - x64

### Changed

- Dependencies
  - built using Go 1.15.2
  - upgrade `atc0005/go-nagios`
    - `v0.4.0` to `v0.5.1`
  - upgrade `actions/checkout`
    - `v2.3.2` to `v2.3.3`
  - upgrade `rs/zerolog`
    - `v1.19.0` to `v1.20.0`

### Fixed

- `ReturnNagiosResults` deferred first, allowed to run last (as intended) to
  handle setting final exit code
- Formatting for `certs.GenerateCertsReport` to place additional whitespace at
  the *end* of each cert chain entry instead of at the beginning
- Linting issue with unused/commented out code formatting

## [v0.1.5] - 2020-09-02

### Fixed

- `lscert`, `check_cert` : TCP connection is not closed after use

## [v0.1.4] - 2020-09-01

### Changed

- Dependencies
  - upgrade `atc0005/go-nagios`
    - `v0.3.0` to `v0.4.0`

- Replace local implementation of `NagiosExitState` type and associated method
  with type/method now provided by the `atc0005/go-nagios` package

### Fixed

- threshold key/value pair whitespace rendering

## [v0.1.3] - 2020-08-22

### Added

- Docker-based GitHub Actions Workflows
  - Replace native GitHub Actions with containers created and managed through
    the `atc0005/go-ci` project.

  - New, primary workflow
    - with parallel linting, testing and building tasks
    - with three Go environments
      - "old stable"
      - "stable"
      - "unstable"
    - Makefile is *not* used in this workflow
    - staticcheck linting using latest stable version provided by the
      `atc0005/go-ci` containers

  - Separate Makefile-based linting and building workflow
    - intended to help ensure that local Makefile-based builds that are
      referenced in project README files continue to work as advertised until
      a better local tool can be discovered/explored further
    - use `golang:latest` container to allow for Makefile-based linting
      tooling installation testing since the `atc0005/go-ci` project provides
      containers with those tools already pre-installed
      - linting tasks use container-provided `golangci-lint` config file
        *except* for the Makefile-driven linting task which continues to use
        the repo-provided copy of the `golangci-lint` configuration file

  - Add Quick Validation workflow
    - run on every push, everything else on pull request updates
    - linting via `golangci-lint` only
    - testing
    - no builds

### Changed

- Disable `golangci-lint` default exclusions

- dependencies
  - `go.mod` Go version
    - updated from `1.13` to `1.14`
  - `actions/setup-go`
    - updated from `v2.1.0` to `v2.1.2`
      - since replaced with Docker containers
  - `actions/setup-node`
    - updated from `v2.1.0` to `v2.1.1`
  - `actions/checkout`
    - updated from `v2.3.1` to `v2.3.2`

- README
  - Link badges to applicable GitHub Actions workflows results

- Linting
  - Local
    - `Makefile`
      - install latest stable `golangci-lint` binary instead of using a fixed
          version
  - CI
    - remove repo-provided copy of `golangci-lint` config file at start of
      linting task in order to force use of Docker container-provided config
      file

### Fixed

- Multiple linting issues exposed when disabling `exclude-use-default` setting

## [v0.1.2] - 2020-07-06

### Added

- The emitted calculations used for `WARNING` and `CRITICAL` thresholds is
  intended as a helpful troubleshooting tool in case the results are not as
  expected
- Enable Dependabot updates
  - GitHub Actions
  - Go Modules
- README
  - Add `CRITICAL` threshold examples by using <https://expired.badssl.com/>
    as the test host
    - many thanks to that project for providing the service!
  - Add `Shared` flags table

### Changed

- GoDoc `Usage` section now points reader to main README for usage details,
  examples instead of duplicating the coverage
  - the concern is that duplication will lead to the GoDoc copy getting out of
    date with the main README

- README
  - Updated examples to reflect changes in this release
  - Add additional coverage for threshold logic
    - how it differs from the official `check_http` plugin
    - `UTC` values (previously local time)
    - emphasize that rounding is *not* used
  - Change flag descriptions for threshold values in an attempt to better
    explain the intent (coupled with the extra section for threshold
    calculations, this should hopefully be clearer)

- Update dependencies
  - `actions/checkout`
    - `v1` to `v2.3.1`
  - `actions/setup-go`
    - `v1` to `v2.1.0`
  - `actions/setup-node`
    - `v1` to `v2.1.0`
  - `atc0005/go-nagios`
    - `v0.2.0` to `v0.3.0`

- `lscert`
  - Tweak "next to expire" and "status overview" details to (hopefully) read
    better at a quick glance
  - Explicitly set `UTC` location for `now` variables
  - Add new output block to list `WarningThreshold` and `CriticalThreshold`
    formatted strings
    - expiration date thresholds in number of days
    - expiration date thresholds in specific dates/times
  - Move potential `WARNING` summary item just below the potential `ERROR`
    summary item, intentionally placing the FYI item last

- `check_cert`
  - rework one-line summary to provide feature parity with `check_http`
    plugin, but with custom details specific to this plugin
    - cert chain position
    - status overview
  - Add `NagiosExitState` struct fields
    - `WarningThreshold`
    - `CriticalThreshold`
  - Add new output block to list `WarningThreshold` and `CriticalThreshold`
    formatted strings
    - expiration date thresholds in number of days
    - expiration date thresholds in specific dates/times
    - when reviewing the email notification (ticket) or looking at the web UI,
      having this information available should help emphasize what values are
      used to determine the current service check state

- `lscert`, `check_cert`
  - replace hard-coded status strings with const references
  - Limit connection error scope

- `internal/certs`
  - Create new `ChainStatus` type to encompass the shared cert details
    computed throughout both `check_cert` and `lscert` applications
  - Update `NextToExpire` func to support including or excluding expired
    certificates depending on the use case
  - Add `ChainSummary` func to handle generating a `ChainStatus` value for use
    throughout the application in place of one-off values

### Fixed

- gitignore
  - Fix patterns for `check_cert` binary to only match at the root of the repo
    and not subdirectories

- README
  - fix typos
  - Remove reference to setting values in a config file (not yet implemented)

- misc fixes, cleanup

- Update various doc comments

- Use shared const for intended date formatting instead of multiple hard-coded
  layout strings

- `lscert`
  - Fix invalid cert count check

- `lscert`, `check_cert`
  - Fix struct field doc comment (referred to wrong field name)
  - Server name: Use CN if set, otherwise first SANs to help prevent empty
    server name in output

- `internal/certs`
  - `GenerateCertsReport` func updated to replace debug `String()` call with
    explicit format

## [v0.1.1] - 2020-06-08

### Fixed

- (GH-17) Fix improper handling of `SKIPSANSCHECKS` keyword for the
  `--sans-entries` flag
- Misc documentation fixes

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

[Unreleased]: https://github.com/atc0005/check-cert/compare/v0.1.6...HEAD
[v0.1.6]: https://github.com/atc0005/check-cert/releases/tag/v0.1.6
[v0.1.5]: https://github.com/atc0005/check-cert/releases/tag/v0.1.5
[v0.1.4]: https://github.com/atc0005/check-cert/releases/tag/v0.1.4
[v0.1.3]: https://github.com/atc0005/check-cert/releases/tag/v0.1.3
[v0.1.2]: https://github.com/atc0005/check-cert/releases/tag/v0.1.2
[v0.1.1]: https://github.com/atc0005/check-cert/releases/tag/v0.1.1
[v0.1.0]: https://github.com/atc0005/check-cert/releases/tag/v0.1.0
