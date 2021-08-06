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

## [v0.4.5] - 2021-08-06

### Overview

- Dependency updates
- built using Go 1.16.7
  - Statically linked
  - Linux (x86, x64)

### Changed

- Dependencies
  - `Go`
    - `1.16.6` to `1.16.7`
  - `actions/setup-node`
    - updated from `v2.3.2` to `v2.4.0`

## [v0.4.4] - 2021-08-05

### Overview

- Add new flag
- Change existing flag
- Dependency update
- built using Go 1.16.6
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Added

- Implement `verbose` flag
  - expose certificate fingerprints
  - expose `KeyID` and `IssuerKeyID` values
    - previously shown by default

### Changed

- Flags
  - reassign `v` short flag from `version` to `verbose` flag

- Output
  - `KeyID` and `IssuerKeyID` values are now shown only when the `v` short
    flag or `verbose` long flags are specified

- Dependencies
  - `actions/setup-node`
    - updated from `v2.3.0` to `v2.3.2`

## [v0.4.3] - 2021-07-29

### Overview

- Bug fixes
- Dependency updates
- built using Go 1.16.6
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Changed

- dependencies
  - `actions/setup-node`
    - updated from `v2.2.0` to `v2.3.0`

- documentation
  - Add Overview example
  - Refresh `check_cert` examples

### Fixed

- (GH-188, GH-189) Certificates crossing the CRITICAL threshold are not
  flagged as CRITICAL state

## [v0.4.2] - 2021-07-15

### Overview

- Dependency updates
- built using Go 1.16.6
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Added

- Add "canary" Dockerfile to track stable Go releases, serve as a reminder to
  generate fresh binaries

### Changed

- dependencies
  - `Go`
    - `1.15.8` to `1.16.6`
  - `atc0005/go-nagios`
    - `v0.6.0` to `v0.6.1`
  - upgrade `rs/zerolog`
    - `v1.20.0` to `v1.23.0`
  - `actions/setup-node`
    - updated from `v2.1.4` to `v2.2.0`
    - update `node-version` value to always use latest LTS version instead of
      hard-coded version

## [v0.4.1] - 2021-02-21

### Overview

- Bugfixes
- built using Go 1.15.8

### Changed

- Swap out GoDoc badge for pkg.go.dev badge

- dependencies
  - `go.mod` Go version
    - updated from `1.14` to `1.15`
  - built using Go 1.15.8
    - Statically linked
    - Windows (x86, x64)
    - Linux (x86, x64)
  - `atc0005/go-nagios`
    - updated from `v0.5.2` to `v0.6.0`

### Fixed

- Fix Go module path
- Remove Octet Range Addressing test binary

## [v0.4.0] - 2020-12-25

### Overview

Merry Christmas, Happy Holidays and (before long) Happy New Year!

- `all`
  - new: add timestamp field to logger output
  - built using Go 1.15.6
    - Statically linked
    - Windows (x86, x64)
    - Linux (x86, x64)
- `certsum`
  - bug fixes
  - speed improvements
  - new: application timeout

### Added

- `all`
  - add timestamp field to structured logging output
- `certsum`
  - application timeout
    - default value set to help prevent app from "hanging"
    - custom values accepted to allow working around "brittle" or
      non-compliant devices which may take longer than usual to respond to
      scan attempts

### Changed

- `certsum`
  - refactor concurrent scanning implementation to increase speed, reduce
    complexity and help prevent deadlocks between competing tasks
  - increase summary output details

### Fixed

- `certsum`
  - Various potential race conditions and deadlocks

## [v0.3.1] - 2020-12-23

### Overview

- `certsum`
  - minor fixes
  - speed improvements
- built using Go 1.15.6
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Changed

- cert scanning is performed concurrently (estimated 2x speed increase)
- Add timing info to port scanning, cert scanning steps

### Fixed

- Incomplete logging call for port scan error
- Doc comment func name incorrect
- `panic: sync: negative WaitGroup counter`

## [v0.3.0] - 2020-12-21

### Overview

- `certsum`: improved support for specifying hosts
- built using Go 1.15.6
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Added

- `certsum`
  - Add support for partial IP ranges
    - inspired by [nmap's `octet range addressing`
      syntax](https://nmap.org/book/man-target-specification.html)
  - Add support for hostname and FQDN targets

### Changed

- Rename `internal/net` to `internal/netutils`
  - help avoid conflicts with `net` standard library package
- `certsum`: omit results table if no certificate issues found

- Dependencies
  - `actions/setup-node`
    - `v2.1.3` to `v2.1.4`

## [v0.2.0] - 2020-12-16

### Added

- Add IP range cert scanner prototype: `certsum`
- Add support for verifying MD5-RSA signatures

## [v0.1.14] - 2020-12-14

### Fixed

- v1 leaf certificates misidentified as root certs
- v3 leaf certificates marked as "UNKNOWN"

## [v0.1.13] - 2020-12-13

### Fixed

- Self-signed leaf certificate misidentified as root certificate
- Nagios plugin: Logging output intended for debugging mixing with output
  intended for console

## [v0.1.12] - 2020-12-13

### Fixed

- Expired (version 1) CA certificate misidentified as leaf certificate

## [v0.1.11] - 2020-12-13

### Fixed

- README: Examples include serial numbers in wrong format
- Certificate serial number missing leading zero

## [v0.1.10] - 2020-12-12

### Changed

- Dependencies
  - built using Go 1.15.6
    - Statically linked
    - Windows (x86, x64)
    - Linux (x86, x64)
  - `actions/setup-node`
    - `v2.1.2` to `v2.1.3`

### Fixed

- Certificate serial number reported in wrong format
- Refactor config, logging packages
- Makefile: version tagging broken
  - note: did not make it into a public release

## [v0.1.9]- 2020-11-10

### Changed

- Statically linked binary release
  - Built using Go 1.15.3
  - Windows
    - x86
    - x64
  - Linux
    - x86
    - x64

- Dependencies
  - `actions/checkout`
    - `v2.3.3` to `v2.3.4`
  - `atc0005/go-nagios`
    - `v0.5.1` to `v0.5.2`

- Certificate summary
  - Add `Issued On` label with cert `NotBefore` value

- Documentation
  - Add reference link: "How you get multiple TLS certificate chains from a
    server certificate"

## [v0.1.8] - 2020-10-14

### Changed

- Clarify SNI support for systems with multiple certificate chains
  - Update README to expand on behavior and requirements for the `server` and
    `dns-name` flags for hosts with multiple certificates.
  - Add extended Service Check output help text to guide sysadmins when first
    cert in chain fails hostname validation.

## [v0.1.7] - 2020-10-07

### Changed

- Statically linked binary release
  - Built using Go 1.15.2
  - Windows
    - x86
    - x64
  - Linux
    - x86
    - x64

- Dependencies
  - `actions/setup-node`
    - `v2.1.1` to `v2.1.2`

- Add '-trimpath' flag to Makefile build options

### Fixed

- Update CHANGELOG to reflect v0.1.6 binary release
- Makefile generates checksums with qualified path
- Makefile build options do not generate static binaries

## [v0.1.6] - 2020-09-27

### Added

- First (limited) binary release (dynamically linked)
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

[Unreleased]: https://github.com/atc0005/check-cert/compare/v0.4.5...HEAD
[v0.4.5]: https://github.com/atc0005/check-cert/releases/tag/v0.4.5
[v0.4.4]: https://github.com/atc0005/check-cert/releases/tag/v0.4.4
[v0.4.3]: https://github.com/atc0005/check-cert/releases/tag/v0.4.3
[v0.4.2]: https://github.com/atc0005/check-cert/releases/tag/v0.4.2
[v0.4.1]: https://github.com/atc0005/check-cert/releases/tag/v0.4.1
[v0.4.0]: https://github.com/atc0005/check-cert/releases/tag/v0.4.0
[v0.3.1]: https://github.com/atc0005/check-cert/releases/tag/v0.3.1
[v0.3.0]: https://github.com/atc0005/check-cert/releases/tag/v0.3.0
[v0.2.0]: https://github.com/atc0005/check-cert/releases/tag/v0.2.0
[v0.1.14]: https://github.com/atc0005/check-cert/releases/tag/v0.1.14
[v0.1.13]: https://github.com/atc0005/check-cert/releases/tag/v0.1.13
[v0.1.12]: https://github.com/atc0005/check-cert/releases/tag/v0.1.12
[v0.1.11]: https://github.com/atc0005/check-cert/releases/tag/v0.1.11
[v0.1.10]: https://github.com/atc0005/check-cert/releases/tag/v0.1.10
[v0.1.9]: https://github.com/atc0005/check-cert/releases/tag/v0.1.9
[v0.1.8]: https://github.com/atc0005/check-cert/releases/tag/v0.1.8
[v0.1.7]: https://github.com/atc0005/check-cert/releases/tag/v0.1.7
[v0.1.6]: https://github.com/atc0005/check-cert/releases/tag/v0.1.6
[v0.1.5]: https://github.com/atc0005/check-cert/releases/tag/v0.1.5
[v0.1.4]: https://github.com/atc0005/check-cert/releases/tag/v0.1.4
[v0.1.3]: https://github.com/atc0005/check-cert/releases/tag/v0.1.3
[v0.1.2]: https://github.com/atc0005/check-cert/releases/tag/v0.1.2
[v0.1.1]: https://github.com/atc0005/check-cert/releases/tag/v0.1.1
[v0.1.0]: https://github.com/atc0005/check-cert/releases/tag/v0.1.0
