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

## [v0.1.0] - 2020-06-02

Initial release!

This release provides an early release version of a Nagios plugin used to
monitor certificate-enabled services. This plugin will be used to verify that
the certificate used by the monitored service is valid (e.g., complete
certificate chain, expiration dates, etc).

### Placeholder items

List of items that I hope to add in the initial release:

- Generate openssl-like text output from target cert-enabled service
  - thanks to the `grantae/certinfo` package
- Validate leaf certificate only
- Validate certificate chain

### Added

- Check expiration of certificate for cert-enabled services
- Optional, leveled logging using `rs/zerolog` package
  - JSON-format output
  - choice of `disabled`, `panic`, `fatal`, `error`, `warn`, `info` (the
    default), `debug` or `trace`.
- Go modules (vs classic `GOPATH` setup)

[Unreleased]: https://github.com/atc0005/check-cert/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/atc0005/check-cert/releases/tag/v0.1.0
