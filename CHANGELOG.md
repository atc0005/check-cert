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

## [v0.25.2] - 2024-12-05

### Changed

#### Dependency Updates

- (GH-1135) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.21.17 to go-ci-oldstable-build-v0.21.18 in /dependabot/docker/builds
- (GH-1137) Go Dependency: Bump golang.org/x/sys from 0.27.0 to 0.28.0
- (GH-1133) Go Runtime: Bump golang from 1.22.9 to 1.22.10 in /dependabot/docker/go

## [v0.25.1] - 2024-12-03

### Changed

#### Dependency Updates

- (GH-1127) Go Dependency: Bump github.com/atc0005/cert-payload from 0.7.0-alpha.5 to 0.7.0

## [v0.25.0] - 2024-12-02

### Changed

#### Dependency Updates

- (GH-1116) Go Dependency: Bump github.com/atc0005/go-nagios from 0.19.0-alpha.1 to 0.19.0
- (GH-1119) Go Dependency: Bump github.com/atc0005/cert-payload from 0.7.0-alpha.3 to 0.7.0-alpha.4
- (GH-1120) Go Dependency: Bump github.com/atc0005/cert-payload from 0.7.0-alpha.4 to 0.7.0-alpha.5

#### Other

- (GH-1124) Promote cert metadata format 1 to default

## [v0.24.0] - 2024-11-27

### Added

- (GH-1112) Enable plugin output size metric

### Changed

#### Dependency Updates

- (GH-1107) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.21.16 to go-ci-oldstable-build-v0.21.17 in /dependabot/docker/builds
- (GH-1101) Go Dependency: Bump github.com/atc0005/cert-payload from 0.7.0-alpha.1 to 0.7.0-alpha.2
- (GH-1105) Go Dependency: Bump github.com/atc0005/cert-payload from 0.7.0-alpha.2 to 0.7.0-alpha.3

#### Other

- (GH-1109) Note why certs.MaxLifespanInDays truncates result

## [v0.23.0] - 2024-11-25

### Changed

#### Dependency Updates

- (GH-1095) Go Dependency: Bump github.com/atc0005/go-nagios from 0.18.0 to 0.18.1

#### Other

- (GH-1098) Add format version flag & rework payload creation

## [v0.22.1] - 2024-11-20

### Fixed

- (GH-1090) Fix errwrap linting error
- (GH-1089) Rework error handling for cert payload generation

## [v0.22.0] - 2024-11-17

### Added

- (GH-1070) Add indicator of weak cert signature algorithm
- (GH-1068) Add WeakSignatureAlgorithm to cert payload

### Changed

#### Dependency Updates

- (GH-1059) Go Dependency: Bump github.com/atc0005/cert-payload from 0.5.0 to 0.6.1

### Fixed

- (GH-1074) Explicitly list root cert signature algorithms as ignored
- (GH-1067) Fix certificate chain payload generation input
- (GH-1079) Fix SANs entries count payload field logic

## [v0.21.0] - 2024-11-17

### Added

- (GH-1053) Add `--omit-sans-entries` flag alias
- (GH-1050) Add Certificate Signature Algorithm to cert payload
- (GH-1055) Add Certificate Signature Algorithm to output
- (GH-1048) Add SANs entries count to cert metadata payload

### Changed

#### Dependency Updates

- (GH-1038) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.21.15 to go-ci-oldstable-build-v0.21.16 in /dependabot/docker/builds
- (GH-1030) Go Dependency: Bump github.com/atc0005/cert-payload from 0.3.0 to 0.4.0
- (GH-1042) Go Dependency: Bump github.com/atc0005/cert-payload from 0.4.0 to 0.5.0
- (GH-1040) Go Dependency: Bump github.com/atc0005/go-nagios from 0.17.1 to 0.18.0

#### Other

- (GH-1035) Update CertificateChainIssues field

## [v0.20.1] - 2024-11-08

### Changed

#### Dependency Updates

- (GH-1028) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.21.14 to go-ci-oldstable-build-v0.21.15 in /dependabot/docker/builds
- (GH-1023) Go Dependency: Bump github.com/atc0005/go-nagios from 0.17.0 to 0.17.1
- (GH-1019) Go Dependency: Bump golang.org/x/sys from 0.26.0 to 0.27.0
- (GH-1013) Go Runtime: Bump golang from 1.22.8 to 1.22.9 in /dependabot/docker/go

## [v0.20.0] - 2024-11-08

### Added

- (GH-1016) Add flag to support omitting SANs list entries
- (GH-1017) Add support for embedding an encoded JSON payload

### Changed

#### Dependency Updates

- (GH-985) Go Dependency: Bump github.com/atc0005/go-nagios from 0.16.1 to 0.16.2
- (GH-1012) Go Dependency: Bump github.com/atc0005/go-nagios from 0.16.2 to 0.17.0

### Fixed

- (GH-1002) Remove invalid hostname val opt-out notes

## [v0.19.0] - 2024-10-05

### Added

- (GH-976) Add new tool to support copying/filtering certs
- (GH-975) Add SANs list count to cert summary output
- (GH-974) Add support for binary DER format cert files
- (GH-978) Add support for macOS binaries

### Changed

#### Dependency Updates

- (GH-962) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.21.13 to go-ci-oldstable-build-v0.21.14 in /dependabot/docker/builds
- (GH-970) Go Dependency: Bump golang.org/x/sys from 0.25.0 to 0.26.0
- (GH-958) Go Runtime: Bump golang from 1.22.7 to 1.22.8 in /dependabot/docker/go

#### Other

- (GH-977) Update `lscert` hostname validation behavior

## [v0.18.0] - 2024-09-25

### Added

- (GH-947) Add support for ignoring expiring non-leaf certs

## [v0.17.7] - 2024-09-25

### Changed

#### Dependency Updates

- (GH-936) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.21.11 to go-ci-oldstable-build-v0.21.12 in /dependabot/docker/builds
- (GH-939) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.21.12 to go-ci-oldstable-build-v0.21.13 in /dependabot/docker/builds
- (GH-930) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.21.9 to go-ci-oldstable-build-v0.21.11 in /dependabot/docker/builds
- (GH-931) Go Dependency: Bump golang.org/x/sys from 0.24.0 to 0.25.0
- (GH-934) Go Runtime: Bump golang from 1.22.6 to 1.22.7 in /dependabot/docker/go

## [v0.17.6] - 2024-08-21

### Changed

#### Dependency Updates

- (GH-920) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.21.8 to go-ci-oldstable-build-v0.21.9 in /dependabot/docker/builds
- (GH-923) Go Runtime: Bump golang from 1.21.13 to 1.22.6 in /dependabot/docker/go
- (GH-922) Update project to Go 1.22 series

## [v0.17.5] - 2024-08-13

### Changed

#### Dependency Updates

- (GH-897) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.21.4 to go-ci-oldstable-build-v0.21.5 in /dependabot/docker/builds
- (GH-901) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.21.5 to go-ci-oldstable-build-v0.21.6 in /dependabot/docker/builds
- (GH-903) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.21.6 to go-ci-oldstable-build-v0.21.7 in /dependabot/docker/builds
- (GH-911) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.21.7 to go-ci-oldstable-build-v0.21.8 in /dependabot/docker/builds
- (GH-907) Go Dependency: Bump golang.org/x/sys from 0.22.0 to 0.23.0
- (GH-915) Go Dependency: Bump golang.org/x/sys from 0.23.0 to 0.24.0
- (GH-910) Go Runtime: Bump golang from 1.21.12 to 1.21.13 in /dependabot/docker/go

#### Other

- (GH-905) Push `REPO_VERSION` var into containers for builds

## [v0.17.4] - 2024-07-10

### Changed

#### Dependency Updates

- (GH-876) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.20.7 to go-ci-oldstable-build-v0.20.8 in /dependabot/docker/builds
- (GH-879) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.20.8 to go-ci-oldstable-build-v0.21.0 in /dependabot/docker/builds
- (GH-884) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.21.0 to go-ci-oldstable-build-v0.21.2 in /dependabot/docker/builds
- (GH-886) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.21.2 to go-ci-oldstable-build-v0.21.3 in /dependabot/docker/builds
- (GH-890) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.21.3 to go-ci-oldstable-build-v0.21.4 in /dependabot/docker/builds
- (GH-891) Go Dependency: Bump golang.org/x/sys from 0.21.0 to 0.22.0
- (GH-887) Go Runtime: Bump golang from 1.21.11 to 1.21.12 in /dependabot/docker/go

## [v0.17.3] - 2024-06-06

### Changed

#### Dependency Updates

- (GH-856) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.20.4 to go-ci-oldstable-build-v0.20.5 in /dependabot/docker/builds
- (GH-861) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.20.5 to go-ci-oldstable-build-v0.20.6 in /dependabot/docker/builds
- (GH-871) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.20.6 to go-ci-oldstable-build-v0.20.7 in /dependabot/docker/builds
- (GH-859) Go Dependency: Bump github.com/rs/zerolog from 1.32.0 to 1.33.0
- (GH-868) Go Dependency: Bump golang.org/x/sys from 0.20.0 to 0.21.0
- (GH-869) Go Runtime: Bump golang from 1.21.10 to 1.21.11 in /dependabot/docker/go

### Fixed

- (GH-863) Remove inactive maligned linter
- (GH-864) Fix errcheck linting errors

## [v0.17.2] - 2024-05-11

### Changed

#### Dependency Updates

- (GH-843) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.20.1 to go-ci-oldstable-build-v0.20.2 in /dependabot/docker/builds
- (GH-848) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.20.2 to go-ci-oldstable-build-v0.20.3 in /dependabot/docker/builds
- (GH-851) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.20.3 to go-ci-oldstable-build-v0.20.4 in /dependabot/docker/builds
- (GH-842) Go Dependency: Bump golang.org/x/sys from 0.19.0 to 0.20.0
- (GH-847) Go Runtime: Bump golang from 1.21.9 to 1.21.10 in /dependabot/docker/go

## [v0.17.1] - 2024-04-08

### Changed

#### Dependency Updates

- (GH-825) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.15.4 to go-ci-oldstable-build-v0.16.0 in /dependabot/docker/builds
- (GH-827) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.16.0 to go-ci-oldstable-build-v0.16.1 in /dependabot/docker/builds
- (GH-828) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.16.1 to go-ci-oldstable-build-v0.19.0 in /dependabot/docker/builds
- (GH-830) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.19.0 to go-ci-oldstable-build-v0.20.0 in /dependabot/docker/builds
- (GH-834) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.20.0 to go-ci-oldstable-build-v0.20.1 in /dependabot/docker/builds
- (GH-835) Go Dependency: Bump golang.org/x/sys from 0.18.0 to 0.19.0
- (GH-832) Go Runtime: Bump golang from 1.21.8 to 1.21.9 in /dependabot/docker/go

## [v0.17.0] - 2024-03-15

### Added

- (GH-813) Add certificate lifetime metrics
- (GH-814) Add life remaining percentage to expiration status

### Fixed

- (GH-820) Fix nilness govet linting errors

## [v0.16.1] - 2024-03-07

### Changed

#### Dependency Updates

- (GH-804) Add todo/release label to "Go Runtime" PRs
- (GH-800) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.15.3 to go-ci-oldstable-build-v0.15.4 in /dependabot/docker/builds
- (GH-796) Go Dependency: Bump golang.org/x/sys from 0.17.0 to 0.18.0
- (GH-799) Go Runtime: Bump golang from 1.21.7 to 1.21.8 in /dependabot/docker/go

#### Other

- (GH-793) Update README to explicitly mention arm64 builds
- (GH-795) Update README indentation

## [v0.16.0] - 2024-02-27

### Added

- (GH-769) Add Linux ARM64 binaries to build and release process
  - credit: [@GUI](https://github.com/GUI)

### Changed

#### Dependency Updates

- (GH-786) Build Image: Bump atc0005/go-ci from go-ci-oldstable-build-v0.15.2 to go-ci-oldstable-build-v0.15.3 in /dependabot/docker/builds
- (GH-782) canary: bump golang from 1.21.6 to 1.21.7 in /dependabot/docker/go
- (GH-763) docker: bump atc0005/go-ci from go-ci-oldstable-build-v0.14.9 to go-ci-oldstable-build-v0.15.0 in /dependabot/docker/builds
- (GH-776) docker: bump atc0005/go-ci from go-ci-oldstable-build-v0.15.0 to go-ci-oldstable-build-v0.15.1 in /dependabot/docker/builds
- (GH-779) docker: bump atc0005/go-ci from go-ci-oldstable-build-v0.15.1 to go-ci-oldstable-build-v0.15.2 in /dependabot/docker/builds
- (GH-784) Update Dependabot PR prefixes (redux)
- (GH-783) Update Dependabot PR prefixes
- (GH-781) Update project to Go 1.21 series

## [v0.15.9] - 2024-02-14

### Changed

#### Dependency Updates

- (GH-758) canary: bump golang from 1.20.13 to 1.20.14 in /dependabot/docker/go
- (GH-747) docker: bump atc0005/go-ci from go-ci-oldstable-build-v0.14.5 to go-ci-oldstable-build-v0.14.6 in /dependabot/docker/builds
- (GH-759) docker: bump atc0005/go-ci from go-ci-oldstable-build-v0.14.6 to go-ci-oldstable-build-v0.14.9 in /dependabot/docker/builds
- (GH-749) go.mod: bump github.com/rs/zerolog from 1.31.0 to 1.32.0
- (GH-756) go.mod: bump golang.org/x/sys from 0.16.0 to 0.17.0

### Fixed

- (GH-765) Fix linting error and potential race condition

## [v0.15.8] - 2024-01-31

### Changed

#### Dependency Updates

- (GH-730) docker: bump atc0005/go-ci from go-ci-oldstable-build-v0.14.3 to go-ci-oldstable-build-v0.14.4 in /dependabot/docker/builds
- (GH-735) docker: bump atc0005/go-ci from go-ci-oldstable-build-v0.14.4 to go-ci-oldstable-build-v0.14.5 in /dependabot/docker/builds
- (GH-736) go.mod: bump github.com/atc0005/go-nagios from 0.16.0 to 0.16.1

### Fixed

- (GH-743) Fix certsum port flag validation

## [v0.15.7] - 2024-01-19

### Changed

#### Dependency Updates

- (GH-724) canary: bump golang from 1.20.12 to 1.20.13 in /dependabot/docker/go
- (GH-726) docker: bump atc0005/go-ci from go-ci-oldstable-build-v0.14.2 to go-ci-oldstable-build-v0.14.3 in /dependabot/docker/builds
- (GH-721) ghaw: bump github/codeql-action from 2 to 3
- (GH-722) go.mod: bump golang.org/x/sys from 0.15.0 to 0.16.0

## [v0.15.6] - 2023-12-08

### Changed

#### Dependency Updates

- (GH-713) canary: bump golang from 1.20.11 to 1.20.12 in /dependabot/docker/go
- (GH-714) docker: bump atc0005/go-ci from go-ci-oldstable-build-v0.14.1 to go-ci-oldstable-build-v0.14.2 in /dependabot/docker/builds
- (GH-710) go.mod: bump golang.org/x/sys from 0.14.0 to 0.15.0

### Fixed

- (GH-707) Fix textutils.BytesToDelimitedHexStr logic

## [v0.15.5] - 2023-11-15

### Changed

#### Dependency Updates

- (GH-692) canary: bump golang from 1.20.10 to 1.20.11 in /dependabot/docker/go
- (GH-682) canary: bump golang from 1.20.8 to 1.20.10 in /dependabot/docker/go
- (GH-681) docker: bump atc0005/go-ci from go-ci-oldstable-build-v0.13.10 to go-ci-oldstable-build-v0.13.11 in /dependabot/docker/builds
- (GH-683) docker: bump atc0005/go-ci from go-ci-oldstable-build-v0.13.11 to go-ci-oldstable-build-v0.13.12 in /dependabot/docker/builds
- (GH-694) docker: bump atc0005/go-ci from go-ci-oldstable-build-v0.13.12 to go-ci-oldstable-build-v0.14.1 in /dependabot/docker/builds
- (GH-687) go.mod: bump github.com/mattn/go-isatty from 0.0.19 to 0.0.20
- (GH-671) go.mod: bump github.com/rs/zerolog from 1.30.0 to 1.31.0
- (GH-673) go.mod: bump golang.org/x/sys from 0.12.0 to 0.13.0
- (GH-690) go.mod: bump golang.org/x/sys from 0.13.0 to 0.14.0

### Bug Fixes

- (GH-698) Fix goconst linting errors
- (GH-699) Improve cert file parsing

## [v0.15.4] - 2023-10-06

### Changed

#### Dependency Updates

- (GH-656) canary: bump golang from 1.20.7 to 1.20.8 in /dependabot/docker/go
- (GH-646) docker: bump atc0005/go-ci from go-ci-oldstable-build-v0.13.4 to go-ci-oldstable-build-v0.13.5 in /dependabot/docker/builds
- (GH-648) docker: bump atc0005/go-ci from go-ci-oldstable-build-v0.13.5 to go-ci-oldstable-build-v0.13.6 in /dependabot/docker/builds
- (GH-650) docker: bump atc0005/go-ci from go-ci-oldstable-build-v0.13.6 to go-ci-oldstable-build-v0.13.7 in /dependabot/docker/builds
- (GH-657) docker: bump atc0005/go-ci from go-ci-oldstable-build-v0.13.7 to go-ci-oldstable-build-v0.13.8 in /dependabot/docker/builds
- (GH-664) docker: bump atc0005/go-ci from go-ci-oldstable-build-v0.13.8 to go-ci-oldstable-build-v0.13.9 in /dependabot/docker/builds
- (GH-668) docker: bump atc0005/go-ci from go-ci-oldstable-build-v0.13.9 to go-ci-oldstable-build-v0.13.10 in /dependabot/docker/builds
- (GH-655) ghaw: bump actions/checkout from 3 to 4
- (GH-653) go.mod: bump golang.org/x/sys from 0.11.0 to 0.12.0

## [v0.15.3] - 2023-08-16

### Added

- (GH-614) Add initial automated release notes config
- (GH-616) Add initial automated release build workflow

### Changed

- Dependencies
  - `Go`
    - `1.19.11` to `1.20.7`
  - `atc0005/go-ci`
    - `go-ci-oldstable-build-v0.11.0` to `go-ci-oldstable-build-v0.13.4`
  - `rs/zerolog`
    - `v1.29.1` to `v1.30.0`
  - `golang.org/x/sys`
    - `v0.10.0` to `v0.11.0`
- (GH-618) Update Dependabot config to monitor both branches
- (GH-640) Update project to Go 1.20 series

### Fixed

- (GH-612) Fix CHANGELOG entry for v0.15.2 entry

## [v0.15.2] - 2023-07-13

### Overview

- Minor tweaks
- Dependency updates
- built using Go 1.19.11
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Changed

- Dependencies
  - `Go`
    - `1.19.10` to `1.19.11`
  - `atc0005/go-nagios`
    - `v0.15.0` to `v0.16.0`
  - `atc0005/go-ci`
    - `go-ci-oldstable-build-v0.11.0` to `go-ci-oldstable-build-v0.11.3`
  - `golang.org/x/sys`
    - `v0.9.0` to `v0.10.0`
- (GH-532) Update RPM `postinstall.sh` script to use `restorecon` in place of
  `chcon`
- (GH-604) Update error annotation implementation

## [v0.15.1] - 2023-06-21

### Overview

- Bug fixes
- Dependency updates
- built using Go 1.19.10
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Changed

- Dependencies
  - `atc0005/go-ci`
    - `go-ci-oldstable-build-v0.10.6` to `go-ci-oldstable-build-v0.11.0`
  - `golang.org/x/sys`
    - `v0.8.0` to `v0.9.0`
- (GH-596) Update vuln analysis GHAW to remove on.push hook

### Fixed

- (GH-598) Restore local CodeQL workflow
- (GH-600) Fix helper function closure collection evaluation

## [v0.15.0] - 2023-06-08

### Overview

- Add advice for handling error
- built using Go 1.19.10
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Added

- (GH-591) Add advice for `connect: connection refused` error

### Fixed

- (GH-593) Add missing overview item for v0.14.0 release

## [v0.14.0] - 2023-06-07

### Overview

- Add advice for handling error
- Bug fixes
- Dependency updates
- built using Go 1.19.10
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Added

- (GH-585) Add advice for `read: connection reset by peer` error

### Changed

- Dependencies
  - `Go`
    - `1.19.9` to `1.19.10`
  - `atc0005/go-nagios`
    - `v0.14.0` to `v0.15.0`
  - `atc0005/go-ci`
    - `go-ci-oldstable-build-v0.10.5` to `go-ci-oldstable-build-v0.10.6`
  - `mattn/go-isatty`
    - `v0.0.18` to `v0.0.19`

### Fixed

- (GH-579) Formatted expiration has stray leading space when only hours remain
- (GH-583) Disable depguard linter
- (GH-584) Fix TCP port flag validation

## [v0.13.1] - 2023-05-12

### Overview

- Bug fixes
- Dependency updates
- built using Go 1.19.9
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Changed

- Dependencies
  - `Go`
    - `1.19.7` to `1.19.9`
  - `atc0005/go-ci`
    - `go-ci-oldstable-build-v0.10.3` to `go-ci-oldstable-build-v0.10.5`
  - `rs/zerolog`
    - `v1.29.0` to `v1.29.1`
  - `golang.org/x/sys`
    - `v0.6.0` to `v0.8.0`

### Fixed

- (GH-574) Misc cleanup tasks
- (GH-575) Fix markdownlint linting errors

## [v0.13.0] - 2023-03-29

### Overview

- Add support for rootless container builds
- Generate `dev` packages with release builds
- Bug fixes
- Dependency updates
- built using Go 1.19.7
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Added

- Builds
  - (GH-541) Makefile | Include `dev` packages with future stable releases
  - (GH-548) Add rootless container builds via Docker/Podman

### Changed

- Dependencies
  - `atc0005/go-ci`
    - `go-ci-oldstable-build-v0.9.0` to `go-ci-oldstable-build-v0.10.3`
  - `mattn/go-isatty`
    - `v0.0.17` to `v0.0.18`
  - `golang.org/x/sys`
    - `v0.5.0` to `v0.6.0`

### Fixed

- (GH-544) Fix lscert Windows binary InternalName metadata
- (GH-546) Add missing return for perfdata add failure case
- (GH-550) Update vuln analysis GHAW to use on.push hook
- (GH-552) cmd/certsum/certcheck.go:89:2: unused-parameter: parameter
  'rateLimiter' seems to be unused, consider removing or renaming it as _
  (revive)
- (GH-553) internal/config/logging.go:142:2: if-return: redundant if ...; err
  != nil check, just return error instead. (revive)
- (GH-554) internal/certs/validation-results.go:693:47: unused-parameter:
  parameter 'verbose' seems to be unused, consider removing or renaming it as
  _ (revive)
- (GH-555) internal/certs/validation-sans.go:82:2: unused-parameter: parameter
  'dnsName' seems to be unused, consider removing or renaming it as _ (revive)
- (GH-556) Implement certScanner rate limiting
- (GH-565) Fix some errwrap linting errors

## [v0.12.0] - 2023-03-02

### Overview

- Add new flags to `check_cert` plugin
- Change format of emitted performance data "expiration" metrics
- Change exit state for several scenarios
- Give leaf cert highest priority for non-OK states
- Bug fixes
- built using Go 1.19.6
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Added

- (GH-397) Add support for ignoring expired intermediate/root certificates
  - add `ignore-expired-intermediate-certs flag` to allow explicitly ignoring
    expired intermediate certificates in a chain
  - add `ignore-expired-root-certs` flag to allow explicitly ignoring expired
    intermediate certificates in a chain
- (GH-530) Update `netutils.GetCerts` to log num certs fetched

### Changed

- (GH-281) check_cert | Give leaf cert highest priority when it is expiring or
  expired
- (GH-529) Update handling of performance data metrics to allow emitting
  negative expiration values

### Fixed

- (GH-505) Setting up an "expiration only" monitoring configuration for a
  self-signed certificate without SANs entries fails unless
  `ignore-hostname-verification-if-empty-sans` flag is specified
- (GH-525) Explicitly ignoring OK/passing validation results does not work
- (GH-531) Fix Makefile find command printf syntax
- (GH-509) chcon: can't apply partial context to unlabeled file
  '/usr/lib64/nagios/plugins/check_cert'
- (GH-536) Use UNKNOWN state for perfdata add failures
- (GH-537) Use UNKNOWN state for invalid command-line args
- (GH-538) Use WARNING state for unexpected cert file content

## [v0.11.2] - 2023-02-24

### Overview

- Build improvements
- GitHub Actions Workflows updates
- built using Go 1.19.6
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Changed

- Dependencies
  - `Go`
    - `1.19.5` to `1.19.6`
  - `ghcr.io/atc0005/go-ci` build image
    - `go-ci-oldstable-build-v0.9.0`
  - (GH-516) Remove `dependabot/tools` monitoring

- Builds
  - (GH-506) Build dev/stable releases using go-ci Docker image
    - using an `oldstable` `atc0005/go-ci` variant for now
    - via `docker-release-build` recipe
    - via `docker-dev-build` recipe
  - (GH-512) Replace gogeninstall recipe with depsinstall
  - (GH-514) Use git-describe-semver for generating release ver
    - this results in a version pattern change
      - packages (name, internal)
      - binaries (internal)
  - (GH-515) Add `docker-packages` recipe

- GitHub Actions
  - (GH-502) Drop `Push Validation` workflow
  - (GH-503) Rework workflow scheduling
  - (GH-518) Remove `Push Validation` workflow status badge

## [v0.11.1] - 2023-02-10

### Overview

- Bugfixes
- Build improvements
- built using Go 1.19.5
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Changed

- (GH-496) Update package generation to use `W.X.Y-Z` naming pattern

### Fixed

- (GH-493) `ERROR 404: Not Found` when attempting to download DEB, RPM
  packages using links files
- (GH-495) `sha256sum: WARNING: 1 listed file could not be read` error when
  attempting to validate package checksums
- (GH-497) Fix windows-x64 binary download links

## [v0.11.0] - 2023-02-09

### Overview

- Added support for generating DEB, RPM packages
- Binaries are compressed (~ 66% smaller)
- Overall Makefile improvements
- Performance data tweaks
- built using Go 1.19.5
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Added

- (GH-439) Generate RPM/DEB packages using nFPM
- (GH-475) Add `min` expiration lifetime value to `expires_leaf`,
  `expires_intermediate` performance data metrics
- (GH-470) Makefile: Compress binaries & use static filenames
- (GH-471) Makefile: Add missing "standard" recipes
- (GH-473) Add version details to Windows executables
- (GH-477) Makefile: Add recipe to generate "dev" packages

### Changed

- Dependencies
  - `golang.org/x/sys`
    - `v0.4.0` to `v0.5.0`
- (GH-476) Makefile: Replace (unneeded) `recursively expanded` variables with
  `simply expanded` variables
- (GH-489) Update Makefile recipes for dev/stable releases

## [v0.10.0] - 2023-01-31

### Overview

- Added performance data metrics
- Bug fixes
- built using Go 1.19.5
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Added

- (GH-445) Emit "days remaining" and count of certificates type performance
  data metrics
  - `expires_leaf`
  - `expires_intermediate`
  - `certs_present_leaf`
  - `certs_present_intermediate`
  - `certs_present_root`
  - `certs_present_unknown`

### Fixed

- (GH-460) Update `certs.NextToExpire` to add guard, clarify
- (GH-461) SNI-required host value not set when server value is specified as
  IP Address and DNS Name *is* set properly

## [v0.9.3] - 2023-01-31

### Overview

- Bug fixes
- Dependency updates
- GitHub Actions Workflows updates
- built using Go 1.19.5
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Changed

- Dependencies
  - `Go`
    - `1.19.4` to `1.19.5`
  - `atc0005/go-nagios`
    - `v0.10.2` to `v0.14.0`
  - `rs/zerolog`
    - `v1.28.0` to `v1.29.0`
  - `github.com/mattn/go-isatty`
    - `v0.0.16` to `v0.0.17`
  - `golang.org/x/sys`
    - `v0.3.0` to `v0.4.0`
- (GH-450) Add Go Module Validation, Dependency Updates jobs

### Fixed

- (GH-440) Fix mispelling of Inspector app type
- (GH-443) Drop plugin runtime tracking, update library usage

## [v0.9.2] - 2022-12-07

### Overview

- Bug fixes
- Dependency updates
- GitHub Actions Workflows updates
- built using Go 1.19.4
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Changed

- Dependencies
  - `Go`
    - `1.19.1` to `1.19.4`
  - `atc0005/go-nagios`
    - `v0.10.0` to `v0.10.2`
  - `github.com/mattn/go-colorable`
    - `v0.1.12` to `v0.1.13`
  - `github.com/mattn/go-isatty`
    - `v0.0.14` to `v0.0.16`
  - `golang.org/x/sys`
    - `v0.0.0-20210927094055-39ccf1dd6fa6` to `v0.3.0`
- (GH-421) Refactor GitHub Actions workflows to import logic
- (GH-422) GitHub Actions workflows refactor follow-up
- (GH-423) Update README to include go.mod badge

### Fixed

- (GH-424) Fix project repo links
- (GH-427) Issues with `config.supportedLogLevels()` helper function
- (GH-429) Prune stray space in doc comment
- (GH-432) Fix Makefile Go module base path detection

## [v0.9.1] - 2022-09-22

### Overview

- Bug fixes
- Dependency updates
- GitHub Actions Workflows updates
- built using Go 1.19.1
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Changed

- Dependencies
  - `Go`
    - `1.17.13` to `1.19.1`
  - `atc0005/go-nagios`
    - `v0.9.1` to `v0.10.0`
  - `rs/zerolog`
    - `v1.27.0` to `v1.28.0`
  - `github/codeql-action`
    - `v2.1.22` to `v2.1.25`
- (GH-404) Update project to Go 1.19
- (GH-405) Update Makefile and GitHub Actions Workflows
- (GH-406) Add CodeQL GitHub Actions Workflow
- (GH-409) Add additional golangci-lint linters
- (GH-411) Add govulncheck GitHub Actions Workflow
- (GH-412) Combine CodeQL and Vulnerability Analysis GHAWs

### Fixed

- (GH-402) Add missing cmd doc files
- (GH-403) Update certsum overview text
- (GH-407) Makefile: Tweak staticcheck pre-install text

## [v0.9.0] - 2022-08-21

### Overview

- Add URL positional argument support to `lscert`
- Help text tweaks
- Bugfixes
- Dependency updates
- built using Go 1.17.13
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Added

- (GH-378) lscert | Add support for setting `server` and `port` values from
  URL pattern provided as positional argument
- (GH-389) Update help text to reflect app-specific usage

### Changed

- Dependencies
  - `Go`
    - `1.17.12` to `1.17.13`

- (GH-356) Remove deprecated `disable-hostname-verification-if-empty-sans`
  flag
  - previously announced in `v0.8.0` release

### Fixed

- (GH-392) Swap use of `io/ioutil` package for `os`
- (GH-387) Fix `go install` steps to include valid source path
- (GH-390) Apply Go 1.19 specific doc comments linting fixes

## [v0.8.0] - 2022-07-13

### Overview

- Add new flags to `check_cert` plugin
- Documentation refresh
- Output tweaks
- Bugfixes
- Dependency updates
- built using Go 1.17.12
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Added

- (GH-211) Add support for explicitly applying or ignoring specific validation
  check results

### Changed

- Dependencies
  - `Go`
    - `1.17.10` to `1.17.12`
  - `rs/zerolog`
    - `v1.26.1` to `v1.27.0`
  - `atc0005/go-nagios`
    - `v0.8.2` to `v0.9.1`

- (GH-285) check_cert | Improve context deadline related error message
- (GH-324) lscert | Move age thresholds block to debug messages

### Deprecated

- (GH-356) Remove deprecated `disable-hostname-verification-if-empty-sans`
  flag
  - planned removal in v0.9.0 release

### Fixed

- (GH-323) lscert | Position of SANs entries mismatch summary message label is
  incorrect
- (GH-326) Fix misc doc comment typos
- (GH-327) Incorrect calculation for `sans_entries_found` structured logging
  field
- (GH-328) Incorrect state label used for SANs entries mismatch
- (GH-329) Incorrect exit state / status code set for SANs entries mismatch
- (GH-336) lscert | hard-coded failure SANs list evaluation message incorrect
- (GH-338) lscert | Fix exit handling for 0 discovered certs
- (GH-343) If specified, DNS Name value is not used for SNI-enabled cert
  retrieval
- (GH-348) semicolon (`;`) character in plugin output (`ServiceOutput`)
  changed to colon (`:`) character
- (GH-349) README: Fix version reference for last Go 1.16 build
- (GH-351) Fix various atc0005/go-nagios usage linting errors
- (GH-353) Update lintinstall Makefile recipe
- (GH-314) README missing example usage of `filename` flag
- (GH-315) Inconsistent hostname verification applied when `filename` flag is
  used
- (GH-333) README missing coverage of SANs entries validation
- (GH-354) Expiration age threshold value validation does not object to
  specific invalid values

## [v0.7.1] - 2022-05-13

### Overview

- Bugfixes
- Dependency updates
- built using Go 1.17.10
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Changed

- Dependencies
  - `Go`
    - `1.17.9` to `1.17.10`

### Fixed

- (GH-312) certsum | invalid `filename` structured logging field
- (GH-316) check_cert | Include the baseline certs "lead-in" immediately after
  retrieving the certificate chain
- (GH-317) lscert | Verify hostname if dns-name flag is used
- (GH-321) lscert | Tweak wording regarding certificate source

## [v0.7.0] - 2022-04-27

### Overview

- Log output format change
- Rework SNI support
- Output tweaks
- Bugfixes
- Dependency updates
- built using Go 1.17.9
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Added

- (GH-272) certsum | Note which host was scanned for sites using a wildcard
  cert
- (GH-282) List IP of host where cert was retrieved

### Changed

- Dependencies
  - `Go`
    - `1.17.8` to `1.17.9`

- (GH-295) Switch logger output format from `JSON` to `logfmt`
- (GH-308) Update summary cert chain count desc/label

### Fixed

- (GH-273) certsum does not use SNI when given hostnames
- (GH-286) certsum | `port` and `server` fields in logger indicate "zero"
  values regardless of CLI flag values given
- (GH-290) certsum | Empty host/IP value for host with no open ports
- (GH-293) References to IP Addresses instead of hosts
- (GH-298) Update README to note SNI support, change in logging format,
  refresh examples
- (GH-302) Fix `netutils.DedupeHosts()` logic, intro details
- (GH-303) Fix `netutils.isIPv4AddrCandidate()` logic
- (GH-304) Note issue with `netutils.DedupeHosts()`
- (GH-305) Update hostname verification failure suggestion
- (GH-306) Fix IP Address range expansion & update handling
- (GH-307) Minor logging & doc comment tweaks

## [v0.6.0] - 2022-03-08

### Overview

- Bugfixes
- Dependency updates
- built using Go 1.17.8
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Added

- (GH-277) Allow skipping hostname verify for empty SANs list

### Changed

- Dependencies
  - `Go`
    - `1.17.7` to `1.17.8`
  - `actions/checkout`
    - `v2.5.1` to `v3`
  - `actions/setup-node`
    - `v2.5.1` to `v3`

### Fixed

- (GH-275) Server connection string is constructed using `%s:%d` format string
- (GH-276) x509: certificate relies on legacy Common Name field, use SANs
  instead

## [v0.5.5] - 2022-02-11

### Overview

- Bugfixes
- Dependency updates
- built using Go 1.17.7
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Changed

- Dependencies
  - `Go`
    - `1.17.6` to `1.17.7`

- (GH-261) Switch Docker image source from Docker Hub to GitHub Container
  Registry (GHCR)
- (GH-262) Expand linting GitHub Actions Workflow to include `oldstable`,
  `unstable` container images

### Fixed

- (GH-264) var-declaration: should omit type error from declaration (revive)

## [v0.5.4] - 2022-01-21

### Overview

- Dependency updates
- built using Go 1.17.6
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Changed

- Dependencies
  - `Go`
    - `1.16.12` to `1.17.6`
    - (GH-255) Update go.mod file, canary Dockerfile to reflect current
      dependencies
  - `atc0005/go-nagios`
    - `v0.8.1` to `v0.8.2`

### Fixed

- (GH-256) Tweak doc comments for `FormattedExpiration()` func
- Restore explicit Windows support for releases `>= v0.4.5`

## [v0.5.3] - 2021-12-28

### Overview

- Dependency updates
- built using Go 1.16.12
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Changed

- Dependencies
  - `Go`
    - `1.16.10` to `1.16.12`
  - `rs/zerolog`
    - `v1.26.0` to `v1.26.1`
  - `actions/setup-node`
    - `v2.4.1` to `v2.5.1`

- (GH-213) Remove `fixsn` binary, documentation, other references to it
- (GH-248) Help output generated by `-h`, `--help` flag is sent to `stderr`,
  should go to `stdout` instead

### Fixed

- (GH-242) Fix CHANGELOG deps update details

## [v0.5.2] - 2021-11-08

### Overview

- Dependency updates
- built using Go 1.16.10
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Changed

- Dependencies
  - `Go`
    - `1.16.8` to `1.16.10`
  - `atc0005/go-nagios`
    - `v0.7.0` to `v0.8.1`
  - `rs/zerolog`
    - `v1.25.0` to `v1.26.0`
  - `actions/checkout`
    - `v2.3.4` to `v2.4.0`
  - `actions/setup-node`
    - `v2.4.0` to `v2.4.1`

- (GH-229) Update README to list downloading binaries as alternative to
  building from source

### Fixed

- (GH-228) Fix CHANGELOG deps update details

## [v0.5.1] - 2021-09-13

### Overview

- Dependency updates
- built using Go 1.16.8
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Changed

- Dependencies
  - `Go`
    - `1.16.7` to `1.16.8`
  - `atc0005/go-nagios`
    - `v0.6.1` to `v0.7.0`
  - `rs/zerolog`
    - `v1.23.0` to `v1.25.0`

- Replace bundled `ServiceState` type

- README
  - Add missing cert file eval support to feature list

## [v0.5.0] - 2021-08-13

### Overview

- Add new flag to `check_cert` plugin
- Bug fixes
- built using Go 1.16.7
  - Statically linked
  - Windows (x86, x64)
  - Linux (x86, x64)

### Added

- `check_cert` plugin
  - (GH-193) Add support for monitoring certificate file

### Fixed

- `lscert`
  - (GH-203) Inconsistent spacing after "headers" in results output
  - (GH-202) certs.GetCertsFromFile() function "hangs" when evaluating
    certificate file with trailing non-PEM data
- `check_cert` plugin
  - (GH-207) Invalid formatting interpolation for debug logging message

## [v0.4.5] - 2021-08-06

### Overview

- Dependency updates
- built using Go 1.16.7
  - Statically linked
  - Windows (x86, x64)
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

[Unreleased]: https://github.com/atc0005/check-cert/compare/v0.25.2...HEAD
[v0.25.2]: https://github.com/atc0005/check-cert/releases/tag/v0.25.2
[v0.25.1]: https://github.com/atc0005/check-cert/releases/tag/v0.25.1
[v0.25.0]: https://github.com/atc0005/check-cert/releases/tag/v0.25.0
[v0.24.0]: https://github.com/atc0005/check-cert/releases/tag/v0.24.0
[v0.23.0]: https://github.com/atc0005/check-cert/releases/tag/v0.23.0
[v0.22.1]: https://github.com/atc0005/check-cert/releases/tag/v0.22.1
[v0.22.0]: https://github.com/atc0005/check-cert/releases/tag/v0.22.0
[v0.21.0]: https://github.com/atc0005/check-cert/releases/tag/v0.21.0
[v0.20.1]: https://github.com/atc0005/check-cert/releases/tag/v0.20.1
[v0.20.0]: https://github.com/atc0005/check-cert/releases/tag/v0.20.0
[v0.19.0]: https://github.com/atc0005/check-cert/releases/tag/v0.19.0
[v0.18.0]: https://github.com/atc0005/check-cert/releases/tag/v0.18.0
[v0.17.7]: https://github.com/atc0005/check-cert/releases/tag/v0.17.7
[v0.17.6]: https://github.com/atc0005/check-cert/releases/tag/v0.17.6
[v0.17.5]: https://github.com/atc0005/check-cert/releases/tag/v0.17.5
[v0.17.4]: https://github.com/atc0005/check-cert/releases/tag/v0.17.4
[v0.17.3]: https://github.com/atc0005/check-cert/releases/tag/v0.17.3
[v0.17.2]: https://github.com/atc0005/check-cert/releases/tag/v0.17.2
[v0.17.1]: https://github.com/atc0005/check-cert/releases/tag/v0.17.1
[v0.17.0]: https://github.com/atc0005/check-cert/releases/tag/v0.17.0
[v0.16.1]: https://github.com/atc0005/check-cert/releases/tag/v0.16.1
[v0.16.0]: https://github.com/atc0005/check-cert/releases/tag/v0.16.0
[v0.15.9]: https://github.com/atc0005/check-cert/releases/tag/v0.15.9
[v0.15.8]: https://github.com/atc0005/check-cert/releases/tag/v0.15.8
[v0.15.7]: https://github.com/atc0005/check-cert/releases/tag/v0.15.7
[v0.15.6]: https://github.com/atc0005/check-cert/releases/tag/v0.15.6
[v0.15.5]: https://github.com/atc0005/check-cert/releases/tag/v0.15.5
[v0.15.4]: https://github.com/atc0005/check-cert/releases/tag/v0.15.4
[v0.15.3]: https://github.com/atc0005/check-cert/releases/tag/v0.15.3
[v0.15.2]: https://github.com/atc0005/check-cert/releases/tag/v0.15.2
[v0.15.1]: https://github.com/atc0005/check-cert/releases/tag/v0.15.1
[v0.15.0]: https://github.com/atc0005/check-cert/releases/tag/v0.15.0
[v0.14.0]: https://github.com/atc0005/check-cert/releases/tag/v0.14.0
[v0.13.1]: https://github.com/atc0005/check-cert/releases/tag/v0.13.1
[v0.13.0]: https://github.com/atc0005/check-cert/releases/tag/v0.13.0
[v0.12.0]: https://github.com/atc0005/check-cert/releases/tag/v0.12.0
[v0.11.2]: https://github.com/atc0005/check-cert/releases/tag/v0.11.2
[v0.11.1]: https://github.com/atc0005/check-cert/releases/tag/v0.11.1
[v0.11.0]: https://github.com/atc0005/check-cert/releases/tag/v0.11.0
[v0.10.0]: https://github.com/atc0005/check-cert/releases/tag/v0.10.0
[v0.9.3]: https://github.com/atc0005/check-cert/releases/tag/v0.9.3
[v0.9.2]: https://github.com/atc0005/check-cert/releases/tag/v0.9.2
[v0.9.1]: https://github.com/atc0005/check-cert/releases/tag/v0.9.1
[v0.9.0]: https://github.com/atc0005/check-cert/releases/tag/v0.9.0
[v0.8.0]: https://github.com/atc0005/check-cert/releases/tag/v0.8.0
[v0.7.1]: https://github.com/atc0005/check-cert/releases/tag/v0.7.1
[v0.7.0]: https://github.com/atc0005/check-cert/releases/tag/v0.7.0
[v0.6.0]: https://github.com/atc0005/check-cert/releases/tag/v0.6.0
[v0.5.5]: https://github.com/atc0005/check-cert/releases/tag/v0.5.5
[v0.5.4]: https://github.com/atc0005/check-cert/releases/tag/v0.5.4
[v0.5.3]: https://github.com/atc0005/check-cert/releases/tag/v0.5.3
[v0.5.2]: https://github.com/atc0005/check-cert/releases/tag/v0.5.2
[v0.5.1]: https://github.com/atc0005/check-cert/releases/tag/v0.5.1
[v0.5.0]: https://github.com/atc0005/check-cert/releases/tag/v0.5.0
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
