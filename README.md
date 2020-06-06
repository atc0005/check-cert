<!-- omit in toc -->
# check-certs

Go-based tooling to check/verify certs (e.g., as part of a Nagios service check)

<!-- omit in toc -->
## Table of Contents

- [Overview](#overview)
  - [check_certs](#check_certs)
  - [lscerts](#lscerts)
- [Features](#features)
- [License](#license)
- [References](#references)

## Overview

This repo contains various tools used to monitor/validate certificates.

| Tool Name     | Status | Description                                                                            |
| ------------- | ------ | -------------------------------------------------------------------------------------- |
| `check_certs` | Alpha  | Nagios plugin used to monitor certificate chains                                       |
| `lscerts`     | Alpha  | Small CLI app used to generate a summary of certificate metadata and expiration status |

### check_certs

Nagios plugin used to monitor certificate chains. In addition to the features
shared with `lscerts`, this app also validates the provided hostname against
the certificate Common Name *or* one of the available SANs entries.

The output for this application is designed to provide the one-line summary
needed by Nagios for quick identification of a problem while providing longer,
more detailed information for use in email and Teams notifications
([atc0005/send2teams](https://github.com/atc0005/send2teams)).

### lscerts

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
