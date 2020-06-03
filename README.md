# check-certs

Go-based tooling to check/verify certs (e.g., as part of a Nagios service check)

## Features

Several tools are included in this repo.

### check_certs

### lscerts

Small CLI tool to print a *very* basic summary of certificate metadata
provided by a remote service at the specified fully-qualified domain name
(e.g., www.github.com) and port (e.g., 443).

This tool is intended to quickly review the results of replacing a certificate
and/or troubleshoot why connections to a remote system may be failing.

## References

- <https://github.com/grantae/certinfo>
