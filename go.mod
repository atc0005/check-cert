module github.com/atc0005/check-cert

go 1.25.0

// Go 1.23 removed default support for parsing certificates with negative
// serial numbers. We need this support for parsing older certificates
// (e.g., older roots).
//
// See also: https://pkg.go.dev/crypto/x509#ParseCertificate
godebug x509negativeserial=1

require (
	github.com/atc0005/cert-payload v0.8.0
	github.com/atc0005/go-nagios v0.20.0
	github.com/grantae/certinfo v0.0.0-20170412194111-59d56a35515b
	github.com/rs/zerolog v1.34.0
)

// Allow for testing local changes before they're published.
// replace github.com/atc0005/cert-payload => ../cert-payload
// replace github.com/atc0005/go-nagios => ../go-nagios

require (
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	golang.org/x/sys v0.42.0 // indirect
)
