module github.com/atc0005/check-cert

go 1.23.0

godebug (
	// Go 1.23 changed the default TLS cipher suites used by clients and
	// servers when not explicitly configured, removing 3DES cipher suites. We
	// revert this behavior to support retrieving certificates from older
	// systems.
	//
	// See also: https://pkg.go.dev/crypto/tls#Config.CipherSuites
	tls3des=1

	// Go 1.22 changed the default TLS cipher suites used by clients and
	// servers when not explicitly configured, removing the cipher suites
	// which used RSA based key exchange. We revert this behavior to support
	// retrieving certificates from older systems.
	//
	// NOTE: This has been confirmed as needed for Microsoft Windows Server
	// 2012 R2 systems (covered by Azure Arc).
	//
	// See also:
	//
	//   - https://pkg.go.dev/crypto/tls#Config.CipherSuites
	//   - https://github.com/golang/go/issues/63413
	tlsrsakex=1
)

require (
	github.com/atc0005/cert-payload v0.7.1
	github.com/atc0005/go-nagios v0.19.0
	github.com/grantae/certinfo v0.0.0-20170412194111-59d56a35515b
	github.com/rs/zerolog v1.34.0
)

// Allow for testing local changes before they're published.
// replace github.com/atc0005/cert-payload => ../cert-payload
// replace github.com/atc0005/go-nagios => ../go-nagios

require (
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	golang.org/x/sys v0.32.0 // indirect
)
