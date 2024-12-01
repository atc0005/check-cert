module github.com/atc0005/check-cert

go 1.20

require (
	github.com/atc0005/cert-payload v0.7.0-alpha.4
	github.com/atc0005/go-nagios v0.19.0
	github.com/grantae/certinfo v0.0.0-20170412194111-59d56a35515b
	github.com/rs/zerolog v1.33.0
)

// Allow for testing local changes before they're published.
// replace github.com/atc0005/cert-payload => ../cert-payload
// replace github.com/atc0005/go-nagios => ../go-nagios

require (
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	golang.org/x/sys v0.27.0 // indirect
)
