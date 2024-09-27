// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/atc0005/check-cert/internal/certs"
)

func printCertChain(out io.Writer, certChain []*x509.Certificate) error {
	w := tabwriter.NewWriter(out, 4, 4, 4, ' ', 0)

	certChainPositionColTitle := "Chain Position"
	certTypeColTitle := "Cert Type"
	subjectColTitle := "Subject"
	issuerCertificateURLsTitle := "Issuer Certificate URLs"

	certChainPositionSeparatorLength := func() int {
		longest := len(certChainPositionColTitle)

		if len(certChain) > longest {
			longest = len(certChain) + 1
		}

		return longest
	}

	certTypeSeparatorLength := func() int {
		longest := len(certTypeColTitle)
		for _, cert := range certChain {
			certType := certs.ChainPosition(cert, certChain)

			if len(certType) > longest {
				longest = len(certType)
			}
		}

		return longest
	}

	subjectSeparatorLength := func() int {
		longest := len(subjectColTitle)
		for _, cert := range certChain {
			if len(cert.Subject.CommonName) > longest {
				longest = len(cert.Subject.CommonName)
			}
		}

		return longest
	}

	issuerCertificateURLsLength := func() int {
		longest := len(issuerCertificateURLsTitle)
		for _, cert := range certChain {
			for _, aiaURL := range cert.IssuingCertificateURL {
				if len(aiaURL)+2 > longest {
					longest = len(aiaURL) + 2
				}
			}
		}

		return longest
	}

	headerRowTmpl := fmt.Sprintf("%s\t%s\t%s\t%s\t",
		certChainPositionColTitle,
		certTypeColTitle,
		subjectColTitle,
		issuerCertificateURLsTitle,
	)

	separatorRowTmpl := fmt.Sprintf(
		"%s\t%s\t%s\t%s\t",
		strings.Repeat("-", certChainPositionSeparatorLength()),
		strings.Repeat("-", certTypeSeparatorLength()),
		strings.Repeat("-", subjectSeparatorLength()),
		strings.Repeat("-", issuerCertificateURLsLength()),
	)
	dataRowTmpl := "%d\t%s\t%s\t%s\t\n"

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, headerRowTmpl)
	_, _ = fmt.Fprintln(w, separatorRowTmpl)

	for idx, cert := range certChain {
		_, _ = fmt.Fprintf(
			w,
			dataRowTmpl,
			idx,
			certs.ChainPosition(cert, certChain),
			cert.Subject.CommonName,

			// Avoid triggering "loop variable X now per-iteration,
			// stack-allocated" scenario by explicitly passing in the loop
			// variable.
			func(c *x509.Certificate) string {
				switch {
				case len(c.IssuingCertificateURL) == 0:
					return "None"
				case len(c.IssuingCertificateURL) == 1:
					return fmt.Sprint(c.IssuingCertificateURL[0])
				default:
					return fmt.Sprint(c.IssuingCertificateURL)
				}
			}(cert),
		)
	}
	_, _ = fmt.Fprintln(w)

	if err := w.Flush(); err != nil {
		return err
	}

	return nil
}
