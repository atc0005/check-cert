// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package certs

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/atc0005/go-nagios"
)

// incompleteChainAdvice provides advice for the sysadmin when a cert chain is
// found to be incomplete.
func incompleteChainAdvice(certChain []*x509.Certificate) string {
	if len(certChain) == 0 {
		return ""
	}

	var advice strings.Builder

	advice.WriteString(
		fmt.Sprintf(
			"This issue often occurs with Windows Servers when (newer) intermediates are missing from the certificate stores.%s",
			nagios.CheckOutputEOL,
		),
	)

	hostValRef := func(chain []*x509.Certificate) string {
		switch {
		case chain[0].Subject.CommonName != "":
			return fmt.Sprintf(
				" for %s ",
				chain[0].Subject.CommonName,
			)

		case len(chain[0].DNSNames) > 0:
			return fmt.Sprintf(
				" for %s ",
				chain[0].DNSNames[0],
			)

		default:
			return ""
		}
	}

	firstCertType := ChainPosition(certChain[0], certChain)

	isMissingIntermediates := !HasIntermediateCert(certChain)
	// isMissingLeaf := !HasLeafCert(certChain)

	switch {
	case firstCertType == certChainPositionLeafSelfSigned:
		advice.WriteString(
			fmt.Sprintf(
				"It is recommended that you replace the %s certificate with a valid certificate chain.%s",
				certChainPositionLeafSelfSigned,
				nagios.CheckOutputEOL,
			),
		)

		// TODO: We'd need to consider how this advice would come across for a
		// cert check which monitors an intermediates bundle; intermediate
		// bundles should not contain a leaf certificate.
		//
		// 	case isMissingLeaf:
		// 		advice.WriteString(
		// 			fmt.Sprintf(
		// 				"It is recommended that you configure the service%sto include the missing leaf cert.%s",
		// 				hostValRef(certChain),
		// 				nagios.CheckOutputEOL,
		// 			),
		// 		)
		//
		// 		advice.WriteString(certDownloadLinksAdvice(certChain))

	case isMissingIntermediates:
		advice.WriteString(
			fmt.Sprintf(
				"It is recommended that you configure the service%sto include the missing intermediates.%s",
				hostValRef(certChain),
				nagios.CheckOutputEOL,
			),
		)

		advice.WriteString(certDownloadLinksAdvice(certChain))

	default:

		// Any advice for this scenario?
	}

	return advice.String()
}

// certDownloadLinksAdvice attempts to provide sysadmins advice for what
// download links to use when repairing reported certificate chain issues.
func certDownloadLinksAdvice(certChain []*x509.Certificate) string {
	if len(certChain) == 0 {
		return ""
	}

	var advice strings.Builder

	if !HasLeafCert(certChain) {
		advice.WriteString(
			"NOTE: No leaf certs detected in given certificate chain;" +
				" is this an intermediates bundle that is being monitored?",
		)
	}

	type adviceMapEntry struct {
		CA           string
		CASubstrings []string
		Description  string
		Advice       string
	}

	adviceMappings := []adviceMapEntry{
		{
			CASubstrings: []string{
				"InCommon",
				"USERTrust",
				"COMODO",
				"Sectigo",
			},
			Description: "Known CA name prefixes used by Sectigo",
			Advice:      strings.TrimSpace(sectigoEmailAdvice),
		},
	}

outerLoop:
	for _, cert := range certChain {
		for _, adviceEntry := range adviceMappings {
			for _, pattern := range adviceEntry.CASubstrings {
				lowerCasePattern := strings.ToLower(pattern)

				issuerContainsCAPrefix := strings.Contains(
					strings.ToLower(cert.Issuer.CommonName),
					lowerCasePattern,
				)

				issuedContainsCAPrefix := strings.Contains(
					strings.ToLower(cert.Subject.CommonName),
					lowerCasePattern,
				)

				if issuerContainsCAPrefix || issuedContainsCAPrefix {
					advice.WriteString(
						fmt.Sprintf(
							"%s%s%s",
							nagios.CheckOutputEOL,
							adviceEntry.Advice,
							nagios.CheckOutputEOL,
						),
					)

					break outerLoop
				}
			}
		}
	}

	return advice.String()
}
