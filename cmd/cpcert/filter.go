// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"crypto/x509"

	"github.com/atc0005/check-cert/internal/certs"
	"github.com/atc0005/check-cert/internal/config"
	"github.com/atc0005/check-cert/internal/textutils"
)

// filterCertChain filters the given certificate chain to the specified list
// of certificate types.
func filterCertChain(filterKeywords []string, certChain []*x509.Certificate) []*x509.Certificate {
	filteredCertChain := make([]*x509.Certificate, 0, len(certChain))

	// Validation prevents other keywords from being specified alongside this
	// one.
	if textutils.InList(config.CertTypeAll, filterKeywords, true) {
		filteredCertChain = append(filteredCertChain, certChain...)
	}

	if textutils.InList(config.CertTypeLeaf, filterKeywords, true) {
		for _, cert := range certChain {
			if certs.IsLeafCert(cert, certChain) {
				filteredCertChain = append(filteredCertChain, cert)
			}
		}
	}

	if textutils.InList(config.CertTypeIntermediate, filterKeywords, true) {
		for _, cert := range certChain {
			if certs.IsIntermediateCert(cert, certChain) {
				filteredCertChain = append(filteredCertChain, cert)
			}
		}
	}

	if textutils.InList(config.CertTypeRoot, filterKeywords, true) {
		for _, cert := range certChain {
			if certs.IsRootCert(cert, certChain) {
				filteredCertChain = append(filteredCertChain, cert)
			}
		}
	}

	return filteredCertChain
}
