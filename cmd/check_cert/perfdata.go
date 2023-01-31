// Copyright 2023 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"crypto/x509"
	"fmt"
	"strconv"

	"github.com/atc0005/check-cert/internal/certs"
	"github.com/atc0005/go-nagios"
)

// getPerfData generates performance data metrics from the given certificate
// chain and certificate age thresholds. An error is returned if any are
// encountered while gathering metrics or if an empty certificate chain is
// provided.
func getPerfData(certChain []*x509.Certificate, ageCritical int, ageWarning int) ([]nagios.PerformanceData, error) {
	if len(certChain) == 0 {
		return nil, fmt.Errorf(
			"func getPerfData: unable to generate metrics: %w",
			certs.ErrMissingValue,
		)
	}

	var expiresLeaf int
	oldestLeaf := certs.OldestLeafCert(certChain)
	if daysToExpiration, err := certs.ExpiresInDays(oldestLeaf); err == nil {
		expiresLeaf = daysToExpiration
	}

	var expiresIntermediate int
	oldestIntermediate := certs.OldestIntermediateCert(certChain)
	if daysToExpiration, err := certs.ExpiresInDays(oldestIntermediate); err == nil {
		expiresIntermediate = daysToExpiration
	}

	var expiresRoot int
	oldestRoot := certs.OldestRootCert(certChain)
	if daysToExpiration, err := certs.ExpiresInDays(oldestRoot); err == nil {
		expiresRoot = daysToExpiration
	}

	// TODO: Should we emit this metric?
	_ = expiresRoot

	certsPresentLeaf := strconv.Itoa(certs.NumLeafCerts(certChain))
	certsPresentIntermediate := strconv.Itoa(certs.NumIntermediateCerts(certChain))
	certsPresentRoot := strconv.Itoa(certs.NumRootCerts(certChain))
	certsPresentUnknown := strconv.Itoa(certs.NumUnknownCerts(certChain))

	pd := []nagios.PerformanceData{
		{
			Label:             "expires_leaf",
			Value:             fmt.Sprintf("%d", expiresLeaf),
			UnitOfMeasurement: "d",
			Warn:              fmt.Sprintf("%d", ageWarning),
			Crit:              fmt.Sprintf("%d", ageCritical),
		},
		{
			Label:             "expires_intermediate",
			Value:             fmt.Sprintf("%d", expiresIntermediate),
			UnitOfMeasurement: "d",
			Warn:              fmt.Sprintf("%d", ageWarning),
			Crit:              fmt.Sprintf("%d", ageCritical),
		},

		// TODO: Should we even track this? If we report 0 as a default value
		// when the cert is not found, how will that differ from when the cert
		// is actually present and expired?
		//
		//
		// NOTE: Current thinking is that I should not include root cert
		// expiration perfdata; root cert should ideally not be in the chain
		// per current best practice(s).
		// {
		// 	Label:             "expires_root",
		// 	Value:             fmt.Sprintf("%d", expiresRoot),
		// 	UnitOfMeasurement: "d",
		// },
		{
			Label: "certs_present_leaf",
			Value: certsPresentLeaf,
		},
		{
			Label: "certs_present_intermediate",
			Value: certsPresentIntermediate,
		},
		{
			Label: "certs_present_root",
			Value: certsPresentRoot,
		},
		{
			Label: "certs_present_unknown",
			Value: certsPresentUnknown,
		},
	}

	return pd, nil

}
