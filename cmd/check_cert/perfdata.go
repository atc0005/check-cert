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
