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

	// NOTE: We allow falling back to 0 value if leaf or intermediate
	// certificates are not available.
	//
	// This allows monitoring an intermediates bundle where a leaf certificate
	// is not present and it allows monitoring a certificate chain where
	// sysadmins did not include an intermediates bundle (e.g., accidental
	// omission).
	//
	// For those cases the `certs_present_intermediate` and
	// `certs_present_leaf` metrics are intended to clarify why a value of 0
	// is emitted for `expires_*`, or `life_remaining_*` metrics.

	var expiresLeaf int
	oldestLeaf := certs.OldestLeafCert(certChain)
	if daysToExpiration, err := certs.ExpiresInDays(oldestLeaf); err == nil {
		expiresLeaf = daysToExpiration
	}

	var oldestLeafLifeRemaining int
	if leafLifeRemaining, err := certs.LifeRemainingPercentageTruncated(oldestLeaf); err == nil {
		oldestLeafLifeRemaining = leafLifeRemaining
	}

	var expiresIntermediate int
	oldestIntermediate := certs.OldestIntermediateCert(certChain)
	if daysToExpiration, err := certs.ExpiresInDays(oldestIntermediate); err == nil {
		expiresIntermediate = daysToExpiration
	}

	var oldestIntermediateLifeRemaining int
	if intermediateLifeRemaining, err := certs.LifeRemainingPercentageTruncated(oldestIntermediate); err == nil {
		oldestIntermediateLifeRemaining = intermediateLifeRemaining
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
		{
			Label:             "life_remaining_leaf",
			Value:             fmt.Sprintf("%d", oldestLeafLifeRemaining),
			UnitOfMeasurement: "%",

			// TODO: GH-789
			// Warn:              fmt.Sprintf("%d", ageWarning),
			// Crit:              fmt.Sprintf("%d", ageCritical),
		},
		{
			Label:             "life_remaining_intermediate",
			Value:             fmt.Sprintf("%d", oldestIntermediateLifeRemaining),
			UnitOfMeasurement: "%",

			// TODO: GH-789
			// Warn:              fmt.Sprintf("%d", ageWarning),
			// Crit:              fmt.Sprintf("%d", ageCritical),
		},
	}

	return pd, nil

}
