package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/atc0005/check-cert/internal/certs"
)

func printSummaryHighLevel(
	showAllHosts bool,
	discoveredChains certs.DiscoveredCertChains,
	ageCritical int,
	ageWarning int,
) {

	now := time.Now().UTC()
	certsExpireAgeWarning := now.AddDate(0, 0, ageWarning)
	certsExpireAgeCritical := now.AddDate(0, 0, ageCritical)

	certIssuesCount := discoveredChains.NumProblems(certsExpireAgeCritical, certsExpireAgeWarning)

	fmt.Printf("%d certificates (%d issues) found.\n", len(discoveredChains), certIssuesCount)

	if certIssuesCount == 0 && !showAllHosts {
		fmt.Printf("\nResults: No certificate issues found!\n")
		return
	}

	resultsDescription := "all"
	if !showAllHosts {
		resultsDescription = "issues only"
	}

	fmt.Printf("\nResults (%s):\n\n", resultsDescription)

	tw := tabwriter.NewWriter(os.Stdout, 8, 8, 4, '\t', 0)

	// Header row in output
	fmt.Fprintf(tw,
		"IP Address\tPort\tSubject or SANs\tStatus\tChain Summary\tSerial\n")

	// Separator row
	fmt.Fprintln(tw,
		"---\t---\t---\t---\t---\t---")

	for _, certChain := range discoveredChains {

		hasExpiredCert := certs.HasExpiredCert(certChain.Certs)
		hasExpiringCert := certs.HasExpiringCert(
			certChain.Certs,
			certsExpireAgeCritical,
			certsExpireAgeWarning,
		)

		var statusIcon string
		switch {
		case hasExpiredCert || hasExpiringCert:
			statusIcon = "\xE2\x9B\x94 (!!)"
		default:
			statusIcon = "\xE2\x9C\x85 (OK)"
		}

		// Skip listing IP Addresses with certs without issues *unless*
		// specifically requested.
		if !hasExpiredCert && !hasExpiringCert && !showAllHosts {
			continue
		}

		name := certChain.Certs[0].Subject.CommonName
		if name == "" {
			name = strings.Join(certChain.Certs[0].DNSNames, ", ")
		}

		fmt.Fprintf(
			tw,
			"%v\t%v\t%v\t%s\t%v\t%v\n",
			certChain.Host,
			certChain.Port,
			name,
			statusIcon,
			certs.ChainSummary(
				certChain.Certs,
				certsExpireAgeCritical,
				certsExpireAgeWarning,
			).Summary,
			certs.FormatCertSerialNumber(certChain.Certs[0].SerialNumber),
		)

	}

	fmt.Fprintln(tw)
	if err := tw.Flush(); err != nil {
		log.Printf(
			"error occurred flushing tabwriter: %v",
			err,
		)
	}
}

func printSummaryDetailedLevel(
	showAllCerts bool,
	discoveredChains certs.DiscoveredCertChains,
	ageCritical int,
	ageWarning int,
) {

	now := time.Now().UTC()
	certsExpireAgeWarning := now.AddDate(0, 0, ageWarning)
	certsExpireAgeCritical := now.AddDate(0, 0, ageCritical)

	certIssuesCount := discoveredChains.NumProblems(certsExpireAgeCritical, certsExpireAgeWarning)

	fmt.Printf("%d certificates (%d issues) found.\n", len(discoveredChains), certIssuesCount)

	if certIssuesCount == 0 && !showAllCerts {
		fmt.Printf("\nResults: No certificate issues found!\n")
		return
	}

	resultsDescription := "all"
	if !showAllCerts {
		resultsDescription = "issues only"
	}

	fmt.Printf("\nResults (%s):\n\n", resultsDescription)

	tw := tabwriter.NewWriter(os.Stdout, 8, 8, 4, '\t', 0)

	// Header row in output
	fmt.Fprintf(tw,
		"IP Address\tPort\tSubject or SANs\tStatus (Type)\tSummary\tSerial\n")

	// Separator row
	fmt.Fprintln(tw,
		"---\t---\t---\t---\t---\t---")

	for _, certChain := range discoveredChains {
		for _, cert := range certChain.Certs {

			isExpiredCert := certs.IsExpiredCert(cert)
			isExpiringCert := certs.IsExpiringCert(
				cert,
				certsExpireAgeCritical,
				certsExpireAgeWarning,
			)

			// Skip listing Certificates in the chain which are valid *unless*
			// specifically requested.
			if !isExpiredCert && !isExpiringCert && !showAllCerts {
				continue
			}

			var statusIcon string
			switch {
			case isExpiredCert || isExpiringCert:
				statusIcon = "\xE2\x9B\x94"
			default:
				statusIcon = "\xE2\x9C\x85"
			}

			name := cert.Subject.CommonName
			if name == "" {
				name = strings.Join(cert.DNSNames, ", ")
			}

			fmt.Fprintf(
				tw,
				"%v\t%v\t%v\t%s (%s)\t%v\t%v\n",
				certChain.Host,
				certChain.Port,
				name,
				statusIcon,
				certs.ChainPosition(cert, certChain.Certs),
				certs.ExpirationStatus(cert, certsExpireAgeCritical, certsExpireAgeWarning),
				certs.FormatCertSerialNumber(cert.SerialNumber),
			)
		}

	}

	fmt.Fprintln(tw)
	if err := tw.Flush(); err != nil {
		log.Printf(
			"error occurred flushing tabwriter: %v",
			err,
		)
	}
}
