// Copyright 2022 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package config

import (
	"errors"
	"flag"
	"os"
	"strings"
	"testing"
)

func TestExpirationAgeThresholds(t *testing.T) {

	const appName string = "check_cert"

	tests := []struct {
		name        string
		ageCritical string
		ageWarning  string
		err         error
	}{
		{
			name:        "ExplicitDefaults",
			ageCritical: "15",
			ageWarning:  "30",
			err:         nil,
		},
		{
			name:        "IncorrectCriticalThreshold",
			ageCritical: "80",
			ageWarning:  "50",
			err:         errors.New("expiration age critical threshold higher than warning"),
		},
		{
			name:        "ZeroValueWarningThreshold",
			ageCritical: "30",
			ageWarning:  "0",
			err:         errors.New("expiration age WARNING threshold cannot be zero"),
		},
		{
			name:        "ZeroValueCriticalThreshold",
			ageCritical: "0",
			ageWarning:  "30",
			err:         errors.New("expiration age CRITICAL threshold cannot be zero"),
		},
		{
			name:        "EqualValueCriticalAndWarningThresholds",
			ageCritical: "30",
			ageWarning:  "30",
			err:         errors.New("expiration age thresholds cannot be equal"),
		},
	}

	for _, tt := range tests {
		// Make scopelint linter happy
		// https://stackoverflow.com/questions/68559574/using-the-variable-on-range-scope-x-in-function-literal-scopelint
		//
		// NOTE: Not needed as of Go 1.22.
		//
		// tt := tt

		t.Run(tt.name, func(t *testing.T) {
			// Save old command-line arguments so that we can restore them later
			// https://stackoverflow.com/questions/33723300/how-to-test-the-passing-of-arguments-in-golang
			oldArgs := os.Args

			defer func() {
				t.Log("Restoring os.Args to original value")
				os.Args = oldArgs
			}()

			// Clear out any entries added by `go test` or leftovers from
			// previous test cases.
			os.Args = nil

			flagsAndValuesInOrder := []string{
				appName,
				"--server", "www.example.com",
				"--port", "443",
				"--age-critical", tt.ageCritical,
				"--age-warning", tt.ageWarning,
			}

			for i, item := range flagsAndValuesInOrder {

				if strings.TrimSpace(item) != "" {
					os.Args = append(os.Args, item)
				} else {
					t.Logf("Skipping item %d due to empty value", i)
				}
			}

			t.Log("INFO: Old os.Args before rewriting:\n", oldArgs)
			t.Log("INFO: New os.Args before init config:\n", os.Args)

			// Reset parsed flags by discarding the previous default flagset
			// and creating a new one from scratch.
			//
			// TODO: This can be fixed properly by implementing a custom
			// flagset in the config package.
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

			_, err := New(AppType{Plugin: true})
			switch {
			case err != nil && tt.err == nil:
				t.Errorf("want: %v; got: %v", tt.err, err)
			case err == nil && tt.err != nil:
				t.Errorf("want: %v; got: %v", tt.err, err)
			default:
				t.Log("No errors encountered when instantiating configuration")
			}

		})
	}
}

// TestConfigValidationForCheckResultsFlags asserts that given a specific
// configuration based on expected flag values and "apply" or "ignore"
// settings that configuration validation passes or fails as indicated.
func TestConfigValidationForCheckResultsFlags(t *testing.T) {

	tests := []struct {
		name        string
		cfg         Config
		errExpected bool
	}{
		{
			name: "DefaultValidateExpirationResults",
			cfg: Config{
				Port:         443,
				LoggingLevel: defaultLogLevel,
				Server:       "www.example.com",
				AgeWarning:   defaultCertExpireAgeWarning,
				AgeCritical:  defaultCertExpireAgeCritical,
			},
			errExpected: false,
		},
		{
			name: "IgnoreValidateExpirationResults",
			cfg: Config{
				Port:                    443,
				LoggingLevel:            defaultLogLevel,
				Server:                  "www.example.com",
				AgeWarning:              defaultCertExpireAgeWarning,
				AgeCritical:             defaultCertExpireAgeCritical,
				ignoreValidationResults: []string{ValidationKeywordExpiration},
			},
			errExpected: false,
		},
		{
			name: "ApplyValidateExpirationResults",
			cfg: Config{
				Port:                   443,
				LoggingLevel:           defaultLogLevel,
				Server:                 "www.example.com",
				AgeWarning:             defaultCertExpireAgeWarning,
				AgeCritical:            defaultCertExpireAgeCritical,
				applyValidationResults: []string{ValidationKeywordExpiration},
			},
			errExpected: false,
		},
		{
			name: "DefaultValidateHostnameResults",
			cfg: Config{
				Port:         443,
				LoggingLevel: defaultLogLevel,
				Server:       "www.example.com",
				AgeWarning:   defaultCertExpireAgeWarning,
				AgeCritical:  defaultCertExpireAgeCritical,
			},
			errExpected: false,
		},
		{
			name: "IgnoreValidateHostnameResults",
			cfg: Config{
				Port:                    443,
				LoggingLevel:            defaultLogLevel,
				Server:                  "www.example.com",
				AgeWarning:              defaultCertExpireAgeWarning,
				AgeCritical:             defaultCertExpireAgeCritical,
				ignoreValidationResults: []string{ValidationKeywordHostname},
			},
			errExpected: false,
		},
		{
			name: "ApplyValidateHostnameResults",
			cfg: Config{
				Port:                   443,
				LoggingLevel:           defaultLogLevel,
				Server:                 "www.example.com",
				AgeWarning:             defaultCertExpireAgeWarning,
				AgeCritical:            defaultCertExpireAgeCritical,
				applyValidationResults: []string{ValidationKeywordHostname},
			},
			errExpected: false,
		},
		{
			name: "DefaultValidateSANsListResultsWithoutSANsEntries",
			cfg: Config{
				Port:         443,
				LoggingLevel: defaultLogLevel,
				Server:       "www.example.com",
				AgeWarning:   defaultCertExpireAgeWarning,
				AgeCritical:  defaultCertExpireAgeCritical,
			},
			errExpected: false,
		},
		{
			name: "DefaultValidateSANsListResultsWithSANsEntries",
			cfg: Config{
				Port:         443,
				LoggingLevel: defaultLogLevel,
				Server:       "www.example.com",
				AgeWarning:   defaultCertExpireAgeWarning,
				AgeCritical:  defaultCertExpireAgeCritical,
				SANsEntries:  []string{"tacos.example.com"},
			},
			errExpected: false,
		},
		{
			name: "IgnoreValidateSANsListResults",
			cfg: Config{
				Port:                    443,
				LoggingLevel:            defaultLogLevel,
				Server:                  "www.example.com",
				AgeWarning:              defaultCertExpireAgeWarning,
				AgeCritical:             defaultCertExpireAgeCritical,
				ignoreValidationResults: []string{ValidationKeywordSANsList},
			},
			errExpected: false,
		},
		{
			name: "ApplyValidateSANsListResultsWithSANsEntries",
			cfg: Config{
				Port:                   443,
				LoggingLevel:           defaultLogLevel,
				Server:                 "www.example.com",
				AgeWarning:             defaultCertExpireAgeWarning,
				AgeCritical:            defaultCertExpireAgeCritical,
				applyValidationResults: []string{ValidationKeywordSANsList},
				SANsEntries:            []string{"tacos.example.com"},
			},
			errExpected: false,
		},
		{
			name: "ApplyValidateSANsListResultsWithoutSANsEntries",
			cfg: Config{
				Port:                   443,
				LoggingLevel:           defaultLogLevel,
				Server:                 "www.example.com",
				AgeWarning:             defaultCertExpireAgeWarning,
				AgeCritical:            defaultCertExpireAgeCritical,
				applyValidationResults: []string{ValidationKeywordSANsList},
				// SANsEntries:            []string{"tacos.example.com"},
			},
			errExpected: true,
		},
	}

	for _, tt := range tests {
		// Make scopelint linter happy
		// https://stackoverflow.com/questions/68559574/using-the-variable-on-range-scope-x-in-function-literal-scopelint
		//
		// NOTE: Not needed as of Go 1.22.
		//
		// tt := tt

		t.Run(tt.name, func(t *testing.T) {

			// Perform configuration validation.
			cfgErr := tt.cfg.validate(AppType{Plugin: true})
			switch {
			case !tt.errExpected && cfgErr != nil:
				t.Errorf("want error: %v; got %v", tt.errExpected, cfgErr)
			case tt.errExpected && cfgErr == nil:
				t.Errorf("want error: %v; got %v", tt.errExpected, cfgErr)
			default:
				t.Log("configuration validation successful")
			}
		})
	}

}

// TestApplyIgnoreDecision asserts that given a specific configuration (based
// on expected flag values) the "should validation check result be applied"
// question is answered as expected. Configuration validation is not
// performed.
func TestApplyIgnoreDecision(t *testing.T) {

	tests := []struct {
		name         string
		cfg          Config
		validateFunc func(Config) bool
		applyResults bool
	}{
		{
			name:         "DefaultValidateExpirationResults",
			cfg:          Config{},
			validateFunc: Config.ApplyCertExpirationValidationResults,
			applyResults: defaultApplyCertExpirationValidationResults,
		},
		{
			name: "IgnoreValidateExpirationResults",
			cfg: Config{
				ignoreValidationResults: []string{ValidationKeywordExpiration},
			},
			validateFunc: Config.ApplyCertExpirationValidationResults,
			applyResults: false,
		},
		{
			name: "ApplyValidateExpirationResults",
			cfg: Config{
				applyValidationResults: []string{ValidationKeywordExpiration},
			},
			validateFunc: Config.ApplyCertExpirationValidationResults,
			applyResults: true,
		},
		{
			name:         "DefaultValidateHostnameResults",
			cfg:          Config{},
			validateFunc: Config.ApplyCertHostnameValidationResults,
			applyResults: defaultApplyCertHostnameValidationResults,
		},
		{
			name: "IgnoreValidateHostnameResults",
			cfg: Config{
				ignoreValidationResults: []string{ValidationKeywordHostname},
			},
			validateFunc: Config.ApplyCertHostnameValidationResults,
			applyResults: false,
		},
		{
			name: "ApplyValidateHostnameResults",
			cfg: Config{
				applyValidationResults: []string{ValidationKeywordHostname},
			},
			validateFunc: Config.ApplyCertHostnameValidationResults,
			applyResults: true,
		},
		{
			name:         "DefaultValidateSANsListResultsWithoutSANsEntries",
			cfg:          Config{},
			validateFunc: Config.ApplyCertSANsListValidationResults,
			applyResults: false,
		},
		{
			name: "DefaultValidateSANsListResultsWithSANsEntries",
			cfg: Config{
				SANsEntries: []string{"tacos.example.com"},
			},
			validateFunc: Config.ApplyCertSANsListValidationResults,
			applyResults: defaultApplyCertSANsListValidationResults,
		},
		{
			name: "IgnoreValidateSANsListResults",
			cfg: Config{
				ignoreValidationResults: []string{ValidationKeywordSANsList},
			},
			validateFunc: Config.ApplyCertSANsListValidationResults,
			applyResults: false,
		},
		{
			name: "ApplyValidateSANsListResults",
			cfg: Config{
				applyValidationResults: []string{ValidationKeywordSANsList},
			},
			validateFunc: Config.ApplyCertSANsListValidationResults,
			applyResults: true,
		},
		{
			name:         "DefaultValidateChainOrderResults",
			cfg:          Config{},
			validateFunc: Config.ApplyCertChainOrderValidationResults,
			applyResults: defaultApplyCertChainOrderValidationResults,
		},
		{
			name: "IgnoreValidateChainOrderResults",
			cfg: Config{
				ignoreValidationResults: []string{ValidationKeywordChainOrder},
			},
			validateFunc: Config.ApplyCertChainOrderValidationResults,
			applyResults: false,
		},
		{
			name: "ApplyValidateChainOrderResults",
			cfg: Config{
				applyValidationResults: []string{ValidationKeywordChainOrder},
			},
			validateFunc: Config.ApplyCertChainOrderValidationResults,
			applyResults: true,
		},
		{
			name:         "DefaultValidateRootResults",
			cfg:          Config{},
			validateFunc: Config.ApplyCertRootValidationResults,
			applyResults: defaultApplyCertRootValidationResults,
		},
		{
			name: "IgnoreValidateRootResults",
			cfg: Config{
				ignoreValidationResults: []string{ValidationKeywordRoot},
			},
			validateFunc: Config.ApplyCertRootValidationResults,
			applyResults: false,
		},
		{
			name: "ApplyValidateRootResults",
			cfg: Config{
				applyValidationResults: []string{ValidationKeywordRoot},
			},
			validateFunc: Config.ApplyCertRootValidationResults,
			applyResults: true,
		},
	}

	for _, tt := range tests {
		// Make scopelint linter happy
		// https://stackoverflow.com/questions/68559574/using-the-variable-on-range-scope-x-in-function-literal-scopelint
		//
		// NOTE: Not needed as of Go 1.22.
		//
		// tt := tt

		t.Run(tt.name, func(t *testing.T) {

			switch {

			// If the test case indicates that validation results should be
			// applied but the validation function indicates it is not.
			case tt.applyResults && !tt.validateFunc(tt.cfg):
				t.Errorf(
					"want: validation results applied (%v); got: validation results applied (%v)",
					tt.applyResults,
					tt.validateFunc(tt.cfg),
				)

			// If the test case indicates that validation results should not
			// be applied but the validation function indicates it is.
			case !tt.applyResults && tt.validateFunc(tt.cfg):
				t.Errorf(
					"want: validation results applied (%v); got: validation results applied (%v)",
					tt.applyResults,
					tt.validateFunc(tt.cfg),
				)

			// Test case and validation function agree.
			default:
				t.Logf(
					"want: validation results applied (%v); got: validation results applied (%v)",
					tt.applyResults,
					tt.validateFunc(tt.cfg),
				)
			}

		})
	}

}
