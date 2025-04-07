// Copyright 2022 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/atc0005/check-cert/internal/config"
	"github.com/atc0005/go-nagios"
)

// TestApplyIgnoreValidationFlagsForConfigValidationErrors asserts that the
// apply and ignore CSV value flags operate as expected at a high level. The
// config package tests are responsible for asserting specific internal
// behavior.
//
// This test:
//
// 1) sets CLI flag values as the sysadmin would
// 2) does not evaluate whether validation check results are ignored or
// applied (just whether) a config validation error is encountered
func TestApplyIgnoreValidationFlagsForConfigValidationErrors(t *testing.T) {

	const appName string = "check_cert"

	tests := []struct {
		name          string
		server        string
		validateFlags []string
		err           error
	}{
		{
			name:   "ApplyValidationResult",
			server: "www.example.com",
			validateFlags: []string{
				"--" + config.ApplyValidationResultFlag,
				config.ValidationKeywordExpiration,
			},
			err: nil,
		},
		{
			name:   "IgnoreValidationResult",
			server: "www.example.com",
			validateFlags: []string{
				"--" + config.IgnoreValidationResultFlag,
				config.ValidationKeywordExpiration,
			},
			err: nil,
		},
		{
			name:   "IgnoreValidationResultMultipleKeywords",
			server: "www.example.com",
			validateFlags: []string{
				"--" + config.IgnoreValidationResultFlag,
				strings.Join(
					[]string{
						config.ValidationKeywordExpiration,
						config.ValidationKeywordSANsList,
						config.ValidationKeywordHostname,
					}, ", "),
			},
			err: nil,
		},
		{
			name:   "ApplySANsListValidationResultWithSANsEntries",
			server: "www.example.com",
			validateFlags: []string{
				"--" + config.ApplyValidationResultFlag,
				config.ValidationKeywordSANsList,
				"--" + config.SANsEntriesFlagLong,
				"www.example.com",
			},
			err: nil,
		},
		{
			name:   "ApplySANsListValidationResultWithoutSANsEntries",
			server: "www.example.com",
			validateFlags: []string{
				"--" + config.ApplyValidationResultFlag,
				config.ValidationKeywordSANsList,
			},
			err: errors.New("required SANs entries flag and value missing for explicit SANs list validation apply request"),
		},
		{
			name:   "ApplyValidationResultMultipleKeywordsWithoutSANsEntriesFlag",
			server: "www.example.com",
			validateFlags: []string{
				"--" + config.ApplyValidationResultFlag,
				strings.Join(
					[]string{
						config.ValidationKeywordExpiration,
						config.ValidationKeywordSANsList,
						config.ValidationKeywordHostname,
					}, ", "),
			},
			err: errors.New("required SANs entries flag and value missing for explicit SANs list validation apply request"),
		},
		{
			name:   "ApplyValidationResultMultipleKeywordsWithSANsEntriesFlag",
			server: "www.example.com",
			validateFlags: []string{
				"--" + config.ApplyValidationResultFlag,
				strings.Join(
					[]string{
						config.ValidationKeywordExpiration,
						config.ValidationKeywordSANsList,
						config.ValidationKeywordHostname,
					}, ", "),
				"--" + config.SANsEntriesFlagLong,
				"www.example.com",
			},
			err: nil,
		},
		{
			name:   "ApplyValidationResultAndIgnoreValidationResult",
			server: "www.example.com",
			validateFlags: []string{
				"--" + config.ApplyValidationResultFlag,
				config.ValidationKeywordExpiration,
				"--" + config.IgnoreValidationResultFlag,
				config.ValidationKeywordExpiration,
			},
			err: errors.New("validation keyword was specified as value for multiple flags"),
		},
		{
			name:   "ApplyValidationResultUsingInvalidKeyword",
			server: "www.example.com",
			validateFlags: []string{
				"--" + config.ApplyValidationResultFlag,
				"tacos",
			},
			err: errors.New("invalid keyword specified for apply validation results flag"),
		},
		{
			name:   "IgnoreValidationResult",
			server: "www.example.com",
			validateFlags: []string{
				"--" + config.IgnoreValidationResultFlag,
				"tacos",
			},
			err: errors.New("invalid keyword specified for ignore validation results flag"),
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
				"--server", tt.server,
			}

			for i, item := range flagsAndValuesInOrder {
				if strings.TrimSpace(item) != "" {
					os.Args = append(os.Args, item)
				} else {
					t.Logf("Skipping item %d due to empty value", i)
				}
			}
			os.Args = append(os.Args, tt.validateFlags...)

			t.Log("INFO: Old os.Args before rewriting:\n", oldArgs)
			t.Log("INFO: New os.Args before init config:\n", os.Args)

			// Reset parsed flags by discarding the previous default flagset
			// and creating a new one from scratch.
			//
			// TODO: This can be fixed properly by implementing a custom
			// flagset in the config package.
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

			// cfg, err := config.New(config.AppType{Plugin: true})
			_, err := config.New(config.AppType{Plugin: true})
			switch {
			case err != nil && tt.err == nil:
				t.Errorf("want: %v; got: %v", tt.err, err)
			case err == nil && tt.err != nil:
				t.Errorf("want: %v; got: %v", tt.err, err)
			default:
				t.Log("No errors encountered when instantiating configuration")
				// t.Log(cfg.String()) // TODO: Add Stringer implementation
			}
		})
	}
}

// TestApplyValidationResults asserts that with a given set of flags and
// values that the "should validation check result be applied" question is
// answered as expected.
//
// This test very closely mirrors another test in the config package, but
// relies on setting the configuration values used for tests using the same
// CLI flags that a sysadmin would. This exercises the validation and
// apply/ignore logic paths as a consumer of the config package.
func TestApplyValidationResults(t *testing.T) {

	tests := []struct {
		name                   string
		server                 string
		validateFlagsAndValues []string
		validateFunc           func(config.Config) bool
		applyResults           bool
	}{
		{
			name:                   "DefaultValidateExpirationResults",
			server:                 "www.example.com",
			validateFlagsAndValues: []string{},
			validateFunc:           config.Config.ApplyCertExpirationValidationResults,

			// The sysadmin cannot know what the internal default value is, so
			// has to go off of what is documented in the README.
			applyResults: true,
		},
		{
			name:   "IgnoreValidateExpirationResults",
			server: "www.example.com",
			validateFlagsAndValues: []string{
				"--" + config.IgnoreValidationResultFlag,
				config.ValidationKeywordExpiration,
			},
			validateFunc: config.Config.ApplyCertExpirationValidationResults,
			applyResults: false,
		},
		{
			name:   "ApplyValidateExpirationResults",
			server: "www.example.com",
			validateFlagsAndValues: []string{
				"--" + config.ApplyValidationResultFlag,
				config.ValidationKeywordExpiration,
			},
			validateFunc: config.Config.ApplyCertExpirationValidationResults,
			applyResults: true,
		},
		{
			name:                   "DefaultValidateHostnameResults",
			server:                 "www.example.com",
			validateFlagsAndValues: []string{},
			validateFunc:           config.Config.ApplyCertHostnameValidationResults,

			// The sysadmin cannot know what the internal default value is, so
			// has to go off of what is documented in the README.
			applyResults: true,
		},
		{
			name:   "IgnoreValidateHostnameResults",
			server: "www.example.com",
			validateFlagsAndValues: []string{
				"--" + config.IgnoreValidationResultFlag,
				config.ValidationKeywordHostname,
			},
			validateFunc: config.Config.ApplyCertHostnameValidationResults,
			applyResults: false,
		},
		{
			name:   "ApplyValidateHostnameResults",
			server: "www.example.com",
			validateFlagsAndValues: []string{
				"--" + config.ApplyValidationResultFlag,
				config.ValidationKeywordHostname,
			},
			validateFunc: config.Config.ApplyCertHostnameValidationResults,
			applyResults: true,
		},
		{
			name:                   "DefaultValidateSANsListResults",
			server:                 "www.example.com",
			validateFlagsAndValues: []string{},
			validateFunc:           config.Config.ApplyCertSANsListValidationResults,

			// From the README:
			//
			// The SANs list validation check is applied *if* SANs entries are
			// provided. If SANs entries are not specified, this validation
			// check is performed, but noted as ignored in the output (and not
			// used when determining final plugin state); without SANs entries
			// to validate the SANs list validation check result is of limited
			// value. If explicitly requested and SANs entries are not
			// provided a configuration error is emitted and the plugin
			// terminates.
			applyResults: true,
		},
		{
			name:   "IgnoreValidateSANsListResults",
			server: "www.example.com",
			validateFlagsAndValues: []string{
				"--" + config.IgnoreValidationResultFlag,
				config.ValidationKeywordSANsList,
			},
			validateFunc: config.Config.ApplyCertSANsListValidationResults,
			applyResults: false,
		},
		{
			name:   "ApplyValidateSANsListResults",
			server: "www.example.com",
			validateFlagsAndValues: []string{
				"--" + config.ApplyValidationResultFlag,
				config.ValidationKeywordSANsList,
			},
			validateFunc: config.Config.ApplyCertSANsListValidationResults,
			applyResults: true,
		},

		{
			name:                   "DefaultChainOrderResults",
			server:                 "www.example.com",
			validateFlagsAndValues: []string{},
			validateFunc:           config.Config.ApplyCertChainOrderValidationResults,

			// This validation is not part of the original set and has to be
			// opted into.
			applyResults: false,
		},
		{
			name:   "IgnoreValidateChainOrderResults",
			server: "www.example.com",
			validateFlagsAndValues: []string{
				"--" + config.IgnoreValidationResultFlag,
				config.ValidationKeywordChainOrder,
			},
			validateFunc: config.Config.ApplyCertChainOrderValidationResults,
			applyResults: false,
		},
		{
			name:   "ApplyValidateChainOrderResults",
			server: "www.example.com",
			validateFlagsAndValues: []string{
				"--" + config.ApplyValidationResultFlag,
				config.ValidationKeywordChainOrder,
			},
			validateFunc: config.Config.ApplyCertChainOrderValidationResults,
			applyResults: true,
		},

		{
			name:                   "DefaultRootResults",
			server:                 "www.example.com",
			validateFlagsAndValues: []string{},
			validateFunc:           config.Config.ApplyCertRootValidationResults,

			// This validation is not part of the original set and has to be
			// opted into.
			applyResults: false,
		},
		{
			name:   "IgnoreValidateRootResults",
			server: "www.example.com",
			validateFlagsAndValues: []string{
				"--" + config.IgnoreValidationResultFlag,
				config.ValidationKeywordRoot,
			},
			validateFunc: config.Config.ApplyCertRootValidationResults,
			applyResults: false,
		},
		{
			name:   "ApplyValidateRootResults",
			server: "www.example.com",
			validateFlagsAndValues: []string{
				"--" + config.ApplyValidationResultFlag,
				config.ValidationKeywordRoot,
			},
			validateFunc: config.Config.ApplyCertRootValidationResults,
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

			// Save old command-line arguments so that we can restore them later
			// https://stackoverflow.com/questions/33723300/how-to-test-the-passing-of-arguments-in-golang
			oldArgs := os.Args

			defer func() {
				t.Log("Restoring os.Args to original value")
				os.Args = oldArgs
			}()

			appName := "check_cert"

			// Clear out any entries added by `go test` or leftovers from
			// previous test cases.
			os.Args = nil

			flagsAndValuesInOrder := []string{
				appName,
				"--" + config.ServerFlagLong, tt.server,

				// We provide this flag & placeholder value in order to ensure
				// that the list is available for when the SANs list
				// validation is used.
				"--" + config.SANsEntriesFlagLong, "tacos.example.com",
			}

			flagsAndValuesInOrder = append(flagsAndValuesInOrder, tt.validateFlagsAndValues...)

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

			cfg, err := config.New(config.AppType{Plugin: true})
			switch {
			case err != nil:
				t.Fatalf("Error encountered when instantiating configuration: %v", err)
			default:
				t.Log("No errors encountered when instantiating configuration")
				// t.Log(cfg.String()) // TODO: Add Stringer implementation
			}

			switch {

			// If the test case indicates that validation results should be
			// applied but the validation function indicates it is not.
			case tt.applyResults && !tt.validateFunc(*cfg):
				t.Errorf(
					"want: validation results applied (%v); got: validation results applied (%v)",
					tt.applyResults,
					tt.validateFunc(*cfg),
				)

			// If the test case indicates that validation results should not
			// be applied but the validation function indicates it is.
			case !tt.applyResults && tt.validateFunc(*cfg):
				t.Errorf(
					"want: validation results applied (%v); got: validation results applied (%v)",
					tt.applyResults,
					tt.validateFunc(*cfg),
				)

			// Test case and validation function agree.
			default:
				t.Logf(
					"want: validation results applied (%v); got: validation results applied (%v)",
					tt.applyResults,
					tt.validateFunc(*cfg),
				)
			}

		})
	}

}

// TestEmptyClientPerfDataAndConstructedPluginProducesDefaultTimeMetric
// asserts that omitted performance data from client code produces a default
// time metric when using the Plugin constructor.
func TestEmptyClientPerfDataAndConstructedPluginProducesDefaultTimeMetric(t *testing.T) {
	t.Parallel()

	// Setup Plugin type the same way that client code using the
	// constructor would.
	plugin := nagios.NewPlugin()

	// Performance Data metrics are not emitted if we do not supply a
	// ServiceOutput value.
	plugin.ServiceOutput = "TacoTuesday"

	var outputBuffer strings.Builder

	plugin.SetOutputTarget(&outputBuffer)

	// os.Exit calls break tests
	plugin.SkipOSExit()

	// Process exit state, emit output to our output buffer.
	plugin.ReturnCheckResults()

	want := fmt.Sprintf(
		"%s | %s",
		plugin.ServiceOutput,
		"'time'=",
	)

	got := outputBuffer.String()

	if !strings.Contains(got, want) {
		t.Errorf("ERROR: Plugin output does not contain the expected time metric")
		t.Errorf("\nwant %q\ngot %q", want, got)
	} else {
		t.Logf("OK: Emitted performance data contains the expected time metric.")
	}
}
