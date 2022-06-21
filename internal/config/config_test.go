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
		tt := tt

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
