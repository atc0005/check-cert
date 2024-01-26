// Copyright 2024 Adam Chalkley
//
// https://github.com/atc0005/check-cert
//
// Licensed under the MIT License. See LICENSE file in the project root for
// full license information.

package main

import (
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/atc0005/check-cert/internal/config"
)

// TestAssertWorkingConfigValidation asserts that the validation for the most
// common flag combinations works as expected.
//
// This test:
//
// 1) sets CLI flag values as the sysadmin would
// 2) asserts that a config validation error is NOT encountered
func TestAssertWorkingConfigValidation(t *testing.T) {
	// Save old command-line arguments so that we can restore them later
	// https://stackoverflow.com/questions/33723300/how-to-test-the-passing-of-arguments-in-golang
	oldArgs := os.Args

	defer func() {
		t.Log("Restoring os.Args to original value")
		os.Args = oldArgs
	}()

	appName := "certsum"
	server := "google.com"
	port := "443"

	// Clear out any entries added by `go test` or leftovers from
	// previous test cases.
	os.Args = nil

	flagsAndValuesInOrder := []string{
		appName,
		"--" + config.HostsFlagLong, server,
		"--" + config.PortsFlagLong, port,
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

	_, err := config.New(config.AppType{Scanner: true})
	switch {
	case err != nil:
		t.Fatalf("Error encountered when instantiating configuration: %v", err)
	default:
		t.Log("No errors encountered when instantiating configuration")
		// t.Log(cfg.String()) // TODO: Add Stringer implementation
	}

}
