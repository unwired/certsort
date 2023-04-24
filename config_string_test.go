// Copyright 2023 Brendan Abolivier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package certsort

import (
	"encoding/json"
	"strings"
	"testing"
)

// Test that an example valid configuration string is correctly parsed into the correct
// data structure.
func TestConfigurationStringParse(t *testing.T) {
	configString := "cachain.pem:ca_root,ca_intermediates_root_to_leaf!;cert.pem:cert!;private.pem:private_key!"

	expected := []OutputFileConfig{
		{
			Name: "cachain.pem",
			ContentValues: map[ContentTag]bool{
				CTRootCA:                    false,
				CTIntermediatesCARootToLeaf: true,
			},
		},
		{
			Name: "cert.pem",
			ContentValues: map[ContentTag]bool{
				CTClientCert: true,
			},
		},
		{
			Name: "private.pem",
			ContentValues: map[ContentTag]bool{
				CTPrivateKey: true,
			},
		},
	}

	res, err := parseConfigurationString(configString)

	if err != nil {
		t.Fatalf("Error in parseConfigurationString: %s", err)
	}

	testCompareWithJSON(t, expected, res)
}

// Test that a valid configuration string describing only one file is correctly parsed.
func TestConfigurationStringSingleFile(t *testing.T) {
	configString := "cachain.pem:ca_root,ca_intermediates_root_to_leaf!"

	expected := []OutputFileConfig{
		{
			Name: "cachain.pem",
			ContentValues: map[ContentTag]bool{
				CTRootCA:                    false,
				CTIntermediatesCARootToLeaf: true,
			},
		},
	}

	res, err := parseConfigurationString(configString)

	if err != nil {
		t.Fatalf("Error in parseConfigurationString: %s", err)
	}

	testCompareWithJSON(t, expected, res)
}

// Test that an error is returned when trying to parse an empty string.
func TestConfigurationStringEmptyString(t *testing.T) {
	_, err := parseConfigurationString("")

	if err == nil {
		t.Fatalf("parseConfigurationString did not return an error")
	}

	if err != ErrEmptyConfigurationString {
		t.Fatalf(
			"parseConfigurationString returned an unexpected error:"+
				" expected \"%s\", got \"%s\"", ErrEmptyConfigurationString, err,
		)
	}
}

// Test that an error is returned when trying to parse a configuration string with an
// invalid format.
func TestConfigurationStringInvalidFormat(t *testing.T) {
	configString := "cachain.pem::ca_root,ca_intermediates_root_to_leaf!"

	_, err := parseConfigurationString(configString)

	if err == nil {
		t.Fatalf("parseConfigurationString did not return an error")
	}

	if !strings.HasPrefix(err.Error(), "invalid format") {
		t.Fatalf("parseConfigurationString returned an unexpected error: %s", err)
	}
}

// testCompareWithJSON is a test utility that uses JSON marshalling to compare a test
// result with the expected data.
func testCompareWithJSON(t *testing.T, expected any, result any) {
	// Marshal the expected result and cast it to a string.
	b, err := json.Marshal(expected)
	if err != nil {
		t.Fatalf("Error in json.Marshal: %s", err)
	}
	expectedString := string(b)

	// Marshal the actual result and cast it to a string.
	b, err = json.Marshal(result)
	if err != nil {
		t.Fatalf("Error in json.Marshal: %s", err)
	}
	resultString := string(b)

	// Compare both results.
	if expectedString != resultString {
		t.Fatalf("Unexpected result!\nExpected: %s\nResult: %s", expectedString, resultString)
	}
}
