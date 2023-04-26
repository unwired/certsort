// Copyright 2023 Brendan Abolivier
// Copyright 2023 Unwired Networks GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package certsort

import (
	"fmt"
	"regexp"
	"strings"
)

// ContentTag represents a tag indicating what type of content is included in a file.
type ContentTag int

const (
	// CTRootCA indicates that the file should include the root CA certificate.
	CTRootCA ContentTag = iota
	// CTIntermediatesCARootToLeaf indicates that the file should include intermediate CA
	// certificates, ordered from root to leaf.
	CTIntermediatesCARootToLeaf
	// CTIntermediatesCALeafToRoot indicates that the file should include intermediate CA
	// certificates, ordered from leaf to root.
	CTIntermediatesCALeafToRoot
	// CTClientCert indicates that the file should include the client-facing certificate.
	CTClientCert
	// CTPrivateKey indicates that the file should include the private key for the
	// client-facing certificate.
	CTPrivateKey
)

// ctLength must always be the length of possible content tags
// Used to do stable iterations over a ContentTag map.
const ctLength = int(CTPrivateKey) + 1

// ErrEmptyConfigurationString is returned when trying to parse a configuration string
// that is an empty string.
var ErrEmptyConfigurationString = fmt.Errorf("empty configuration string")

// stringToContentTag maps from a raw string extracted from the configuration string,
// to the matching ContentTag variable.
var stringToContentTag = map[string]ContentTag{
	"ca_root":                       CTRootCA,
	"ca_intermediates_root_to_leaf": CTIntermediatesCARootToLeaf,
	"ca_intermediates_leaf_to_root": CTIntermediatesCALeafToRoot,
	"cert":                          CTClientCert,
	"private_key":                   CTPrivateKey,
}

// OutputFileConfig represents the configuration for an output file.
type OutputFileConfig struct {
	// The name of the file.
	Name string
	// The content tags for this file, with a boolean associated to each indicating
	// whether they're mandatory.
	ContentValues map[ContentTag]bool
}

// parseAndStoreContentValues reads a string containing content tags, parses each
// content tag, and stores it into the current instance of the structure.
func (cfg *OutputFileConfig) parseAndStoreContentValues(cv string) error {
	cfg.ContentValues = make(map[ContentTag]bool)

	// Iterate over the content tags.
	contentValues := strings.Split(cv, ",")
	for _, rawCV := range contentValues {
		// If a content tag ends with "!", then it's mandatory.
		mandatory := strings.HasSuffix(rawCV, "!")

		// Don't include any "!" in the content tag's name.
		cvName := rawCV
		if mandatory {
			cvName = cvName[:len(cvName)-1]
		}

		// Validate that the content tag is one that we know of.
		if cv, supported := stringToContentTag[cvName]; supported {
			// Validate that a content tag is only given once for a given file.
			if _, exists := cfg.ContentValues[cv]; exists {
				return fmt.Errorf("duplicate content tag: %s", cvName)
			}

			cfg.ContentValues[cv] = mandatory
		} else {
			return fmt.Errorf("unknown content tag: %s", cvName)
		}
	}

	return nil
}

// configStringFileFormat represents the format used to describe a single file in the
// configuration string.
var configStringFileFormat = regexp.MustCompile(`^([\w.]+):([\w,!]+)$`)

// parseConfigurationString parses the given configuration string into a slice that
// represents all the output files and their configuration.
// Returns an error if the string is empty or malformed.
func parseConfigurationString(s string) ([]*OutputFileConfig, error) {
	// Ensure that there are files being described in the configuration string.
	if len(s) == 0 {
		return nil, ErrEmptyConfigurationString
	}

	// Process each file.
	files := strings.Split(s, ";")
	configs := make([]*OutputFileConfig, len(files))
	for i, file := range files {
		// Validate and parse the file's description. If FindStringSubmatch returns nil,
		// then the string does not match.
		submatches := configStringFileFormat.FindStringSubmatch(file)
		if submatches == nil {
			return nil, fmt.Errorf("invalid format for file at index %d: %s", i, file)
		}

		config := new(OutputFileConfig)
		config.Name = submatches[1]

		if err := config.parseAndStoreContentValues(submatches[2]); err != nil {
			return nil, err
		}

		configs[i] = config
	}

	return configs, nil
}
