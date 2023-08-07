// Copyright 2023 Brendan Abolivier
// Copyright 2023 Unwired Networks GmbH
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

// Package certsort can read X509 certificates and RSA private keys contained in a list of
// PEM-encoded files, order them, and sort them into output files specified by a
// configuration string.
package certsort

import (
	"bytes"
	"fmt"
)

var (
	// ErrMissingRootCA is returned when the initial configuration mandates the root CA
	// certificate to be included in an output file, but none was found.
	ErrMissingRootCA = fmt.Errorf("missing root CA certificate")
	// ErrMissingIntermediateCA is returned when the initial configuration mandates
	// intermediate CA certificates to be included in an output file, but none was found.
	ErrMissingIntermediateCA = fmt.Errorf("no intermediate CA certificate found")
	// ErrMissingClientCert is returned when the initial configuration mandates the
	// client-facing certificate to be included in an output file, but none was found.
	ErrMissingClientCert = fmt.Errorf("missing client-facing certificate")
	// ErrMissingPrivateKey is returned when the initial configuration mandates the
	// private key associated with the client-facing certificate to be included in an
	// output file, but no such key was found.
	ErrMissingPrivateKey = fmt.Errorf("missing private key for client-facing certificate")
)

/*
SortCertificatesBuffer reads the provided PEM-encoded files, containing either X509
certificates, or RSA private keys. It then sorts them into the output files specified
by the given configuration string, as PEM blocks.

Returns ErrMissingRootCA, ErrMissingIntermediateCA, ErrMissingClientCert or
ErrMissingPrivateKey if one of the tags in the configuration string mandated specific
certificate(s) or key to be included in the output file, but no such certificate
or key could be found.

May return other errors if reading and ordering the certificates and private keys
failed, see the documentation for GetChainAndKeyFromPEMFiles.

The configuration string describes any output file that SortCertificates should write into,
as well as information about what to write in what file. It is formatted as a
semicolon-separated string, with each element being identified by the file name and a list
of tags indicating what the file should contain, as such:

	file:ca_root,cert

The supported tags are:

  - ca_root: The certificate of the root CA.
  - ca_intermediates_root_to_leaf: The certificates for the intermediate CAs, ordered from
    root to leaf.
  - ca_intermediates_leaf_to_root: The certificates for the intermediate CAs, ordered from
    leaf to root.
  - cert: The client-facing certificate.
  - private_key: The RSA private key for the client-facing certificate.

Each piece of content is appended to the corresponding file as a PEM block.

If a tag is present but the corresponding piece of content cannot be found within the
provided files, it is ignored. Tags can be made mandatory by suffixing them with an
exclamation mark (!). If a tag is mandatory but the corresponding piece of content cannot
be found within the provided files, SortCertificates returns an error.

For example, the following configuration string:

	cachain.pem:ca_root,ca_intermediates_root_to_leaf!;cert.pem:cert!;private.pem:private_key!

Instructs SortCertificates to create the following output buffers:

  - cachain.pem: contains the root CA certificate (not mandatory), as well as the
    intermediate CA certificates (mandatory), ordered from root to leaf.
  - cert.pem: contains the client-facing certificate (mandatory).
  - private.pem: contains the private key for the client-facing certificate (mandatory).
*/
func SortCertificatesBuffer(cfg string, keys [][]byte) (map[string]*bytes.Buffer, error) {
	// Parse the configuration string.
	outFiles, err := parseConfigurationString(cfg)
	if err != nil {
		return nil, err
	}

	// Read the certificates and keys from files.
	chain, pkey, err := GetChainAndKeyFromRawPEM(keys)
	if err != nil {
		return nil, err
	}

	var result = map[string]*bytes.Buffer{}
	// Write the contents of the output files.
	for _, file := range outFiles {
		var buf *bytes.Buffer
		if buf, err = writeToBufferSortedWithFileConfig(file, chain, pkey); err != nil {
			return nil, fmt.Errorf("error for output file %s: %v", file.Name, err)
		}
		result[file.Name] = buf

	}

	return result, nil
}

/*
SortCertificateFiles reads files from the given file paths, sorts them with SortCertificates
and writes them into the outDir based on the given configuration.

Please refer to [sortCertificatesBuffer] for more details.
*/
func SortCertificateFiles(cfg string, files []string, outDir string) error {
	keys, err := readFiles(files)
	if err != nil {
		return err
	}

	fileKeyBuffers, err := SortCertificatesBuffer(cfg, keys)
	if err != nil {
		return err
	}

	if err := writeFiles(outDir, fileKeyBuffers); err != nil {
		return err
	}

	return nil
}
