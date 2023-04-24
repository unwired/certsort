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

// Package certsort can read X509 certificates and RSA private keys contained in a list of
// PEM-encoded files, order them, and sort them into output files specified by a
// configuration string.
package certsort

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
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
SortCertificates reads the provided PEM-encoded files, containing either X509
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

Instructs SortCertificates to create the following output files:

  - cachain.pem: contains the root CA certificate (not mandatory), as well as the
    intermediate CA certificates (mandatory), ordered from root to leaf.
  - cert.pem: contains the client-facing certificate (mandatory).
  - private.pem: contains the private key for the client-facing certificate (mandatory).
*/
func SortCertificates(cfg string, files []string, outDir string) error {
	// Parse the configuration string.
	outFiles, err := parseConfigurationString(cfg)
	if err != nil {
		return err
	}

	// Read the certificates and keys from files.
	chain, pkey, err := GetChainAndKeyFromPEMFiles(files)
	if err != nil {
		return err
	}

	// Write the contents of the output files.
	for _, file := range outFiles {
		if err = writeFile(outDir, file, chain, pkey); err != nil {
			return fmt.Errorf("error for output file %s: %v", file.Name, err)
		}
	}

	return nil
}

// writeFile writes the configured content into a given output file.
// Returns ErrMissingRootCA, ErrMissingIntermediateCA, ErrMissingClientCert or
// ErrMissingPrivateKey if one of the content tags mandated specific certificate(s) or
// key to be included in the output file, but no such certificate or key could be found.
func writeFile(
	outDir string,
	file *OutputFileConfig,
	chain *CertChain,
	pkey *rsa.PrivateKey,
) error {
	// Buffer containing the file's content.
	buf := &bytes.Buffer{}

	// Iterate over the configured content tags for this file.
	for cv, mandatory := range file.ContentValues {
		if cv == CTRootCA {
			// If the content tag is for the root CA certificate, write it into the
			// buffer if it exists.
			if chain.Root.Type == CertTypeRootCA {
				err := writeToBufferAsPEM(
					buf, chain.Root.Bytes(), PEMBlockTypeCertificate,
				)
				if err != nil {
					return err
				}
			} else if mandatory {
				// If the root CA certificate does not exist, return an error.
				return ErrMissingRootCA
			}
		} else if cv == CTIntermediatesCARootToLeaf {
			// If the content tag is for intermediate CA in the "normal" order (root to
			// leaf), then walk through the chain in that order and write any matching
			// certificate. writeIntermediateCAsToBuffer returns an error if no such
			// certificate could be found and the content tag makes it mandatory.
			err := writeIntermediateCAsToBuffer(buf, chain, false, mandatory)
			if err != nil {
				return err
			}
		} else if cv == CTIntermediatesCALeafToRoot {
			// If the content tag is for intermediate CA in the "reverse" order (leaf to
			// root), then walk through the chain in that order and write any matching
			// certificate. writeIntermediateCAsToBuffer returns an error if no such
			// certificate could be found and the content tag makes it mandatory.
			err := writeIntermediateCAsToBuffer(buf, chain, true, mandatory)
			if err != nil {
				return err
			}
		} else if cv == CTClientCert {
			// If the content tag is for the client-facing certificate, write it into
			// the buffer if it exists.
			if chain.FurthestLeaf.Type == CertTypeClientCert {
				err := writeToBufferAsPEM(
					buf, chain.FurthestLeaf.Bytes(), PEMBlockTypeCertificate,
				)
				if err != nil {
					return err
				}
			} else if mandatory {
				// If the client-facing certificate does not exist, return an error.
				return ErrMissingClientCert
			}
		} else if cv == CTPrivateKey {
			// If the content tag is for the private key matching the client-facing
			// certificate, write it into the buffer if it exists.
			if pkey != nil {
				// Encode the key, then write it into the buffer.
				b := x509.MarshalPKCS1PrivateKey(pkey)
				err := writeToBufferAsPEM(buf, b, PEMBlockTypeRSAKey)
				if err != nil {
					return err
				}
			} else if mandatory {
				// If no such key could be found, return an error.
				return ErrMissingPrivateKey
			}
		}
	}

	// Write the content of each output file.
	filePath := path.Join(outDir, file.Name)
	if err := os.WriteFile(filePath, buf.Bytes(), 0600); err != nil {
		return err
	}

	return nil
}

// writeIntermediateCAsToBuffer walks through the certificate chain in the given order.
// When it finds an intermediate CA certificate, it writes it into the buffer.
// Returns ErrMissingIntermediateCA if it could not find any intermediate CA certificate,
// and `mandatory` is set to true.
func writeIntermediateCAsToBuffer(
	buf *bytes.Buffer,
	chain *CertChain,
	reverse bool,
	mandatory bool,
) error {
	// Set the starting point.
	cert := chain.Root
	if reverse {
		cert = chain.FurthestLeaf
	}

	// Iterate through every certificate in the chain.
	found := false
	for cert != nil {
		// If the certificate is an intermediate CA, record we've found at least one such
		// certificate, and write it to the buffer.
		if cert.Type == CertTypeIntermediateCA {
			found = true

			err := writeToBufferAsPEM(buf, cert.Bytes(), PEMBlockTypeCertificate)
			if err != nil {
				return err
			}
		}

		// Continue to the next certificate in the chain.
		if reverse {
			cert = cert.Parent
		} else {
			cert = cert.Leaf
		}
	}

	// If no intermediate CA certificate was found, and finding at least one is mandatory,
	// return an error.
	if !found && mandatory {
		return ErrMissingIntermediateCA
	}

	return nil
}

// writeToBufferAsPEM wraps the given DER bytes into a PEM block, which is then encoded
// into the buffer.
func writeToBufferAsPEM(buf *bytes.Buffer, b []byte, blockType string) error {
	block := &pem.Block{
		Type:    blockType,
		Headers: make(map[string]string),
		Bytes:   b,
	}
	return pem.Encode(buf, block)
}
