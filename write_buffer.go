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

package certsort

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// writeToBufferSortedWithFileConfig writes the configured content into a given output file.
// Returns ErrMissingRootCA, ErrMissingIntermediateCA, ErrMissingClientCert or
// ErrMissingPrivateKey if one of the content tags mandated specific certificate(s) or
// key to be included in the output file, but no such certificate or key could be found.
// All key algorithms will be rewritten as PKCS#8 PEM blocks.
func writeToBufferSortedWithFileConfig(
	file *OutputFileConfig,
	chain *CertChain,
	pkey crypto.PrivateKey,
) (*bytes.Buffer, error) {
	// Buffer containing the file's content.
	buf := &bytes.Buffer{}

	// Iterate over the configured content tags for this file.
	for i := 0; i < ctLength; i++ {
		cv := ContentTag(i)
		mandatory, ok := file.ContentValues[cv]
		if !ok {
			continue
		}
		if cv == CTRootCA {
			// If the content tag is for the root CA certificate, write it into the
			// buffer if it exists.
			if chain.Root.Type == CertTypeRootCA {
				err := writeToBufferAsPEM(
					buf, chain.Root.Bytes(), PEMBlockTypeCertificate,
				)
				if err != nil {
					return nil, err
				}
			} else if mandatory {
				// If the root CA certificate does not exist, return an error.
				return nil, ErrMissingRootCA
			}
		} else if cv == CTIntermediatesCARootToLeaf {
			// If the content tag is for intermediate CA in the "normal" order (root to
			// leaf), then walk through the chain in that order and write any matching
			// certificate. writeIntermediateCAsToBuffer returns an error if no such
			// certificate could be found and the content tag makes it mandatory.
			err := writeIntermediateCAsToBuffer(buf, chain, false, mandatory)
			if err != nil {
				return nil, err
			}
		} else if cv == CTIntermediatesCALeafToRoot {
			// If the content tag is for intermediate CA in the "reverse" order (leaf to
			// root), then walk through the chain in that order and write any matching
			// certificate. writeIntermediateCAsToBuffer returns an error if no such
			// certificate could be found and the content tag makes it mandatory.
			err := writeIntermediateCAsToBuffer(buf, chain, true, mandatory)
			if err != nil {
				return nil, err
			}
		} else if cv == CTClientCert {
			// If the content tag is for the client-facing certificate, write it into
			// the buffer if it exists.
			if chain.FurthestLeaf.Type == CertTypeClientCert {
				err := writeToBufferAsPEM(
					buf, chain.FurthestLeaf.Bytes(), PEMBlockTypeCertificate,
				)
				if err != nil {
					return nil, err
				}
			} else if mandatory {
				// If the client-facing certificate does not exist, return an error.
				return nil, ErrMissingClientCert
			}
		} else if cv == CTPrivateKey {
			// If the content tag is for the private key matching the client-facing
			// certificate, write it into the buffer if it exists.
			var bytes []byte
			var blockType string
			var err error
			if pkey != nil {
				// No matter what the original key type was, we'll encode it as PKCS#8 for now.
				blockType = PEMBlockTypeKeyPKCS8
				bytes, err = x509.MarshalPKCS8PrivateKey(pkey)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal pkcs8 private key: %w", err)
				}

				err = writeToBufferAsPEM(buf, bytes, blockType)
				if err != nil {
					return nil, err
				}
			} else if mandatory {
				// If no such key could be found, return an error.
				return nil, ErrMissingPrivateKey
			}
		}
	}

	return buf, nil
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

func flattenFromRootToLeaf(chain *CertChain) (string, error) {
	buf := bytes.NewBuffer(nil)
	current := chain.Root
	for current != nil {
		writeCertToBuffer(current, buf)
		current = current.Leaf
	}
	return buf.String(), nil
}

func flattenFromLeafToRoot(chain *CertChain) (string, error) {
	buf := bytes.NewBuffer(nil)
	current := chain.FurthestLeaf
	for current != nil {
		current = current.Parent
		writeCertToBuffer(current, buf)
	}

	return buf.String(), nil
}

// writeCertToBuffer writes the certificate to the buffer.
// this is the simplified version of writeToBufferSortedWithFileConfig.
// without any configuration, it will write all certificates to the buffer.
func writeCertToBuffer(current *Certificate, buf *bytes.Buffer) error {
	if current.Type == CertTypeRootCA {
		err := writeToBufferAsPEM(
			buf, current.Bytes(), PEMBlockTypeCertificate,
		)
		if err != nil {
			return fmt.Errorf("failed to write root ca to buffer: %w", err)
		}
	}
	if current.Type == CertTypeIntermediateCA {
		err := writeToBufferAsPEM(buf, current.Bytes(), PEMBlockTypeCertificate)
		if err != nil {
			return fmt.Errorf("failed to write intermediate ca to buffer: %w", err)
		}
	}
	if current.Type == CertTypeClientCert {
		err := writeToBufferAsPEM(buf, current.Bytes(), PEMBlockTypeCertificate)
		if err != nil {
			return fmt.Errorf("failed to write client cert to buffer: %w", err)
		}
	}
	return nil
}
