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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

const (
	// PEMBlockTypeCertificate represents the PEM block type for certificates.
	PEMBlockTypeCertificate = "CERTIFICATE"
	// PEMBlockTypeRSAKey represents the PEM block type for RSA keys.
	PEMBlockTypeRSAKey = "RSA PRIVATE KEY"
)

var (
	// ErrInterruptedChain is returned if the chain of certificates is interrupted, for
	// example if an intermediate CA's certificate is missing.
	ErrInterruptedChain = fmt.Errorf("interrupted certificate chain detected")
)

// GetChainAndKeyFromPEMFiles reads the PEM files at the given path, which may contain a
// number of certificates and keys and returns the certificate chain as well as the
// private key for the furthest leaf of the certificate chain.
// If no private key could be found for the client-facing certificate, or if no
// client-facing certificate exists in the chain, returns a nil key.
// Returns ErrParallelChains if more than one certificate chain is included in the files.
// Returns ErrInterruptedChain if the chain is incomplete.
func GetChainAndKeyFromPEMFiles(
	paths []string,
) (chain *CertChain, clientKey *rsa.PrivateKey, err error) {
	// The chain of certificates in the files.
	chain = NewCertChain()
	// A list of all the keys found in the files, to use to compare against the
	// client-facing certificate.
	keys := make([]*rsa.PrivateKey, 0)

	// Iterate over the files.
	for _, path := range paths {
		// Read the file's bytes.
		var b []byte
		b, err = os.ReadFile(path)
		if err != nil {
			return
		}

		// Iterate over the PEM blocks in that file.
		for len(b) != 0 {
			block, rest := pem.Decode(b)
			if block == nil {
				// If `block` is nil, then no PEM data could be found in the remaining
				// bytes.
				break
			}

			if block.Type == PEMBlockTypeCertificate {
				// If the block is a certificate, parse it and add it to the chain.
				if err = chain.AddFromBytes(block.Bytes, nil); err != nil {
					return
				}
			} else if block.Type == PEMBlockTypeRSAKey {
				// If the block is an RSA key, parse it.
				var key *rsa.PrivateKey
				key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					return
				}

				keys = append(keys, key)
			}

			// Load the rest of the file into `b` for the next iteration.
			b = rest
		}
	}

	// Try to eliminate any remaining orphan in the chain.
	if err = chain.Cleanup(); err != nil {
		return
	}

	// Check if there is any orphan remaining; if so then the chain is interrupted, which
	// should result in an error.
	if chain.CountOrphans() != 0 {
		err = ErrInterruptedChain
		return
	}

	// If there is a client-facing certificate, try to find its key.
	if chain.FurthestLeaf.Type == CertTypeClientCert {
		clientKey = FindKeyForCertificate(chain.FurthestLeaf, keys)
	}
	return
}

// FindKeyForCertificate checks each of the provided private keys against the given
// certificate. If the public key for a given private key matches with the certificate's
// public key, it returns it, otherwise it returns nil.
func FindKeyForCertificate(c *Certificate, knownKeys []*rsa.PrivateKey) *rsa.PrivateKey {
	for _, key := range knownKeys {
		if c.PublicKey().Equal(key.Public()) {
			return key
		}
	}

	return nil
}
