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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const (
	// PEMBlockTypeCertificate represents the PEM block type for certificates.
	PEMBlockTypeCertificate = "CERTIFICATE"
	// PEMBlockTypeRSAKeyPKCS1 represents the PEM block type for RSA keys in PKCS#1 format.
	PEMBlockTypeRSAKeyPKCS1 = "RSA PRIVATE KEY"
	// PEMBlockTypeKeyPKCS8 represents the PEM block type for keys in PKCS#8 format.
	PEMBlockTypeKeyPKCS8 = "PRIVATE KEY"
	// PEMBlockTypeECDSAKey represents the PEM block type for ECDSA keys.
	PEMBlockTypeECDSAKey = "EC PRIVATE KEY"
)

var (
	// ErrInterruptedChain is returned if the chain of certificates is interrupted, for
	// example if an intermediate CA's certificate is missing.
	ErrInterruptedChain = fmt.Errorf("interrupted certificate chain detected")
)

// GetChainAndKeyFromPEMFiles reads a list of files and returns the certificate chain as well as the
// private key for the furthest leaf of the certificate chain.
// If no private key could be found for the client-facing certificate, or if no
// client-facing certificate exists in the chain, returns a nil key.
// Returns ErrParallelChains if more than one certificate chain is included in the files.
// Returns ErrInterruptedChain if the chain is incomplete.
func GetChainAndKeyFromPEMFiles(
	paths []string,
) (chain *CertChain, clientKey crypto.PrivateKey, err error) {
	rawKeys, err := readFiles(paths)
	if err != nil {
		return
	}
	return GetChainAndKeyFromRawPEM(rawKeys)
}

// GetChainAndKeyFromRawPEM reads raw PEM strings, which may contain a
// number of certificates and keys and returns the certificate chain as well as the
// private key for the furthest leaf of the certificate chain.)
// If no private key could be found for the client-facing certificate, or if no
// client-facing certificate exists in the chain, returns a nil key.
// Returns ErrParallelChains if more than one certificate chain is included in the files.
// Returns ErrInterruptedChain if the chain is incomplete.
func GetChainAndKeyFromRawPEM(
	rawKeys [][]byte,
) (chain *CertChain, clientKey crypto.PrivateKey, err error) {
	// The chain of certificates in the files.
	chain = NewCertChain()
	// A list of all the keys found in the files, to use to compare against the
	// client-facing certificate.
	keys := make([]crypto.PrivateKey, 0)

	// Iterate over the PEM blocks in that file.
	for _, rawKey := range rawKeys {
		b := rawKey
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
			} else if block.Type == PEMBlockTypeRSAKeyPKCS1 {
				// If the block is an RSA key, parse it.
				var key crypto.PrivateKey
				key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					return
				}

				keys = append(keys, key)
			} else if block.Type == PEMBlockTypeKeyPKCS8 {
				var untypedKey any
				untypedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					return
				}

				keys = append(keys, untypedKey)
			} else if block.Type == PEMBlockTypeECDSAKey {
				var key crypto.PrivateKey
				key, err = x509.ParseECPrivateKey(block.Bytes)
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

// privateKey is a private key that can be used to call Equal and Public. As crypto.PrivateKey does not define Equal and Public for backwards compatibility.
type privateKey interface {
	Equal(other crypto.PrivateKey) bool
	Public() crypto.PublicKey
}

// publicKey is a public key that can be used to call Equal. As crypto.PublicKey does not define Equal for backwards compatibility.
type publicKey interface {
	Equal(other crypto.PublicKey) bool
}

// FindKeyForCertificate checks each of the provided private keys against the given
// certificate. If the public key for a given private key matches with the certificate's
// public key, it returns it, otherwise it returns nil.
func FindKeyForCertificate(c *Certificate, knownKeys []crypto.PrivateKey) crypto.PrivateKey {
	// Do some type assertions to get the right types to call Equal and Public on
	// Because crypto.PrivateKey and crypto.PublicKey do not define Equal and Public for backwards compatibility.
	// Although they state that Equal and Public will be available on all types.
	// So we can panic if the type assertion fails.
	pubKey := c.PublicKey().(publicKey)
	for _, knownKey := range knownKeys {
		knownPubKey := knownKey.(privateKey).Public().(publicKey)
		if knownPubKey.Equal(pubKey) {
			return knownKey
		}
	}

	return nil
}
