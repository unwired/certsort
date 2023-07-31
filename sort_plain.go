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
	"bytes"
	"crypto/x509"
	"fmt"
)

// SortCertificates reads the provided PEM-encoded strings, containing either X509
// certificates, or RSA private keys. It then sorts them according to the given sort direction.
// Returns the sorted certificates and the private key for the furthest leaf of the certificate chain.
// If no private key could be found for the client-facing certificate, or if no
// client-facing certificate exists in the chain, returns a nil key.
func SortCertificates(certs rawCerts, rootToLeaf bool) (sortedCerts string, privateKey *string, err error) {
	// Read the certificates and keys from files.
	chain, pKey, err := GetChainAndKeyFromRawPEM(certs.ByteArray())
	if err != nil {
		return "", nil, fmt.Errorf("failed to get chain and key from raw pem: %w", err)
	}

	if pKey != nil {
		buf := bytes.NewBuffer(nil)
		// No matter what the original key type was, we'll encode it as PKCS#8 for now.
		blockType := PEMBlockTypeKeyPKCS8
		bytes, err := x509.MarshalPKCS8PrivateKey(pKey)
		if err != nil {
			return "", nil, fmt.Errorf("failed to marshal pkcs8 private key: %w", err)
		}

		err = writeToBufferAsPEM(buf, bytes, blockType)
		if err != nil {
			return "", nil, fmt.Errorf("failed to write private key to buffer: %w", err)
		}
		keyString := buf.String()
		privateKey = &keyString
	}

	if rootToLeaf {
		sortedCerts, err = flattenFromRootToLeaf(chain)
	} else {
		sortedCerts, err = flattenFromLeafToRoot(chain)
	}
	if err != nil {
		return "", nil, fmt.Errorf("failed to flatten chain: %w", err)
	}
	return
}
