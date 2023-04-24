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
	"os"
	"testing"
)

// Tests that if given a full chain of certificate and a key matching the client-facing
// certificate's, GetChainAndKeyFromPEMFiles returns a chain representing the certificates
// in the correct order, as well as said key.
func TestPEMReadFiles(t *testing.T) {
	filePaths := []string{
		"test_data/full_chain/ca.pem",
		"test_data/full_chain/intermediate.pem",
		"test_data/full_chain/cert.pem",
		"test_data/full_chain/key.pem",
	}

	// Read and parse the files.
	chain, key, err := GetChainAndKeyFromPEMFiles(filePaths)
	if err != nil {
		t.Fatal(err)
	}

	// Check the chain length.
	if chain.Len() != 3 {
		t.Fatalf("Expected chain length to be 3, got: %d", chain.Len())
	}

	// Test that we got a key for the client-facing certificate.
	if key == nil {
		t.Fatal("Unexpected nil key")
	}
}

// Tests that GetChainAndKeyFromPEMFiles returns an error if the chain is interrupted.
func TestPEMInterrupted(t *testing.T) {
	filePaths := []string{
		"test_data/full_chain/ca.pem",
		"test_data/full_chain/cert.pem",
	}

	// Read and parse the files.
	_, _, err := GetChainAndKeyFromPEMFiles(filePaths)
	// Check that the hole in the chain is correctly identified.
	if err != ErrInterruptedChain {
		t.Fatalf(
			"Unexpected error.\nExpected: %v\nGot: %v", ErrInterruptedChain, err,
		)
	}
}

// Tests that GetChainAndKeyFromPEMFiles returns an error if multiple parallel certificate
// chains are detected.
func TestPEMMultipleChains(t *testing.T) {
	filePaths := []string{
		"test_data/multiple_chains/ca.pem",
		"test_data/multiple_chains/intermediate-ca1.pem",
		"test_data/multiple_chains/intermediate-ca2.pem",
	}

	// Read and parse the files.
	_, _, err := GetChainAndKeyFromPEMFiles(filePaths)
	// Check that the parallel chain is correctly identified.
	if err != ErrParallelChains {
		t.Fatalf(
			"Unexpected error.\nExpected: %v\nGot: %v", ErrParallelChains, err,
		)
	}
}

// Tests that GetChainAndKeyFromPEMFiles does not return a key if it does not match the
// public key for the client-facing certificate.
func TestPEMMismatchingKey(t *testing.T) {
	filePaths := []string{
		"test_data/full_chain/cert.pem",
		"test_data/multiple_chains/key-ca2.pem",
	}

	// Read and parse the files.
	_, key, err := GetChainAndKeyFromPEMFiles(filePaths)
	if err != nil {
		t.Fatal(err)
	}

	// Test that no key was identified.
	if key != nil {
		t.Fatal("Unexpected key")
	}
}

// Tests that FindKeyForCertificate identifies the correct key matching a certificate's
// public key among several keys.
func TestPEMFindKeyForCert(t *testing.T) {
	// Read the certificate's bytes.
	certPath := "test_data/full_chain/cert.pem"
	certs := testReadCertsFromFiles(t, []string{certPath})

	// Parse the bytes as an X509 certificate.
	x509Cert, err := x509.ParseCertificate(certs[certPath])
	if err != nil {
		t.Fatal(err)
	}
	// Instantiate a new certificate instance from the X509 certificate.
	cert, err := NewCertificate(x509Cert, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Read private keys.
	keys := make([]*rsa.PrivateKey, 0)
	keyPaths := []string{
		"test_data/multiple_chains/key-ca2.pem",
		"test_data/full_chain/key.pem",
	}
	for _, path := range keyPaths {
		// Read bytes from the key's file.
		bytes, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		// Decode the PEM block.
		bloc, rest := pem.Decode(bytes)
		// Check that the PEM block was correctly parsed, that it's the only block in the
		// file, and that it's got the correct type.
		if bloc == nil {
			t.Fatal("No PEM-encoded content in test key")
		}
		if len(rest) != 0 {
			t.Fatal("More than one PEM block in file")
		}
		if bloc.Type != PEMBlockTypeRSAKey {
			t.Fatalf("Expected PEM block to be RSA PRIVATE KEY, got: %s", bloc.Type)
		}

		// Parse the key from the block's bytes.
		k, err := x509.ParsePKCS1PrivateKey(bloc.Bytes)
		if err != nil {
			t.Fatal(err)
		}

		keys = append(keys, k)
	}

	// Test that we matched the correct key.
	matchingKey := FindKeyForCertificate(cert, keys)
	if matchingKey != keys[1] {
		t.Fatalf(
			"Identified key is not the expected one.\nExpected: %p\nGot: %p",
			keys[2],
			matchingKey,
		)
	}
}
