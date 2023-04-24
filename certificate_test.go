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
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

// Test that a full chain consisting of a root CA + an intermediate CA + a client
// certificate is recorded correctly.
func TestCertificateFullChainInOrder(t *testing.T) {
	chain := NewCertChain()

	chainPaths := []string{
		"test_data/full_chain/ca.pem",
		"test_data/full_chain/intermediate.pem",
		"test_data/full_chain/cert.pem",
	}

	// Read the certificate Bytes from the files.
	certs := testReadCertsFromFiles(t, chainPaths)

	// Populate the chain and check that it did not produce any unexpected orphan.
	for _, path := range chainPaths {
		// Set the label as a separate variable so its address is separate for every
		// iteration.
		label := path
		// Add the certificate to the chain.
		if err := chain.AddFromBytes(certs[path], &label); err != nil {
			t.Fatalf("Failed to add cert to chain: %s", err.Error())
		}

		// Test that the chain was correctly initialised from the first certificate.
		if chain.Root == nil || chain.FurthestLeaf == nil {
			t.Fatal("Chain did not initialise correctly")
		}

		// Test that adding the certificate did not create any orphan.
		if chain.CountOrphans() != 0 {
			t.Fatal("Unexpected orphan(s) in chain")
		}
	}

	// Walk through the chain and check that all certificates are recorded in order.
	cert := chain.Root
	for _, label := range chainPaths {
		if *cert.label != label {
			t.Fatalf("Unexpected certificate\nExpected: %s\nGot: %s", label, *cert.label)
		}
		cert = cert.Leaf
	}
}

// Test that a full chain consisting of a root CA + an intermediate CA + a client
// certificate provided in the wrong order is recorded correctly and can be reordered
// correctly.
func TestCertificateFullChainOutOfOrder(t *testing.T) {
	chain := NewCertChain()

	rootPath := "test_data/full_chain/ca.pem"
	intermediatePath := "test_data/full_chain/intermediate.pem"
	clientPath := "test_data/full_chain/cert.pem"

	chainPaths := []string{rootPath, intermediatePath, clientPath}

	// Read the certificate bytes from the files.
	certs := testReadCertsFromFiles(t, chainPaths)

	// First add the root certificate, check that the chain was initialised correctly.
	if err := chain.AddFromBytes(certs[rootPath], &rootPath); err != nil {
		t.Fatalf("Failed to add cert to chain: %s", err.Error())
	}

	if chain.Root == nil || chain.FurthestLeaf == nil {
		t.Fatal("Chain did not initialise correctly")
	}

	// Now add the client certificate. Because we haven't recorded the intermediate
	// certificate, it should be recorded as an orphan.
	if err := chain.AddFromBytes(certs[clientPath], &clientPath); err != nil {
		t.Fatalf("Failed to add cert to chain: %s", err.Error())
	}

	if chain.CountOrphans() != 1 {
		t.Fatalf("Expected exactly one orphan, got %d", len(chain.Orphans))
	}

	// Now add the intermediate certificate, which should be correctly fitted within the
	// main chain.
	if err := chain.AddFromBytes(certs[intermediatePath], &intermediatePath); err != nil {
		t.Fatalf("Failed to add cert to chain: %s", err.Error())
	}

	if chain.Len() != 2 {
		t.Fatalf("Expected chain length to be 2, got %d", chain.Len())
	}

	// Make sure we've still got one orphan.
	if chain.CountOrphans() != 1 {
		t.Fatalf("Expected exactly one orphan, got %d", chain.CountOrphans())
	}

	// Attempt to remove any orphan.
	if err := chain.Cleanup(); err != nil {
		t.Fatalf("Failed to Cleanup the chain: %s", err.Error())
	}

	if chain.CountOrphans() != 0 {
		t.Fatalf("Expected no orphan, got %d", chain.CountOrphans())
	}

	// Walk through the chain and check that all certificates are recorded in order.
	cert := chain.Root
	for _, label := range chainPaths {
		if *cert.label != label {
			t.Fatalf("Unexpected certificate\nExpected: %s\nGot: %s", label, *cert.label)
		}
		cert = cert.Leaf
	}
}

// Test that a full chain consisting of a root CA + an intermediate CA + a client
// certificate provided in the wrong order is recorded correctly and can be reordered
// correctly, specifically with the root first.
func TestCertificateFullChainOutOfOrderIntermediateFirst(t *testing.T) {
	chain := NewCertChain()

	rootPath := "test_data/full_chain/ca.pem"
	intermediatePath := "test_data/full_chain/intermediate.pem"
	clientPath := "test_data/full_chain/cert.pem"

	chainPaths := []string{rootPath, intermediatePath, clientPath}

	// Read the certificate bytes from the files.
	certs := testReadCertsFromFiles(t, chainPaths)

	// First add the intermediate certificate, check that the chain was initialised
	// correctly.
	if err := chain.AddFromBytes(certs[intermediatePath], &intermediatePath); err != nil {
		t.Fatalf("Failed to add cert to chain: %s", err.Error())
	}

	if chain.Root == nil || chain.FurthestLeaf == nil {
		t.Fatal("Chain did not initialise correctly")
	}

	// Now add the client certificate, which should be fitted within the chain.
	if err := chain.AddFromBytes(certs[clientPath], &clientPath); err != nil {
		t.Fatalf("Failed to add cert to chain: %s", err.Error())
	}

	if chain.CountOrphans() != 0 {
		t.Fatalf("Expected no orphan, got %d", len(chain.Orphans))
	}

	// Now add the root certificate, which should be correctly fitted within the
	// main chain (before the intermediate certificate).
	if err := chain.AddFromBytes(certs[rootPath], &rootPath); err != nil {
		t.Fatalf("Failed to add cert to chain: %s", err.Error())
	}

	if chain.CountOrphans() != 0 {
		t.Fatalf("Expected no orphan, got %d", len(chain.Orphans))
	}

	// Walk through the chain and check that all certificates are recorded in order.
	cert := chain.Root
	for _, label := range chainPaths {
		if *cert.label != label {
			t.Fatalf("Unexpected certificate\nExpected: %s\nGot: %s", label, *cert.label)
		}
		cert = cert.Leaf
	}
}

// Test that parallel chains are correctly identified and raise an error.
func TestCertificateMultipleChains(t *testing.T) {
	chain := NewCertChain()

	rootPath := "test_data/multiple_chains/ca.pem"
	intermediatePath1 := "test_data/multiple_chains/intermediate-ca1.pem"
	intermediatePath2 := "test_data/multiple_chains/intermediate-ca2.pem"

	chainPaths := []string{rootPath, intermediatePath1, intermediatePath2}

	// Read the certificate bytes from the files.
	certs := testReadCertsFromFiles(t, chainPaths)

	// First add the root certificate.
	if err := chain.AddFromBytes(certs[rootPath], &rootPath); err != nil {
		t.Fatalf("Failed to add cert to chain: %s", err.Error())
	}

	// Now add a first intermediate certificate.
	if err := chain.AddFromBytes(certs[intermediatePath1], &intermediatePath1); err != nil {
		t.Fatalf("Failed to add cert to chain: %s", err.Error())
	}

	// Now add the second intermediate certificate, which should produce an error.
	if err := chain.AddFromBytes(certs[intermediatePath2], &intermediatePath2); err != ErrParallelChains {
		t.Fatalf("Expected multiple chains error, got: %v", err)
	}
}

// Test that duplicates of already recorded certificates are correctly ignored.
func TestCertificateDuplicateCertificates(t *testing.T) {
	chain := NewCertChain()

	chainPaths := []string{
		"test_data/duplicate_certs/ca.pem",
		"test_data/duplicate_certs/ca_copy.pem",
		"test_data/duplicate_certs/intermediate.pem",
		"test_data/duplicate_certs/intermediate_copy.pem",
	}

	// Read the certificate bytes from the files.
	certs := testReadCertsFromFiles(t, chainPaths)

	// Populate the chain and check that it did not produce any unexpected orphan or
	// return an unexpected error.
	for _, label := range chainPaths {
		if err := chain.AddFromBytes(certs[label], &label); err != nil {
			t.Fatalf("Failed to add cert to chain: %s", err.Error())
		}

		if chain.Root == nil || chain.FurthestLeaf == nil {
			t.Fatal("Chain did not initialise correctly")
		}

		if chain.CountOrphans() != 0 {
			t.Fatal("Unexpected orphan(s) in chain")
		}
	}

	// Check that the chain is 2 certificates long, not 4, since the input data contains
	// 2 duplicates.
	if chain.Len() != 2 {
		t.Fatalf("Expected the chain length to be 2, got %d", chain.Len())
	}
}

// Tests that certificate.IsSignedBy correctly detects when a certificate is signed by
// another and does not return a false positive when it's not.
func TestCertificateIsSignedBy(t *testing.T) {
	chainPaths := []string{
		"test_data/full_chain/ca.pem",
		"test_data/full_chain/intermediate.pem",
	}

	// Read the certificate bytes from the files.
	certs := testReadCertsFromFiles(t, chainPaths)

	// Parse the certificates.
	rootCert := testParseCertificate(t, certs[chainPaths[0]])
	intermediateCert := testParseCertificate(t, certs[chainPaths[1]])

	// Test that the intermediate certificate is signed by the root certificate.
	if !intermediateCert.IsSignedBy(rootCert) {
		t.Fatal("Expected intermediate to be signed by root")
	}
	// Test that the root certificate is not signed by the intermediate certificate.
	if rootCert.IsSignedBy(intermediateCert) {
		t.Fatal("Expected root to not be signed by intermediate")
	}
}

// Tests that certificate.SetLeaf correctly sets the leaf and parent of certificates.
func TestCertificateSetLeaf(t *testing.T) {
	chainPaths := []string{
		"test_data/full_chain/ca.pem",
		"test_data/full_chain/intermediate.pem",
	}

	// Read the certificate bytes from the files.
	certs := testReadCertsFromFiles(t, chainPaths)

	// Parse the certificates.
	rootCert := testParseCertificate(t, certs[chainPaths[0]])
	intermediateCert := testParseCertificate(t, certs[chainPaths[1]])

	// Set the intermediate as leaf of root.
	if err := rootCert.SetLeaf(intermediateCert); err != nil {
		t.Fatal(err)
	}

	// Test that the intermediate certificate is a leaf of the root certificate.
	if rootCert.Leaf != intermediateCert {
		t.Fatalf("Expected intermediate to be leaf of root, got: %p", rootCert.Leaf)
	}
	// Test that the root certificate is a parent of the intermediate certificate.
	if intermediateCert.Parent != rootCert {
		t.Fatalf(
			"Expected root to be parent of intermediate, got: %p",
			intermediateCert.Parent,
		)
	}

	// Set the intermediate as leaf of root again. Since root already has a leaf, and we
	// don't do the deduplication work here, SetLeaf should return an error about parallel
	// chains.
	if err := rootCert.SetLeaf(intermediateCert); err != ErrParallelChains {
		t.Fatal(err)
	}
}

// Tests that certificate.cacheKey() generates a unique key for a certificate, which is common
// to copies of this certificate as well.
func TestCertificateCacheKey(t *testing.T) {
	chainPaths := []string{
		"test_data/duplicate_certs/ca.pem",
		"test_data/duplicate_certs/ca_copy.pem",
		"test_data/duplicate_certs/intermediate.pem",
	}

	// Read the certificate bytes from the files.
	certs := testReadCertsFromFiles(t, chainPaths)

	// Parse the certificates.
	rootCert := testParseCertificate(t, certs[chainPaths[0]])
	rootCopyCert := testParseCertificate(t, certs[chainPaths[1]])
	intermediateCert := testParseCertificate(t, certs[chainPaths[2]])

	// Test that the cacheKey for the root certificate does not equal the cacheKey for the
	// intermediate certificate.
	if rootCert.cacheKey() == intermediateCert.cacheKey() {
		t.Fatalf(
			"Did not expect %v to equal %v",
			rootCert.cacheKey(),
			intermediateCert.cacheKey(),
		)
	}

	// Test that the keys for the root certificate and its copy are the same.
	if rootCert.cacheKey() != rootCopyCert.cacheKey() {
		t.Fatalf(
			"Expected %v to equal %v",
			rootCert.cacheKey(),
			rootCopyCert.cacheKey(),
		)
	}
}

// Tests that NewCertificate correctly returns an error if the algorithm for the
// certificate's public key is not RSA.
func TestCertificateNonRSA(t *testing.T) {
	// Read the certificate.
	x509Cert := testParseX509CertFromFile(t, "test_data/ecdsa/cert.pem")

	// Test that NewCertificate correctly returns an error.
	_, err := NewCertificate(x509Cert, nil)
	if err != ErrCertificatePKeyAlgoNotRSA {
		t.Fatalf("Expected error on non-RSA algo, got: %v", err)
	}
}

// Tests that NewCertificate associates the correct type to a certificate.
func TestCertificateTypeAssignment(t *testing.T) {
	testParseCertAndCheckType(t, "test_data/full_chain/ca.pem", CertTypeRootCA)
	testParseCertAndCheckType(t, "test_data/full_chain/intermediate.pem", CertTypeIntermediateCA)
	testParseCertAndCheckType(t, "test_data/full_chain/cert.pem", CertTypeClientCert)
}

// testReadCertsFromFiles reads the PEM files at the given paths and returns a map
// associating a path to the DER bytes for this file.
// This test function works with two constraints:
//  1. Only one PEM block per file
//  2. All PEM blocks are certificates
func testReadCertsFromFiles(t *testing.T, paths []string) map[string][]byte {
	certs := make(map[string][]byte)

	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		certs[path] = testGetCertBytesFromPEM(t, b, path)
	}

	return certs
}

// testGetCertBytesFromPEM parses the given Bytes as a PEM block, then checks that it
// describes a certificate and returns its bytes.
func testGetCertBytesFromPEM(t *testing.T, pemBytes []byte, path string) []byte {
	block, rest := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("empty PEM file: %s", path)
	}
	if len(rest) != 0 {
		t.Fatalf("more than one certificate in file: %s", path)
	}

	if block.Type != PEMBlockTypeCertificate {
		t.Fatalf("PEM content is not a certificate: %s", path)
	}

	return block.Bytes
}

// testParseX509CertFromFile parse the content of the file at a given path into an X509
// certificate.
func testParseX509CertFromFile(t *testing.T, path string) *x509.Certificate {
	certs := testReadCertsFromFiles(t, []string{path})

	// Parse the bytes as an X509 certificate.
	x509Cert, err := x509.ParseCertificate(certs[path])
	if err != nil {
		t.Fatal(err)
	}

	return x509Cert
}

// testParseCertificate parses the given bytes as an instance of the certificate struct,
// and fail the test if they could not be parsed into an X509 certificate.
func testParseCertificate(t *testing.T, b []byte) *Certificate {
	parsedCert, err := x509.ParseCertificate(b)
	if err != nil {
		t.Fatal(err)
	}
	return &Certificate{C: parsedCert}
}

// testParseCertAndCheckType parses the certificate at a given path, and checks that
// its inferred type is correct.
func testParseCertAndCheckType(t *testing.T, certPath string, expectedType certType) {
	// Read the certificate.
	cert, err := NewCertificate(
		testParseX509CertFromFile(t, certPath),
		nil,
	)
	if err != nil {
		t.Fatalf("Error when instantiating certificate %s: %v", certPath, err)
	}

	// Compare its type to the associated one.
	if cert.Type != expectedType {
		t.Fatalf(
			"Unexpected certficate type\nExpected: %v\nGot: %v",
			expectedType,
			cert.Type,
		)
	}
}
