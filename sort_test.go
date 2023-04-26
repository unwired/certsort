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
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path"
	"strings"
	"testing"
)

// Tests that writeIntermediateCAsToBuffer correctly writes intermediate CA certificates
// to the buffer.
func TestWriteIntermediateToBuffer(t *testing.T) {
	buf := new(bytes.Buffer)
	files := []string{
		"test_data/algorithms/rsa/ca.pem",
		"test_data/algorithms/rsa/intermediate.pem",
		"test_data/algorithms/rsa/cert.pem",
	}

	// Populate a chain from the files.
	chain, _, err := GetChainAndKeyFromPEMFiles(files)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the certificate after the root key is the intermediate one.
	intermediate := chain.Root.Leaf
	if intermediate.Type != CertTypeIntermediateCA {
		t.Fatalf(
			"Did not find intermediate CA certificate at expected location (got type %v)",
			intermediate.Type,
		)
	}

	// Write the intermediate CA to the buffer.
	if err = writeIntermediateCAsToBuffer(buf, chain, false, false); err != nil {
		t.Fatal(err)
	}

	// Retrieve the first (and only) certificate in the buffer, and test that it's the
	// correct one.
	b := testGetCertBytesFromPEM(t, buf.Bytes(), ":memory:")
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		t.Fatal(err)
	}

	if !cert.Equal(intermediate.C) {
		t.Fatal("Certificate different than expected")
	}
}

// Tests that writeIntermediateCAsToBuffer does not write anything to the buffer if there
// is no intermediate CA certificate.
func TestWriteIntermediateToBufferMissing(t *testing.T) {
	buf := new(bytes.Buffer)
	files := []string{
		"test_data/algorithms/rsa/cert.pem",
	}

	// Populate a chain from the file.
	chain, _, err := GetChainAndKeyFromPEMFiles(files)
	if err != nil {
		t.Fatal(err)
	}

	// Write any intermediate CA cert to the buffer (which should not write anything since
	// there isn't any).
	if err = writeIntermediateCAsToBuffer(buf, chain, false, false); err != nil {
		t.Fatal(err)
	}

	// Check that the buffer is empty.
	if buf.Len() != 0 {
		t.Fatalf("Unexpected Bytes in buffer: %s", buf.String())
	}
}

// Tests that writeIntermediateCAsToBuffer raises an error if there is no intermediate CA
// certificate and the mandatory flag is set to true.
func TestWriteIntermediateToBufferMissingMandatory(t *testing.T) {
	buf := new(bytes.Buffer)
	files := []string{
		"test_data/algorithms/rsa/cert.pem",
	}

	// Populate a chain from the file.
	chain, _, err := GetChainAndKeyFromPEMFiles(files)
	if err != nil {
		t.Fatal(err)
	}

	// Check that writeIntermediateCAsToBuffer returns the expected error when setting
	// `mandatory` to `true`.
	if err = writeIntermediateCAsToBuffer(
		buf, chain, false, true,
	); err != ErrMissingIntermediateCA {
		t.Fatalf("Expected error: %v\nGot: %v", ErrMissingIntermediateCA, err)
	}
}

// Tests that writeToBufferAsPEM correctly encodes the given bytes into a PEM block of the
// correct type.
func TestWriteToBufferAsPEM(t *testing.T) {
	buf := new(bytes.Buffer)
	blocType := "foo"
	blockBytes := []byte("bar")

	// Write the bytes to the buffer.
	if err := writeToBufferAsPEM(buf, blockBytes, blocType); err != nil {
		t.Fatal(err)
	}

	// Decode the buffered bytes as a PEM block.
	block, rest := pem.Decode(buf.Bytes())

	// The buffer should only contain the block.
	if len(rest) != 0 {
		t.Fatal("Unexpected remaining bytes after end of block")
	}

	// A nil block means no PEM-encoded data could be found in the bytes.
	if block == nil {
		t.Fatal("Unexpected nil block")
	}

	// Check the block's type.
	if block.Type != blocType {
		t.Fatalf(
			"Unexpected PEM block type.\nExpected: %s\nGot: %s",
			blocType,
			block.Type,
		)
	}

	// Check the block's bytes.
	if !bytes.Equal(block.Bytes, blockBytes) {
		t.Fatalf(
			"Unexpected PEM block type.\nExpected: %v\nGot: %v",
			blocType,
			block.Type,
		)
	}
}

// Tests that writeFile correctly isolates the root CA certificate and writes it into the
// given file.
func TestWriteFileRootCA(t *testing.T) {
	fileName := "root.pem"

	// The output file may contain a root CA certificate if one exists.
	cfg := &OutputFileConfig{
		Name: fileName,
		ContentValues: map[ContentTag]bool{
			CTRootCA: false,
		},
	}

	// Build the certificate chain.
	files := []string{
		"test_data/algorithms/rsa/ca.pem",
		"test_data/algorithms/rsa/intermediate.pem",
		"test_data/algorithms/rsa/cert.pem",
	}

	chain, key, err := GetChainAndKeyFromPEMFiles(files)
	if err != nil {
		t.Fatal(err)
	}

	buf, err := writeToBufferSorted(cfg, chain, key)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the written file matches the expected result.
	testAssertCertFromBufferEqual(t, buf, chain.Root)
}

// Tests that writeFile correctly returns an error when writing a root CA certificate is
// mandatory but no such certificate exists.
func TestWriteFileRootCAMissingMandatory(t *testing.T) {
	fileName := "root.pem"

	// The output file must contain a root CA certificate.
	cfg := &OutputFileConfig{
		Name: fileName,
		ContentValues: map[ContentTag]bool{
			CTRootCA: true,
		},
	}

	// Build the chain.
	files := []string{
		"test_data/algorithms/rsa/intermediate.pem",
		"test_data/algorithms/rsa/cert.pem",
	}

	chain, key, err := GetChainAndKeyFromPEMFiles(files)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = writeToBufferSorted(cfg, chain, key); err != ErrMissingRootCA {
		t.Fatalf("Expected error: %v\nGot: %v", ErrMissingRootCA, err)
	}
}

// Tests that writeFile correctly isolates the intermediate CA certificate and writes it
// into the given file.
func TestWriteFileIntermediateCA(t *testing.T) {
	fileName := "intermediate.pem"

	// The output file may contain intermediate CA certificates if any exists.
	cfg := &OutputFileConfig{
		Name: fileName,
		ContentValues: map[ContentTag]bool{
			CTIntermediatesCARootToLeaf: false,
		},
	}

	// Build the chain.
	files := []string{
		"test_data/algorithms/rsa/ca.pem",
		"test_data/algorithms/rsa/intermediate.pem",
		"test_data/algorithms/rsa/cert.pem",
	}

	chain, key, err := GetChainAndKeyFromPEMFiles(files)
	if err != nil {
		t.Fatal(err)
	}

	buf, err := writeToBufferSorted(cfg, chain, key)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the written file matches the expected result.
	intermediate := chain.Root.Leaf
	testAssertCertFromBufferEqual(t, buf, intermediate)
}

// Tests that writeFile correctly returns an error when writing an intermediate CA
// certificate is mandatory but no such certificate exists.
func TestWriteFileIntermediateCAMissingMandatory(t *testing.T) {
	fileName := "intermediate.pem"

	// The output file must contain at least one intermediate CA certificate.
	cfg := &OutputFileConfig{
		Name: fileName,
		ContentValues: map[ContentTag]bool{
			CTIntermediatesCARootToLeaf: true,
		},
	}

	// We can't include the client-facing certificate (or the root CA certificate if we
	// chose to include the client-facing certificate) since otherwise
	// GetChainAndKeyFromPEMFiles will detect an interruption in the chain and error.
	files := []string{
		"test_data/algorithms/rsa/ca.pem",
	}

	chain, key, err := GetChainAndKeyFromPEMFiles(files)
	if err != nil {
		t.Fatal(err)
	}

	// Attempt to write the file, and check that an error is returned.
	if _, err := writeToBufferSorted(cfg, chain, key); err != ErrMissingIntermediateCA {
		t.Fatalf("Expected error: %v\nGot: %v", ErrMissingIntermediateCA, err)
	}
}

// Tests that writeFile correctly isolates the client-facing certificate and writes it
// into the given file.
func TestWriteFileClientCert(t *testing.T) {
	fileName := "cert.pem"

	// The output file may contain a client-facing certificate if one exists.
	cfg := &OutputFileConfig{
		Name: fileName,
		ContentValues: map[ContentTag]bool{
			CTClientCert: false,
		},
	}

	// Build the chain.
	files := []string{
		"test_data/algorithms/rsa/ca.pem",
		"test_data/algorithms/rsa/intermediate.pem",
		"test_data/algorithms/rsa/cert.pem",
	}

	chain, key, err := GetChainAndKeyFromPEMFiles(files)
	if err != nil {
		t.Fatal(err)
	}

	buf, err := writeToBufferSorted(cfg, chain, key)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the written file matches the expected result.
	testAssertCertFromBufferEqual(t, buf, chain.FurthestLeaf)
}

// Tests that writeFile correctly returns an error when writing a client-facing
// certificate is mandatory but no such certificate exists.
func TestWriteFileClientCertMissingMandatory(t *testing.T) {
	fileName := "cert.pem"

	// The output file must contain a client-facing certificate.
	cfg := &OutputFileConfig{
		Name: fileName,
		ContentValues: map[ContentTag]bool{
			CTClientCert: true,
		},
	}

	// Build the chain.
	files := []string{
		"test_data/algorithms/rsa/ca.pem",
		"test_data/algorithms/rsa/intermediate.pem",
	}

	chain, key, err := GetChainAndKeyFromPEMFiles(files)
	if err != nil {
		t.Fatal(err)
	}

	// Attempt to write the file, and check that an error is returned.

	if _, err = writeToBufferSorted(cfg, chain, key); err != ErrMissingClientCert {
		t.Fatalf("Expected error: %v\nGot: %v", ErrMissingClientCert, err)
	}
}

// Tests that writeFile correctly isolates the key for the client-facing certificate and
// writes it into the given file.
func TestWriteFileClientKey(t *testing.T) {
	fileName := "key.pem"

	// The output file may contain the key for the client-facing certificate if it exists.
	cfg := &OutputFileConfig{
		Name: fileName,
		ContentValues: map[ContentTag]bool{
			CTPrivateKey: false,
		},
	}

	// Build the chain, and identify the key.
	files := []string{
		"test_data/algorithms/rsa/ca.pem",
		"test_data/algorithms/rsa/intermediate.pem",
		"test_data/algorithms/rsa/cert.pem",
		"test_data/algorithms/rsa/key.pem",
	}

	chain, key, err := GetChainAndKeyFromPEMFiles(files)
	if err != nil {
		t.Fatal(err)
	}

	buf, err := writeToBufferSorted(cfg, chain, key)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the written file matches the expected result.
	testAssertKeyFromBufferEqual(t, buf, key)
}

// Tests that writeFile correctly returns an error when writing a key for the client-facing
// certificate is mandatory but no such key exists.
func TestWriteFileClientKeyMissingMandatory(t *testing.T) {
	fileName := "key.pem"

	// The output file must contain the key for the client-facing certificate.
	cfg := &OutputFileConfig{
		Name: fileName,
		ContentValues: map[ContentTag]bool{
			CTPrivateKey: true,
		},
	}

	// Build the chain.
	files := []string{
		"test_data/algorithms/rsa/ca.pem",
		"test_data/algorithms/rsa/intermediate.pem",
		"test_data/algorithms/rsa/cert.pem",
	}

	chain, key, err := GetChainAndKeyFromPEMFiles(files)
	if err != nil {
		t.Fatal(err)
	}

	// Attempt to write the file, and check that an error is returned.

	if _, err = writeToBufferSorted(cfg, chain, key); err != ErrMissingPrivateKey {
		t.Fatalf("Expected error: %v\nGot: %v", ErrMissingPrivateKey, err)
	}
}

// Tests that SortCertificates correctly sorts certificates accordingly with the provided
// input string.
// Tests different supported algorithms.
func TestSortCertificates(t *testing.T) {
	// Define the configuration string and files.
	config := "root.pem:ca_root!;intermediate.pem:ca_intermediates_root_to_leaf!;cert.pem:cert!;key.pem:private_key!"

	var algorithms = []struct {
		name string
	}{
		{"ecdh"},
		{"ecdsa"},
		{"ed25519"},
		{"rsa"},
		{"rsa-pkcs8"},
	}

	for _, algo := range algorithms {
		t.Run("Key_"+algo.name, func(t *testing.T) {
			files := []string{
				"test_data/algorithms/" + algo.name + "/ca.pem",
				"test_data/algorithms/" + algo.name + "/intermediate.pem",
				"test_data/algorithms/" + algo.name + "/cert.pem",
				"test_data/algorithms/" + algo.name + "/key.pem",
			}

			// Set up the output directory.
			outputDir := t.TempDir()

			// Sort the files.
			if err := SortCertificateFiles(config, files, outputDir); err != nil {
				t.Fatal(err)
			}

			// Separately load the certificates and key from the input files.
			chain, key, err := GetChainAndKeyFromPEMFiles(files)
			if err != nil {
				t.Fatal(err)
			}

			root := chain.Root
			intermediate := chain.Root.Leaf
			cert := chain.FurthestLeaf

			// Check that the output files match the expected results.
			testAssertCertFromFileEqual(t, path.Join(outputDir, "root.pem"), root)
			testAssertCertFromFileEqual(t, path.Join(outputDir, "intermediate.pem"), intermediate)
			testAssertCertFromFileEqual(t, path.Join(outputDir, "cert.pem"), cert)
			testAssertKeyFromFileEqual(t, path.Join(outputDir, "key.pem"), key)
		})
	}
}

// Tests that SortCertificates correctly sorts certificates accordingly with the provided
// input string and checks if the order within a file is always correct.
// This ensures that the sorting is deterministic.
func TestSortCertificatesOrder(t *testing.T) {
	// Define the configuration string and files.
	config := "ca.pem:ca_root!,ca_intermediates_root_to_leaf!;cert.pem:cert!;key.pem:private_key!"
	files := []string{
		"test_data/algorithms/rsa/ca.pem",
		"test_data/algorithms/rsa/intermediate.pem",
		"test_data/algorithms/rsa/cert.pem",
		"test_data/algorithms/rsa/key.pem",
	}

	tries := 10
	matches := 0
	for i := 0; i < tries; i++ {
		// Set up the output directory.
		outputDir := t.TempDir()

		// Sort the files.
		if err := SortCertificateFiles(config, files, outputDir); err != nil {
			t.Fatal(err)
		}

		b, err := os.ReadFile(path.Join(outputDir, "ca.pem"))
		if err != nil {
			t.Fatal(err)
		}

		expectedFirstLine := "MIIDSTCCAjGgAwIBAgIBBzANBgkqhkiG9w0BAQsFADA6MQswCQYDVQQGEwJBVDEZ"

		// checks if the order is correct
		lines := strings.Split(string(b), "\n")
		if lines[1] == expectedFirstLine {
			matches++
		} else {
			t.Errorf("first line should be %v, but was %v", expectedFirstLine, lines[1])
		}
	}
	if tries != matches {
		t.Errorf("ordering is wrong in %v of %v tries", tries-matches, tries)
	}
}

// testAssertCertFromFileEqual checks that the certificate that is PEM-encoded at the
// given path corresponds to the expected certificate.
func testAssertCertFromFileEqual(t *testing.T, path string, expected *Certificate) {
	cert := testParseX509CertFromFile(t, path)

	if !cert.Equal(expected.C) {
		t.Fatalf("Certificate in file %s did not match the expected certificate", path)
	}
}

// testAssertCertFromBufferEqual checks that the certificate that is PEM-encoded in the
// given buffer corresponds to the expected certificate.
func testAssertCertFromBufferEqual(t *testing.T, buf *bytes.Buffer, expected *Certificate) {
	block, _ := pem.Decode(buf.Bytes())

	// Parse the bytes as an X509 certificate.
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if !x509Cert.Equal(expected.C) {
		t.Fatalf("Certificate in buffer did not match the expected certificate")
	}
}

// testAssertKeyFromFileEqual checks that the private key that is PEM-encoded at the given
// path corresponds to the expected private key.
func testAssertKeyFromFileEqual(t *testing.T, path string, expected crypto.PrivateKey) {
	// Read the file bytes.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	testAssertKeyFromBufferEqual(t, bytes.NewBuffer(b), expected)
}

type keyType interface {
	Equal(crypto.PrivateKey) bool
}

func testAssertKeyFromBufferEqual(t *testing.T, buf *bytes.Buffer, expected crypto.PrivateKey) {
	// Decode the PEM block.
	block, rest := pem.Decode(buf.Bytes())
	if block == nil {
		t.Fatalf("Empty PEM file: %s", buf.String())
	}
	if len(rest) != 0 {
		t.Fatalf("More than one PEM block in file: %s", buf.String())
	}

	var privateKey keyType

	if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		privateKey = key.(keyType)
	}
	if block.Type == "EC PRIVATE KEY" {
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		privateKey = keyType(key)
	}
	if block.Type == "RSA PRIVATE KEY" {
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		privateKey = keyType(key)
	}
	if privateKey == nil {
		t.Fatalf("Unknown private key type: %s", block.Type)
	}

	// Compare the decoded key with the expected result.
	if !privateKey.Equal(expected) {
		t.Fatalf("Key in file %s did not match the expected certificate", buf.String())
	}
}
