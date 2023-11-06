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
	"testing"
)

var filePaths = []string{
	"test_data/concat/ca.pem",
	"test_data/concat/cert.pem",
	"test_data/concat/key.pem",
}

// Note that these test are not testing the actual sorting algorithm, but rather the
// the error or invalid input outcome, which is basically garbage in, garbage out.
// Makes sure it does not panic or return unexpected results.

func TestCertificateSort(t *testing.T) {
	rawKeys, err := readFiles(filePaths)
	if err != nil {
		t.Fatalf("Error in readFiles: %s", err)
	}

	certs := NewRawCerts(string(rawKeys[0]))
	certs = certs.Append(string(rawKeys[1]))
	certs = certs.Append(string(rawKeys[2]))

	sortedCerts, key, err := SortCertificates(certs, true)
	if err != nil {
		t.Fatalf("Error in SortCertificates: %s", err)
	}
	if len(sortedCerts) != 6013 {
		t.Fatalf("Expected chain length to be 3, got: %d", len(sortedCerts))
	}
	if key == nil {
		t.Fatal("Key was expected to be non-nil")
	}
}

func TestInvalidCaOnly(t *testing.T) {
	certs := NewRawCerts("invalid ca")

	sortedCerts, key, err := SortCertificates(certs, true)
	if err != nil {
		t.Fatalf("Expected no error, got: %s", err)
	}
	if len(sortedCerts) != 0 {
		t.Fatalf("Expected chain length to be 0, got: %d", len(sortedCerts))
	}
	if key != nil {
		t.Fatal("Key was expected to be nil")
	}
}

func TestCertificatesWithInvalidCert(t *testing.T) {
	rawKeys, err := readFiles(filePaths)
	if err != nil {
		t.Fatalf("Error in readFiles: %s", err)
	}
	certs := NewRawCerts(string(rawKeys[0]))
	certs = certs.Append("invald cert")
	certs = certs.Append(string(rawKeys[2]))

	sortedCerts, key, err := SortCertificates(certs, true)
	if err != nil {
		t.Fatalf("Expected no error, got: %s", err)
	}
	if len(sortedCerts) != 4817 {
		t.Fatalf("Expected chain length to be 4817, got: %d", len(sortedCerts))
	}
	if key != nil {
		t.Fatal("Key was expected to be nil")
	}
}

func TestCertificatesWithInvalidCa(t *testing.T) {
	rawKeys, err := readFiles(filePaths)
	if err != nil {
		t.Fatalf("Error in readFiles: %s", err)
	}
	certs := NewRawCerts("invalid ca")
	certs = certs.Append(string(rawKeys[1]))
	certs = certs.Append(string(rawKeys[2]))

	sortedCerts, key, err := SortCertificates(certs, true)
	if err != nil {
		t.Fatalf("Expected no error, got: %s", err)
	}
	if len(sortedCerts) != 1196 {
		t.Fatalf("Expected chain length to be 1196, got: %d", len(sortedCerts))
	}
	if key == nil {
		t.Fatal("Key was expected to be non-nil")
	}
}

func TestCertificatesWithInvalidKey(t *testing.T) {
	rawKeys, err := readFiles(filePaths)
	if err != nil {
		t.Fatalf("Error in readFiles: %s", err)
	}
	certs := NewRawCerts(string(rawKeys[0]))
	certs = certs.Append(string(rawKeys[1]))
	certs = certs.Append("invalid key")

	sortedCerts, key, err := SortCertificates(certs, true)
	if err != nil {
		t.Fatalf("Expected no error, got: %s", err)
	}
	if len(sortedCerts) != 6013 {
		t.Fatalf("Expected chain length to be 6013, got: %d", len(sortedCerts))
	}
	if key != nil {
		t.Fatal("key was expected to be nil")
	}
}
