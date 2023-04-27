[![Go Report Card](https://goreportcard.com/badge/github.com/unwired/certsort)](https://goreportcard.com/report/github.com/unwired/certsort)
[![GitHub issues](https://img.shields.io/github/issues/unwired/certsort.svg)](https://github.com/unwired/certsort/issues)
[![Documentation](https://godoc.org/github.com/unwired/certsort?status.svg)](https://godoc.org/github.com/unwired/certsort)
[![license](https://img.shields.io/github/license/unwired/certsort.svg)](https://github.com/unwired/certsort/blob/main/LICENSE)

# Certificate sorting

This library can read X509 certificates and private keys contained in a list of files,
order them, and sort them into output files specified by a configuration string.

## Usage

### Sorting certificates and private keys

The `SortCertificateFiles` method takes a configuration string, an input directory,
and an output directory. It reads the certificates and private keys from the files,
orders them, and sorts them into the output directory.

The `SortCertificates` method takes a configuration string, a list of certificates and
private keys as byte arrays. It orders the certificates and private keys, and sorts them
into output buffers. The output buffers are returned as a map, where the keys are the
content tags specified in the configuration string.

### Configuration string

The configuration string is a semicolon-separated list of files, where each file is
described by a colon-separated list of two elements: the name of the file, and the
content tags for the file.

The content tags are a comma-separated list of tags, where each tag is a string
describing the content of the file. The tags are processed in the order they are
specified in the configuration string.

The following content tags are supported:

- ca_root: the root CA certificate
- ca_intermediates_root_to_leaf: intermediate CA certificates, ordered from root to leaf
- ca_intermediates_leaf_to_root: intermediate CA certificates, ordered from leaf to root
- cert: the client-facing certificate
- private_key: the private key for the client-facing certificate

If a content tag ends with an exclamation mark (!), then it's mandatory.
If a mandatory content tag is not found in the certificate chain, then an error is
returned.

## Examples

Please refer to the documentation for the signatures of methods, variables, constants and
types exposed by this library, as well as for the syntax of the configuration string
showed in this example.

### Example code usage

```go
package main

import (
	"os"
	"path"
	"strings"

	"certsort"
)

func main() {
	inputDir := "in"
	outputDir := "out"

	files, err := os.ReadDir(inputDir)
	if err != nil {
		panic(err)
	}


	filePaths := make([]string, 0)
	for _, file := range files {
		// Only process PEM-encoded files.
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".pem") {
			filePaths = append(filePaths, path.Join(inputDir, file.Name()))
		}
	}

  // The configuration string specifies the following:
  // - The root CA certificate is in the file "cachain.pem"
  // - The intermediate CA certificates are in the file "cachain.pem"
  // - The client-facing certificate is in the file "cert.pem"
  // - The private key for the client-facing certificate is in the file "private.pem"
  // - The root CA certificate is mandatory
  // - The intermediate CA certificates are mandatory
  // - The client-facing certificate is mandatory
  // - The private key for the client-facing certificate is mandatory
	config := "cachain.pem:ca_root,ca_intermediates_root_to_leaf!;cert.pem:cert!;private.pem:private_key!"

  // Sort the certificates and private keys into the output directory.
  if err = certsort.SortCertificateFiles(config, filePaths, outputDir); err != nil {
    panic(err)
  }
}
```

### Example CLI usage

```shell
go build cmd/main.go -o  certsort
./certsort -config "cachain.pem:ca_root,ca_intermediates_root_to_leaf!;cert.pem:cert!;private.pem:private_key!" -input test_data/concat -output test_output
```

## Contributing

### Running tests

```shell
go test ./...
```

### Building

```shell
go build cmd/main.go -o certsort
```

### Generating documentation

Install the `godoc` tool if this hasn't already been done:

```shell
go install golang.org/x/tools/cmd/godoc
```

Run a local `godoc` server:

```shell
godoc
```

Then point your browser to http://127.0.0.1:6060/pkg/certsort
