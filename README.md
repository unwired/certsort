# Certificate sorting

This library can read X509 certificates and RSA private keys contained in a list of files,
order them, and sort them into output files specified by a configuration string.

## Documentation

Install the `godoc` tool if this hasn't already been done:

```shell
go install golang.org/x/tools/cmd/godoc
```

Run a local `godoc` server:

```shell
godoc
```

Then point your browser to http://127.0.0.1:6060/pkg/certsort

## Example

Please refer to the documentation for the signatures of methods, variables, constants and
types exposed by this library, as well as for the syntax of the configuration string
showed in this example.

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
	
	config := "cachain.pem:ca_root,ca_intermediates_root_to_leaf!;cert.pem:cert!;private.pem:private_key!"
	
	if err = certsort.SortCertificates(config, filePaths, outputDir); err != nil {
		panic(err)
    }
}
```