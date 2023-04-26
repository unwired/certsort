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

package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/unwired/certsort"
)

// CLI tool wrapping SortCertificateFiles
func main() {
	// Define command line flags
	configFlag := flag.String("config", "", "Configuration string")
	inputDirFlag := flag.String("input", "", "Input directory")
	outputDirFlag := flag.String("output", "", "Output directory")
	flag.Parse()

	// Check that all required flags are provided
	if *configFlag == "" || *inputDirFlag == "" || *outputDirFlag == "" {
		fmt.Println("Usage: mycli -config <config string> -input <input directory> -output <output directory>")
		os.Exit(1)
	}

	// Read the configuration string
	config := *configFlag

	// make absolute path from here
	inputDir, err := filepath.Abs(*inputDirFlag)
	if err != nil {
		panic(err)
	}

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

	outputDir := *outputDirFlag
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		err := os.MkdirAll(outputDir, 0755)
		if err != nil {
			fmt.Println("Error creating output directory:", err)
			os.Exit(1)
		}
	}

	if err = certsort.SortCertificateFiles(config, filePaths, outputDir); err != nil {
		panic(err)
	}
}
