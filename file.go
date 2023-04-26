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
	"os"
	"path"
)

func readFiles(paths []string) (rawKeys [][]byte, err error) {
	// Iterate over the files.
	for _, path := range paths {
		// Read the file's bytes.
		var b []byte
		b, err = os.ReadFile(path)
		if err != nil {
			return
		}

		if len(b) == 0 {
			return
		}
		rawKeys = append(rawKeys, b)
	}
	return
}

func writeFiles(outDir string, fileKeyBuffers map[string]*bytes.Buffer) error {
	// Write the contents of the output files.
	for name, fileContentBuffer := range fileKeyBuffers {

		// Write the content of each output file.
		filePath := path.Join(outDir, name)
		if err := os.WriteFile(filePath, fileContentBuffer.Bytes(), 0600); err != nil {
			return err
		}
	}
	return nil
}
