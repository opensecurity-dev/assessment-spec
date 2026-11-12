// Command gen writes the generated schemas from the Go types.
package main

import (
	"log"
	"os"

	"github.com/opensecurity-dev/assessment-spec/schema"
)

func main() {
	b, err := schema.GenerateEvidenceManifest()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(schema.EvidenceManifestFile, b, 0o644); err != nil { //nolint:gosec // a schema file is meant to be world-readable
		log.Fatal(err)
	}
}
