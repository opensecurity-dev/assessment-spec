// Command gen writes the generated schemas from the Go types.
package main

import (
	"log"
	"os"

	"github.com/opensecurity-dev/assessment-spec/schema"
)

func main() {
	for file, gen := range schema.All {
		b, err := gen()
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(file, b, 0o644); err != nil { //nolint:gosec // a schema file is meant to be world-readable
			log.Fatal(err)
		}
	}
}
