// Command assessment validates assessment-spec documents and evidence, checks
// evidence freshness, and prints a system's view, control resolution and
// framework coverage for an audience.
package main

import "os"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
