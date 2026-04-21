// Reverse hash lookup.
//
// Usage:
//
//	rhash hashsum
//
// The arguments are:
//
//	sum
//	    Hash sum to find all possible sources for (required).
package main

import (
	"fmt"
	"os"
	"strings"

	"go.foxforensics.dev/rhash/database"
)

func main() {
	if len(os.Args) == 1 || os.Args[1] == "--help" {
		_, _ = fmt.Fprintln(os.Stderr, "usage: rhash sum")
		os.Exit(2)
	}

	s := strings.ToLower(os.Args[1])

	for v := range database.Lookup(s) {
		_, _ = fmt.Println(v)
	}
}
