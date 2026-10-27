// Command wordlint checks the wording registry: blocklisted terms, placeholder
// and slot discipline, attribution requirements, and file/id consistency.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/wording"
)

func main() {
	dir := flag.String("dir", "wording", "path to the wording registry")
	flag.Parse()

	reg, err := wording.Load(os.DirFS(*dir))
	if err != nil {
		fmt.Fprintln(os.Stderr, "wordlint:", err)
		os.Exit(1)
	}
	problems := reg.Lint()
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "wordlint:", p)
	}
	if len(problems) > 0 {
		os.Exit(1)
	}
	fmt.Println("wordlint: ok")
}
