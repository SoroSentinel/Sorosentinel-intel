// Command wordlint checks the wording registry: blocklisted terms, placeholder
// and slot discipline, attribution requirements, and file/id consistency.
// With -docs it also checks public Markdown pages (e.g. docs/methodology) for
// blocked terms.
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/wording"
)

func main() {
	dir := flag.String("dir", "wording", "path to the wording registry")
	docs := flag.String("docs", "", "comma-separated directories of public Markdown pages to check")
	flag.Parse()

	reg, err := wording.Load(os.DirFS(*dir))
	if err != nil {
		fmt.Fprintln(os.Stderr, "wordlint:", err)
		os.Exit(1)
	}
	problems := reg.Lint()
	if *docs != "" {
		for _, d := range strings.Split(*docs, ",") {
			p, err := lintDocs(reg, d)
			if err != nil {
				fmt.Fprintln(os.Stderr, "wordlint:", err)
				os.Exit(1)
			}
			problems = append(problems, p...)
		}
	}
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "wordlint:", p)
	}
	if len(problems) > 0 {
		os.Exit(1)
	}
	fmt.Println("wordlint: ok")
}

func lintDocs(reg *wording.Registry, dir string) ([]wording.Problem, error) {
	var out []wording.Problem
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".md" {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out = append(out, reg.LintDocument(path, string(b))...)
		return nil
	})
	return out, err
}
