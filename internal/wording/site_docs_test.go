package wording

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// docsSite is the GitHub Pages tree published from this repo (docs/site). It is
// public prose, so it has the same teeth as the registry lint: blocked terms come
// from wordlint -docs, and this test enforces the two structural things that make
// a page render at all and not dead-end.
const docsSite = "../../docs/site"

var markdownLink = regexp.MustCompile(`\]\(([^)\s]+)\)`)

func TestDocsSitePagesRenderAndResolve(t *testing.T) {
	var pages []string
	err := filepath.WalkDir(docsSite, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".md" {
			pages = append(pages, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v (the docs site must exist for this test to mean anything)", docsSite, err)
	}
	if len(pages) == 0 {
		t.Fatalf("%s holds no markdown pages", docsSite)
	}

	for _, page := range pages {
		raw, err := os.ReadFile(page)
		if err != nil {
			t.Fatalf("%s: %v", page, err)
		}
		text := string(raw)

		// Jekyll only turns a file into a page when it opens with a frontmatter
		// block; without one the .md is copied verbatim and served as plain text,
		// so every link to it 404s on the published site.
		if !strings.HasPrefix(text, "---\n") {
			t.Errorf("%s: no frontmatter block, so Jekyll will not render it", page)
		} else {
			fm, _, found := strings.Cut(text[4:], "\n---\n")
			if !found {
				t.Errorf("%s: frontmatter block is never closed", page)
			} else if !strings.Contains(fm, "title:") {
				t.Errorf("%s: frontmatter has no title, so the page has an empty accessible name", page)
			}
		}

		for _, m := range markdownLink.FindAllStringSubmatch(text, -1) {
			target := m[1]
			if strings.HasPrefix(target, "#") || strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			if _, scoped, ok := strings.Cut(target, ":"); ok && !strings.Contains(scoped, "/") {
				t.Errorf("%s: link target %q looks like a scheme-less external URL", page, target)
				continue
			}
			rel := strings.TrimSuffix(strings.TrimSuffix(target, ".html"), ".md")
			rel = strings.TrimSuffix(strings.TrimSuffix(rel, "/index"), "/")
			dir := filepath.Dir(page)
			candidates := []string{
				filepath.Join(dir, rel+".md"),
				filepath.Join(dir, rel+".html"),
				filepath.Join(dir, rel),
			}
			if !anyExists(candidates) {
				t.Errorf("%s: link target %q resolves to no file in the tree", page, target)
			}
		}
	}
}

func anyExists(paths []string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}
