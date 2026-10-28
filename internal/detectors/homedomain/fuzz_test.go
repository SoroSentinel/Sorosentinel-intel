package homedomain

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseCurrencies checks that the reader never panics or hangs on hostile
// input. Run with: go test -fuzz=FuzzParseCurrencies ./internal/detectors/homedomain
func FuzzParseCurrencies(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join(testdata, "*.toml"))
	for _, name := range files {
		if b, err := os.ReadFile(name); err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxTOMLBytes {
			return
		}
		_, _ = parseCurrencies(b)
	})
}
