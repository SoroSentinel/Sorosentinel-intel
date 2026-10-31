// Command gen-alerts rewrites the Cloud Monitoring artifacts Intel applies for
// its own operation: the log-based metrics and the alerting policies generated
// from the alert table in internal/monitoring (intel #54).
//
// It writes files, it does not touch a cloud account. Applying them is an
// operator action and is written up in docs/runbooks/oncall-alerts.md. A test
// (internal/monitoring/alerts_test.go) fails when the committed files and the
// table disagree, so the artifacts cannot drift away from the code.
//
// Usage: go run ./cmd/gen-alerts [-dir deploy/monitoring] [-check] [-split DIR]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/monitoring"
)

func main() {
	dir := flag.String("dir", filepath.Join("deploy", "monitoring"), "directory to write the artifacts to")
	check := flag.Bool("check", false, "compare the committed files with the table instead of writing")
	split := flag.String("split", "", "also write one log-metric config file per metric into this directory")
	flag.Parse()

	logMetrics, err := monitoring.RenderLogMetrics()
	if err != nil {
		fail(err)
	}
	policies, err := monitoring.RenderAlertPolicies()
	if err != nil {
		fail(err)
	}
	files := map[string][]byte{
		"log-metrics.json":    logMetrics,
		"alert-policies.json": policies,
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	// Deterministic order, so -check output does not depend on the map.
	slices.Sort(names)
	if *check {
		for _, name := range names {
			before, err := os.ReadFile(filepath.Join(*dir, name))
			if err != nil {
				fail(err)
			}
			if string(before) != string(files[name]) {
				fmt.Fprintf(os.Stderr, "gen-alerts: %s is stale; run `make gen-alerts`\n", name)
				os.Exit(1)
			}
		}
		return
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		fail(err)
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(*dir, name), files[name], 0o644); err != nil {
			fail(err)
		}
		fmt.Fprintf(os.Stderr, "gen-alerts: wrote %s\n", filepath.Join(*dir, name))
	}
	if *split == "" {
		return
	}
	// `gcloud logging metrics create` takes one metric per call, so the apply
	// step wants one config file per metric rather than the array.
	if err := os.MkdirAll(*split, 0o755); err != nil {
		fail(err)
	}
	for _, m := range monitoring.LogMetrics() {
		body, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			fail(err)
		}
		path := filepath.Join(*split, m.Name+".json")
		if err := os.WriteFile(path, append(body, '\n'), 0o644); err != nil {
			fail(err)
		}
		fmt.Fprintf(os.Stderr, "gen-alerts: wrote %s\n", path)
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "gen-alerts:", err)
	os.Exit(1)
}
