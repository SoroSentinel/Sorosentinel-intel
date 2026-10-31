package monitoring_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/monitoring"
)

// alertSite is the source pattern that links a rule to the line that feeds it: a
// call site names its constant inside monitoring.AlertFields rather than passing
// a variable, so this file can check both directions of the contract.
var alertSite = regexp.MustCompile(`monitoring\.AlertFields\(monitoring\.([A-Za-z0-9_]+)\)`)

// constNames maps each emitted alert id to the Go constant an alert site uses.
// A rule and its site are only linked if both are named here, which is the point:
// adding an alert without wiring a log line, or a log line without a rule, fails.
var constNames = map[string]string{
	monitoring.IngestHalt:         "IngestHalt",
	monitoring.WriterLockLost:     "WriterLockLost",
	monitoring.SnapshotSignFailed: "SnapshotSignFailed",
	monitoring.SnapshotFailed:     "SnapshotFailed",
	monitoring.SnapshotRejected:   "SnapshotRejected",
	monitoring.ApiPanic:           "ApiPanic",
	monitoring.ApiStopped:         "ApiStopped",
}

// haltKindNames maps each halt cause a rule can select on to its ingest constant.
var haltKindNames = map[string]string{
	ingest.HaltGap:                 "HaltGap",
	ingest.HaltInconsistent:        "HaltInconsistent",
	ingest.HaltWrongNetwork:        "HaltWrongNetwork",
	ingest.HaltWriterActive:        "HaltWriterActive",
	ingest.HaltNoStart:             "HaltNoStart",
	ingest.HaltUnknownXDR:          "HaltUnknownXDR",
	ingest.HaltUnsupportedProtocol: "HaltUnsupportedProtocol",
	ingest.HaltInvalidData:         "HaltInvalidData",
	ingest.HaltRetriesExhausted:    "HaltRetriesExhausted",
}

var runbookPath = monitoring.RunbookPath

func TestAlertTableIsWellFormed(t *testing.T) {
	seenID := map[string]bool{}
	seenMetric := map[string]bool{}
	coarseCount := 0
	for _, a := range monitoring.Alerts {
		if a.Coarse {
			coarseCount++
			if a.MinEvents < 1 {
				t.Errorf("%s: the coarse rule needs at least one event per window", a.ID)
			}
			if a.Emits != "" || a.MinStatus != 0 || len(a.HaltKinds) > 0 || a.Absent || a.Msg != "" {
				t.Errorf("%s: the coarse rule keys on the alert flag and nothing else", a.ID)
			}
			continue
		}
		if a.Msg == "" {
			t.Errorf("%s: every other rule names the log line it was written against", a.ID)
		}
		if !regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,40}$`).MatchString(a.ID) {
			t.Errorf("%s: id must be upper snake case", a.ID)
		}
		if seenID[a.ID] {
			t.Errorf("%s: duplicate alert id", a.ID)
		}
		seenID[a.ID] = true
		if !regexp.MustCompile(`^intel_[a-z0-9_]{3,60}$`).MatchString(a.Metric) {
			t.Errorf("%s: metric %q must be intel_<snake>", a.ID, a.Metric)
		}
		if seenMetric[a.Metric] {
			t.Errorf("%s: metric %q is already used by another alert", a.ID, a.Metric)
		}
		seenMetric[a.Metric] = true
		if a.Severity != monitoring.Page && a.Severity != monitoring.Ticket {
			t.Errorf("%s: severity %q is neither page nor ticket", a.ID, a.Severity)
		}
		d, err := time.ParseDuration(a.Window)
		if err != nil || d <= 0 {
			t.Errorf("%s: window %q is not a positive duration", a.ID, a.Window)
		}
		if a.Title == "" || a.Summary == "" || a.Action == "" || a.Component == "" {
			t.Errorf("%s: title, summary, action and component are all required", a.ID)
		}
		for _, k := range a.HaltKinds {
			if _, ok := haltKindNames[k]; !ok {
				t.Errorf("%s: halt_kind %q is not an ingest.Halt* constant", a.ID, k)
			}
		}
		if a.Absent {
			if a.Emits != "" || a.MinStatus != 0 || len(a.HaltKinds) > 0 {
				t.Errorf("%s: an absence rule keys on a log line only", a.ID)
			}
			if a.MinEvents != 0 {
				t.Errorf("%s: an absence rule has no event count to compare; min_events would be ignored", a.ID)
			}
			continue
		}
		if a.Ratio {
			if a.Percent <= 0 || a.Percent > 100 || a.MinRequest < 1 {
				t.Errorf("%s: a ratio rule needs a percent and a minimum volume", a.ID)
			}
			if a.MinEvents != 0 {
				t.Errorf("%s: a ratio rule breaches on its percent, so min_events would be ignored", a.ID)
			}
			if a.Datapoints < 2 {
				t.Errorf("%s: one window of a rate is noise; a ratio rule needs two datapoints", a.ID)
			}
		} else if a.MinEvents < 1 {
			t.Errorf("%s: a threshold rule must count at least one event per window", a.ID)
		}
		if !a.Ratio && a.MinRequest != 0 {
			t.Errorf("%s: min_requests is only meaningful for a ratio rule", a.ID)
		}
	}
	if coarseCount != 1 {
		t.Errorf("got %d coarse rules; exactly one net over unlisted ids is the design", coarseCount)
	}
	if len(monitoring.Alerts) < 10 {
		t.Errorf("the taxonomy lost alerts: %d", len(monitoring.Alerts))
	}
}

// TestEveryAlertHasARunbookSection covers "a runbook per alert" (intel #54 AC 2)
// as a build requirement rather than a review habit.
func TestEveryAlertHasARunbookSection(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", runbookPath))
	if err != nil {
		t.Fatalf("read runbook: %v", err)
	}
	text := string(body)
	for _, a := range monitoring.Alerts {
		anchor := `<a id="` + a.RunbookAnchor() + `"></a>`
		at := strings.Index(text, anchor)
		if at < 0 {
			t.Errorf("%s: %s has no anchor %s", a.ID, runbookPath, anchor)
			continue
		}
		rest := text[at+len(anchor):]
		end := strings.Index(rest, "\n## ")
		if end < 0 {
			end = len(rest) // the last section runs to the end of the file
		}
		if len(strings.TrimSpace(rest[:end])) < 200 {
			t.Errorf("%s: its runbook section is too short to act on", a.ID)
		}
	}
	// A command block that holds only comments is a placeholder someone forgot to
	// fill in, and an unbalanced fence means the rest of the page is malformed.
	requireRunnableCommands(t, text)
}

// requireRunnableCommands checks every fenced block in the runbook: closed, and
// with at least one line an operator would paste that is not a comment.
func requireRunnableCommands(t *testing.T, text string) {
	t.Helper()
	const fence = "```"
	var lang string
	var lines []string
	checked := 0
	for {
		open := strings.Index(text, fence)
		if open < 0 {
			break
		}
		rest := text[open+len(fence):]
		nl := strings.Index(rest, "\n")
		if nl < 0 {
			t.Errorf("%s: a code fence is not closed", runbookPath)
			return
		}
		lang, rest = strings.TrimSpace(rest[:nl]), rest[nl+1:]
		closeAt := strings.Index(rest, fence)
		if closeAt < 0 {
			t.Errorf("%s: a %s code fence is not closed", runbookPath, lang)
			return
		}
		lines = strings.Split(rest[:closeAt], "\n")
		text = rest[closeAt+len(fence):]
		if lang != "sh" {
			continue
		}
		checked++
		hasCommand := false
		for _, l := range lines {
			if trimmed := strings.TrimSpace(l); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				hasCommand = true
			}
		}
		if !hasCommand {
			t.Errorf("%s: a sh block contains only comments; nothing to run", runbookPath)
		}
	}
	if checked == 0 {
		t.Errorf("%s: no command block at all; an on-call page needs commands", runbookPath)
	}
}

// TestRulesKeyOnRealLogLines reads every non-test Go file in the repo and checks
// that each rule's log line and alert id actually exist in the code.
func TestRulesKeyOnRealLogLines(t *testing.T) {
	sources := repoSources(t)
	sites := alertSites(sources)
	for _, a := range monitoring.Alerts {
		if !a.Coarse && !strings.Contains(sources, `"`+a.Msg+`"`) {
			t.Errorf("%s: no code logs a line with msg %q", a.ID, a.Msg)
		}
		if a.Emits == "" {
			continue
		}
		name, ok := constNames[a.Emits]
		if !ok {
			t.Errorf("%s: emits %q has no known constant name", a.ID, a.Emits)
			continue
		}
		if sites[name] == 0 {
			t.Errorf("%s: nothing logs monitoring.%s through AlertFields", a.ID, name)
		}
	}
}

// TestUnclassifiedRuleWatchesOnlyForgottenLines proves the net under the taxonomy:
// no code may name the coarse id itself, because its filter selects alert lines
// that carry no id. A site that did would fire both its own rule and the net.
func TestUnclassifiedRuleWatchesOnlyForgottenLines(t *testing.T) {
	if got := alertSites(repoSources(t))[monitoring.UnclassifiedAlert]; got > 0 {
		t.Errorf("%s is a net over unlisted ids, but %d site(s) name it", monitoring.UnclassifiedAlert, got)
	}
	coarse := monitoring.ByID(monitoring.UnclassifiedAlert)
	if coarse == nil {
		t.Fatalf("the taxonomy lost its coarse rule")
	}
	if !strings.Contains(coarse.Filter(), "NOT jsonPayload.alert_id=*") {
		t.Errorf("%s: the coarse rule must exclude lines that name a rule: %q", coarse.ID, coarse.Filter())
	}
}

// alertSites counts each constant name used at an AlertFields call site.
func alertSites(sources string) map[string]int {
	out := map[string]int{}
	for _, m := range alertSite.FindAllStringSubmatch(sources, -1) {
		out[m[1]]++
	}
	return out
}

// TestNoUncoveredAlertSite is the other direction: an alert id logged anywhere in
// the repo must be in the taxonomy, so a new failure mode cannot ship unwatched.
func TestNoUncoveredAlertSite(t *testing.T) {
	byName := make(map[string]string, len(constNames))
	for id, name := range constNames {
		byName[name] = id
	}
	for name := range alertSites(repoSources(t)) {
		id, ok := byName[name]
		if !ok {
			t.Errorf("code emits monitoring.%s, which no rule knows", name)
			continue
		}
		if monitoring.ByID(id) == nil {
			t.Errorf("code emits alert_id %s (%s) with no rule for it", id, name)
		}
	}
}

func TestFiltersAndMetricNames(t *testing.T) {
	metrics := monitoring.LogMetrics()
	names := make([]string, 0, len(metrics))
	for _, m := range metrics {
		names = append(names, m.Name)
	}
	if !slices.IsSorted(names) {
		t.Errorf("log metrics must be sorted for a stable diff: %v", names)
	}
	if len(metrics) != len(monitoring.Alerts)+1 {
		t.Errorf("got %d metrics for %d alerts; expected one more for the ratio denominator",
			len(metrics), len(monitoring.Alerts))
	}
	if !slices.Contains(names, monitoring.DenominatorMetric()) {
		t.Errorf("the ratio denominator %q is missing", monitoring.DenominatorMetric())
	}
	for _, m := range metrics {
		if m.MetricKind != "DELTA" || m.ValueType != "INT64" {
			t.Errorf("%s: a log counter must be DELTA over INT64, got %s/%s", m.Name, m.MetricKind, m.ValueType)
		}
		if !strings.HasPrefix(m.Filter, "jsonPayload.") {
			t.Errorf("%s: filter %q does not select on a structured log field", m.Name, m.Filter)
		}
		if !strings.Contains(m.Description, runbookPath) {
			t.Errorf("%s: description must point an operator at the runbook", m.Name)
		}
	}
	// A generated filter is pasted into a console, so it must stay a single
	// well-formed predicate: one quoted value per clause and no empty one.
	for _, a := range monitoring.Alerts {
		f := a.Filter()
		if strings.Contains(f, `""`) {
			t.Errorf("%s: filter %q has an empty quoted value", a.ID, f)
		}
		if strings.Count(f, `"`)%2 != 0 {
			t.Errorf("%s: filter %q has unbalanced quotes", a.ID, f)
		}
	}
	// A policy refers to a log metric by its full user-domain path, in both the
	// numerator and the denominator: a bare metric name matches no series, which
	// is a rule that never fires.
	for _, d := range monitoring.Policies() {
		cond := d["conditions"].([]any)[0].(map[string]any)
		threshold, ok := cond["conditionThreshold"].(map[string]any)
		if !ok {
			continue
		}
		for _, field := range []string{"filter", "denominatorFilter"} {
			v, ok := threshold[field].(string)
			if !ok {
				continue
			}
			if !strings.HasPrefix(v, `metric."logging.googleapis.com/user/intel_`) || !strings.HasSuffix(v, `"`) {
				t.Errorf("%s: %s %q is not a full log-metric path", cond["displayName"], field, v)
			}
		}
		_, hasDenominator := threshold["denominatorFilter"]
		isRatio := cond["displayName"] == any(monitoring.ApiErrorRate)
		if hasDenominator != isRatio {
			t.Errorf("%s: denominatorFilter present=%v, ratio rule=%v", cond["displayName"], hasDenominator, isRatio)
		}
	}
}

// TestCommittedArtifactsMatchTable keeps deploy/monitoring honest: regenerate and
// compare, exactly like the shared vectors under schemas/.
func TestCommittedArtifactsMatchTable(t *testing.T) {
	files := map[string]func() ([]byte, error){
		"deploy/monitoring/log-metrics.json":    monitoring.RenderLogMetrics,
		"deploy/monitoring/alert-policies.json": monitoring.RenderAlertPolicies,
	}
	for path, render := range files {
		want, err := render()
		if err != nil {
			t.Fatalf("%s: render: %v", path, err)
		}
		got, err := os.ReadFile(filepath.Join("..", "..", path))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if string(got) != string(want) {
			t.Errorf("%s is stale; run `make gen-alerts`", path)
		}
	}
	// Both files must stay parseable as the shapes Cloud uses.
	policies, err := os.ReadFile(filepath.Join("..", "..", "deploy/monitoring/alert-policies.json"))
	if err != nil {
		t.Fatal(err)
	}
	var docs []map[string]any
	if err := json.Unmarshal(policies, &docs); err != nil {
		t.Fatalf("alert-policies.json is not a JSON array of policies: %v", err)
	}
	if len(docs) != len(monitoring.Alerts) {
		t.Errorf("got %d policies for %d alerts", len(docs), len(monitoring.Alerts))
	}
	for _, d := range docs {
		conds, ok := d["conditions"].([]any)
		if !ok || len(conds) != 1 {
			t.Errorf("policy %v must carry exactly one condition", d["displayName"])
			continue
		}
		cond := conds[0].(map[string]any)
		threshold, absent := cond["conditionThreshold"], cond["conditionAbsent"]
		if threshold == nil && absent == nil {
			t.Errorf("policy %v has neither a threshold nor an absence condition", d["displayName"])
		}
		if _, ok := d["userLabels"].(map[string]any); !ok {
			t.Errorf("policy %v lost its runbook labels", d["displayName"])
		}
	}
}

// TestCountFieldsMapToCloudNumbers pins the two counts onto the two Cloud numbers
// they each mean: min_events is the per-window event floor (thresholdValue, one
// lower because the comparison is GT) and datapoints is how many consecutive
// breaching windows must agree (trigger.count). One field feeding both turns a
// ticket into a twenty-minute page, which is what this test guards against.
func TestCountFieldsMapToCloudNumbers(t *testing.T) {
	for _, d := range monitoring.Policies() {
		cond := d["conditions"].([]any)[0].(map[string]any)
		id, _ := cond["displayName"].(string)
		a := monitoring.ByID(id)
		if a == nil {
			t.Fatalf("condition %q is not a table alert", id)
		}
		want := a.Datapoints
		if want == 0 {
			want = 1
		}
		tr, ok := cond["conditionThreshold"].(map[string]any)
		if !ok {
			ab := cond["conditionAbsent"].(map[string]any)
			if got := ab["trigger"].(map[string]any)["count"]; got != want {
				t.Errorf("%s: absence trigger count = %v, table says %d", id, got, want)
			}
			continue
		}
		if got := tr["trigger"].(map[string]any)["count"]; got != want {
			t.Errorf("%s: trigger count = %v, table says %d datapoints", id, got, want)
		}
		wantThreshold := float64(a.MinEvents - 1)
		if a.Ratio {
			wantThreshold = a.Percent / 100
		}
		got, ok := tr["thresholdValue"].(float64)
		if !ok {
			t.Errorf("%s: thresholdValue is missing", id)
			continue
		}
		if wantThreshold < 0 {
			t.Errorf("%s: table wants a negative threshold, which always breaches", id)
		}
		if got != wantThreshold {
			t.Errorf("%s: thresholdValue = %v, table wants %v", id, got, wantThreshold)
		}
	}
}

// TestHaltKindCoversEveryHalt keeps the taxonomy and the ingester in step: each
// error IsHalt recognises must have a kind, and each kind must be reachable.
func TestHaltKindCoversEveryHalt(t *testing.T) {
	seen := map[string]bool{}
	for kind, name := range haltKindNames {
		if !regexp.MustCompile(`^Halt[A-Z]`).MatchString(name) {
			t.Errorf("%s: constant name %q does not look like a halt kind", kind, name)
		}
		if seen[kind] {
			t.Errorf("duplicate halt kind %q", kind)
		}
		seen[kind] = true
	}
	for _, a := range monitoring.Alerts {
		for _, k := range a.HaltKinds {
			if !seen[k] {
				t.Errorf("%s selects on halt_kind %q, which ingest does not define", a.ID, k)
			}
		}
	}
	// The general ingestion-halt rule must not narrow on kinds, or a new kind
	// would silence it: a halt with an unknown cause still has to page.
	halt := monitoring.ByID(monitoring.IngestHalt)
	if halt == nil || len(halt.HaltKinds) > 0 {
		t.Errorf("INGEST_HALT must fire on any halt cause, not a list")
	}
}

// repoSources returns the concatenated non-test Go source of the repository,
// minus this package: the table states its own Msg and id strings, so leaving it
// in would let a rule satisfy its own coverage check by describing itself.
func repoSources(t *testing.T) string {
	t.Helper()
	return sourcesOf(t, filepath.Join("..", ".."), "monitoring")
}

func sourcesOf(t *testing.T, root string, skipDirs ...string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable sibling directories are not this test's problem
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "testdata" || slices.Contains(skipDirs, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		b.Write(body)
		b.WriteByte('\n')
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return b.String()
}
