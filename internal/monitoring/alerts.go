// Package monitoring is Intel's alert taxonomy: the log lines that mean an
// operator has to act, the threshold each is watched at, and the Cloud
// Monitoring artifacts generated from them (intel #54).
//
// The table below is the only place an alert is defined. `make gen-alerts`
// rewrites `deploy/monitoring/` from it, and this package's tests fail when the
// committed artifacts and the table disagree, when a rule keys on a log line the
// code does not emit, or when the code emits an alert id the table does not
// list. Renaming a halt path without renaming its rule is therefore a build
// failure rather than a silent monitoring gap.
//
// Rules watch log-based metrics rather than a scrape endpoint: Intel's failure
// modes are already log statements (ADR 0006 routed alerting through Cloud
// Logging), and a new endpoint would need an approval, a port and an
// authentication story. A missing rule is a hole in the fail-loud promise
// (AGENTS.md §3.2), which is why coverage is checked in both directions.
package monitoring

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Alert ids. These are the values written into the `alert_id` log field, so they
// are the contract between the code and the generated rules. Names are stable:
// once an id is on an operator's dashboard it is not renamed casually.
const (
	IngestHalt         = "INGEST_HALT"
	LedgerGap          = "LEDGER_GAP"
	XdrUnsupported     = "XDR_UNSUPPORTED"
	WriterLockLost     = "WRITER_LOCK_LOST"
	SnapshotSignFailed = "SNAPSHOT_SIGN_FAILED"
	SnapshotFailed     = "SNAPSHOT_PUBLISH_FAILED"
	SnapshotStale      = "SNAPSHOT_STALE"
	SnapshotRejected   = "SNAPSHOT_FILE_REJECTED"
	IngestLag          = "INGEST_LAG"
	ApiErrorRate       = "API_ERROR_RATE"
	ApiPanic           = "API_PANIC"
	ApiStopped         = "API_STOPPED"
	// UnclassifiedAlert is not an id any code writes. It is the net under the
	// rest of the taxonomy: a line that sets the coarse `alert` flag but names no
	// rule, which is what happens when someone adds a failure site and forgets the
	// table. It has to be an id for the metric and runbook section to exist.
	UnclassifiedAlert = "UNCLASSIFIED_ALERT"
)

// AlertFields returns the slog fields that make a log line an alert: the coarse
// `alert` flag and the id of the rule that watches it.
//
// Call sites name the constant inside this call rather than passing a variable,
// so the rule and the line that feeds it are linked in the source text itself.
// The tests in this package use that link to fail a build when a rule watches a
// line nothing logs, or a log line has no rule.
func AlertFields(id string) []any {
	return []any{"alert", true, "alert_id", id}
}

// Severity is what the notification asks of a person.
type Severity string

// RunbookPath is the one page with a section per alert; it is carried into every
// generated metric description, and the tests fail if the file loses a section.
const RunbookPath = "docs/runbooks/oncall-alerts.md"

const (
	// Page: the protection Intel provides is degraded now, so someone acts now.
	Page Severity = "page"
	// Ticket: a retry is already in flight; act the same day.
	Ticket Severity = "ticket"
)

// Alert is one rule: what the code logs, what the metric counts, and when that
// becomes a notification.
type Alert struct {
	// ID names the rule; it is what an operator sees and what the runbook
	// section is anchored on.
	ID string
	// Emits is the alert id the log line actually carries. It is ID, except for
	// a subtype rule, which reads one field of an existing halt line: a ledger
	// gap and an undecodable XDR are both INGEST_HALT with a different
	// halt_kind. Empty means the rule keys on an ordinary log line instead.
	Emits string
	// HaltKinds selects among halt causes (ingest.HaltKind values). It is only
	// used with Emits, and every entry must be a kind the ingest package can
	// actually return.
	HaltKinds []string
	// MinStatus is the response-code floor for a rule over the API request log.
	MinStatus int
	// Title and Summary are the notification text; Action is the first thing an
	// operator does, with the reasoning left to the runbook section.
	Title    string
	Summary  string
	Action   string
	Severity Severity
	// Component names the command whose logs this rule reads.
	Component string
	// Msg is the slog `msg` of the emitting line; it must exist in the repo.
	Msg string
	// Metric is the log-based metric the rule watches. Every alert has one: an
	// absence rule still needs a time series that can go missing.
	Metric string
	// Absent fires when Metric stops arriving, which is how a stale snapshot or
	// a stalled ingestion is expressible from logs alone.
	Absent bool
	// Coarse makes the rule watch the `alert` flag instead of one log line, so it
	// catches an alert whose id the table does not know. It is the only rule with
	// no Msg, and there is exactly one of them.
	Coarse bool
	// Ratio divides the counted series by the request series it came from, so an
	// error rate is a rate and not a spike in traffic.
	Ratio   bool
	Percent float64
	// MinRequest is the volume below which a Ratio alert is noise. It is carried
	// into the policy's labels and explained in the runbook rather than invented
	// as a second condition here.
	MinRequest int
	// Window is the alignment period and the absence duration ("600s").
	Window string
	// MinEvents is how many log lines one window must hold for that datapoint to
	// breach (thresholdValue is one less, because the comparison is GT). Leave it
	// 0 for one event, and for a Ratio rule, whose breach is Percent instead.
	MinEvents int
	// Datapoints is how many consecutive breaching windows must agree before
	// notifying (the condition's trigger count). Zero means one, which is what
	// every rule wants except a ratio, where a single window is noise.
	Datapoints int
}

// datapoints is the condition trigger count, defaulting to a single window.
func (a Alert) datapoints() int {
	if a.Datapoints > 0 {
		return a.Datapoints
	}
	return 1
}

// event builds a rule that fires on MinEvents log lines per window.
func event(id, emits, title, summary, action string, sev Severity, component, msg, metric, window string, minEvents int) Alert {
	return Alert{ID: id, Emits: emits, Title: title, Summary: summary, Action: action, Severity: sev,
		Component: component, Msg: msg, Metric: metric, Window: window, MinEvents: minEvents}
}

// heartbeat builds a rule that fires when a periodic success line stops.
func heartbeat(id, title, summary, action string, sev Severity, component, msg, metric, window string) Alert {
	return Alert{ID: id, Title: title, Summary: summary, Action: action, Severity: sev,
		Component: component, Msg: msg, Metric: metric, Window: window, Absent: true}
}

// Alerts is the taxonomy, page-worthy rules first. The order only affects the
// generated files, so it is kept readable rather than alphabetical.
var Alerts = []Alert{
	event(IngestHalt, IngestHalt,
		"Intel ingestion halted",
		"intel-worker exited because a ledger could not be ingested correctly. Nothing new is being recorded.",
		"Read halt_kind, then that runbook section. Do not restart to make the alert quiet.",
		Page, "intel-worker", "worker stopped", "intel_ingest_halt", "300s", 1),
	withKinds(event(LedgerGap, IngestHalt,
		"Intel ingestion hit a ledger gap",
		"A halt whose cause is a missing ledger: the checkpoint's next sequence is not what the source serves.",
		"Treat it as a data-completeness incident: those ledgers need a backfill before ingestion resumes.",
		Page, "intel-worker", "worker stopped", "intel_ledger_gap", "300s", 1),
		"gap"),
	withKinds(event(XdrUnsupported, IngestHalt,
		"Intel cannot decode this ledger stream",
		"A halt whose cause is XDR: an unknown structure, a protocol newer than this build's pin, or a value that breaks a ledger rule.",
		"Compare the protocol version with the pinned XDR library and follow docs/runbooks/protocol-upgrade.md.",
		Page, "intel-worker", "worker stopped", "intel_xdr_unsupported", "300s", 1),
		"unknown_xdr", "unsupported_protocol", "invalid_data"),
	event(WriterLockLost, WriterLockLost,
		"Intel lost its single-writer lock",
		"The Postgres advisory lock that makes one process the writer for a network went away, so a second writer could start.",
		"Confirm one worker per network before restarting anything.",
		Page, "intel-worker", "worker stopped", "intel_writer_lock_lost", "300s", 1),
	event(SnapshotSignFailed, SnapshotSignFailed,
		"Intel could not sign a snapshot",
		"The signing call failed, so no new snapshot exists. Guard keeps using the last one until it goes stale.",
		"Check the key id and the signer's availability; a rotated key or a permission change is the usual cause.",
		Page, "intel-worker", "snapshot publish failed", "intel_snapshot_sign_failed", "300s", 1),
	event(SnapshotRejected, SnapshotRejected,
		"Intel refused to serve a snapshot",
		"A recorded snapshot's file is missing or disagrees with its row, so the API answered 503 instead of serving unverified bytes.",
		"Compare the file with the snapshot row. Do not delete the row to make the request succeed.",
		Page, "intel-api", "snapshot file rejected", "intel_snapshot_rejected", "300s", 1),
	event(ApiPanic, ApiPanic,
		"An Intel API handler panicked",
		"A handler crashed mid-request; the client got a 500 and the panic value was not logged.",
		"Find the request id in the neighbouring request log, then reproduce it against the same snapshot version.",
		Page, "intel-api", "handler panic", "intel_api_panic", "300s", 1),
	event(ApiStopped, ApiStopped,
		"The Intel API stopped",
		"intel-api exited non-zero, so the read API is down.",
		"Check the database connection and the snapshot directory before starting it again.",
		Page, "intel-api", "api stopped", "intel_api_stopped", "300s", 1),
	heartbeat(SnapshotStale,
		"The published snapshot is going stale",
		"No snapshot has been published in twice the publish interval, so Guard clients are approaching their max-age refusal.",
		"Confirm the worker is running and its publish loop is not logging failures.",
		Page, "intel-worker", "snapshot published", "intel_snapshot_published", "600s"),
	heartbeat(IngestLag,
		"Ingestion has made no progress",
		"No ledger was processed for fifteen minutes without a halt being reported: the worker is stuck, not stopped.",
		"Check the RPC endpoint and the source ledger range before restarting the worker.",
		Page, "intel-worker", "ledger processed", "intel_ledger_processed", "900s"),
	{
		ID: UnclassifiedAlert, Coarse: true,
		Title:    "An Intel alert has no rule",
		Summary:  "A log line asked for an operator but named an alert id the taxonomy does not list, so nothing else would have fired.",
		Action:   "Read the line, then add its id to internal/monitoring/alerts.go and regenerate; do not close this until it has a rule of its own.",
		Severity: Ticket, Component: "intel",
		Metric:    "intel_unclassified_alert",
		Window:    "300s",
		MinEvents: 1,
	},
	event(SnapshotFailed, SnapshotFailed,
		"An Intel snapshot publish failed",
		"One publish attempt failed and the loop retries at the next tick. One is noise; a run of them is the stale-snapshot alert.",
		"No action for a single hit; check the disk and the database if it repeats.",
		Ticket, "intel-worker", "snapshot publish failed", "intel_snapshot_publish_failed", "600s", 2),
	{
		ID: ApiErrorRate, MinStatus: 500,
		Title:    "The Intel API is returning too many errors",
		Summary:  "More than one percent of read-API requests answered 5xx over five minutes.",
		Action:   "Check database latency first: a store timeout is a 503 and looks like an error spike.",
		Severity: Ticket, Component: "intel-api",
		Msg:        requestMsg,
		Metric:     "intel_api_5xx",
		Ratio:      true,
		Percent:    1,
		MinRequest: 100,
		Window:     "300s",
		Datapoints: 2,
	},
}

// requestMsg is the slog msg of the API's per-request line.
const requestMsg = "request"

// DenominatorMetric is the request-count series a Ratio alert divides by.
func DenominatorMetric() string { return denominatorMetric }

// denominatorMetric is the request-count series a Ratio alert divides by.
const denominatorMetric = "intel_api_requests"

// withKinds attaches the halt causes a rule selects on.
func withKinds(a Alert, kinds ...string) Alert {
	a.HaltKinds = kinds
	return a
}

// Filter returns the Cloud Logging predicate that defines this alert's metric.
// A rule with an alert id keys on the id alone, so every command that can emit
// that condition is covered by one rule; a heartbeat or status-code rule has no
// id to key on, so it keys on the log line's msg instead; and the coarse rule
// keys on the alert flag with no id attached. Msg names the code path each other
// rule was written against, and is what the coverage tests check.
func (a Alert) Filter() string {
	var b strings.Builder
	switch {
	case a.Coarse:
		b.WriteString(`jsonPayload.alert=true AND NOT jsonPayload.alert_id=*`)
	case a.Emits == "":
		fmt.Fprintf(&b, "jsonPayload.msg=%q", a.Msg)
	default:
		fmt.Fprintf(&b, "jsonPayload.alert_id=%q", a.Emits)
	}
	if len(a.HaltKinds) > 0 {
		ors := make([]string, 0, len(a.HaltKinds))
		for _, k := range a.HaltKinds {
			ors = append(ors, fmt.Sprintf("jsonPayload.halt_kind=%q", k))
		}
		fmt.Fprintf(&b, " AND (%s)", strings.Join(ors, " OR "))
	}
	if a.MinStatus > 0 {
		fmt.Fprintf(&b, " AND jsonPayload.status>=%d", a.MinStatus)
	}
	return b.String()
}

// MetricPath is how a rule refers to the log metric: log-based metrics live
// under the user domain of the monitored project.
func (a Alert) MetricPath() string { return metricPath(a.Metric) }

func metricPath(name string) string { return "logging.googleapis.com/user/" + name }

// RunbookAnchor is the id of this alert's section in the on-call runbook.
func (a Alert) RunbookAnchor() string {
	return strings.ToLower(strings.ReplaceAll(a.ID, "_", "-"))
}

// Description is the text stored on the log metric.
func (a Alert) Description() string {
	return fmt.Sprintf("%s: %s Severity %s. Runbook: %s#%s",
		a.Metric, a.Summary, a.Severity, RunbookPath, a.RunbookAnchor())
}

// ByID returns the alert with this id, or nil.
func ByID(id string) *Alert {
	for i := range Alerts {
		if Alerts[i].ID == id {
			return &Alerts[i]
		}
	}
	return nil
}

// LogMetric is the config file shape `gcloud logging metrics create
// --config-from-file` takes: a name, the required filter, a description, and the
// counter kind Intel's rules are built on.
type LogMetric struct {
	Name        string `json:"name"`
	Filter      string `json:"filter"`
	Description string `json:"description"`
	MetricKind  string `json:"metricKind"`
	ValueType   string `json:"valueType"`
	Unit        string `json:"unit"`
}

func counter(name, filter, description string) LogMetric {
	return LogMetric{Name: name, Filter: filter, Description: description,
		MetricKind: "DELTA", ValueType: "INT64", Unit: "1"}
}

// LogMetrics returns every log-based metric the rules need, including the
// request total the ratio rule divides by, sorted by name for a stable diff.
func LogMetrics() []LogMetric {
	out := make([]LogMetric, 0, len(Alerts)+1)
	for _, a := range Alerts {
		out = append(out, counter(a.Metric, a.Filter(), a.Description()))
	}
	out = append(out, counter(denominatorMetric,
		fmt.Sprintf("jsonPayload.msg=%q", requestMsg),
		"Count of read-API requests logged by intel-api. Denominator of the API error-rate "+
			"alert (intel #54). The request line carries the route pattern, status, size and "+
			"duration only: never a path, body or address. Runbook: "+RunbookPath+"#"+
			strings.ToLower(strings.ReplaceAll(ApiErrorRate, "_", "-"))))
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// aggregation aligns a log metric's deltas into one datapoint per window, which
// is what "N events in the last M minutes" means as a threshold.
func aggregation(window string) map[string]any {
	return map[string]any{
		"alignmentPeriod":    window,
		"perSeriesAligner":   "ALIGN_SUM",
		"crossSeriesReducer": "REDUCE_SUM",
	}
}

// policy builds one Cloud Monitoring v3 AlertPolicy for this alert: one
// condition each, so muting or editing a rule cannot touch another.
func (a Alert) policy() map[string]any {
	cond := map[string]any{"displayName": a.ID}
	if a.Absent {
		cond["conditionAbsent"] = map[string]any{
			"filter":       metricFilter(a.MetricPath()),
			"aggregations": []any{aggregation(a.Window)},
			"duration":     a.Window,
			"trigger":      map[string]any{"count": a.datapoints()},
		}
		return a.policyOuter(cond)
	}
	threshold := map[string]any{
		"filter":       metricFilter(a.MetricPath()),
		"aggregations": []any{aggregation(a.Window)},
		"duration":     "0s",
		"comparison":   "COMPARISON_GT",
		"trigger":      map[string]any{"count": a.datapoints()},
	}
	if a.Ratio {
		threshold["thresholdValue"] = a.Percent / 100
		threshold["denominatorFilter"] = metricFilter(metricPath(denominatorMetric))
	} else {
		// The comparison is GT, so "at least N events in a window" is "more than N-1".
		threshold["thresholdValue"] = float64(a.MinEvents - 1)
	}
	cond["conditionThreshold"] = threshold
	return a.policyOuter(cond)
}

func (a Alert) policyOuter(cond map[string]any) map[string]any {
	labels := map[string]string{
		"runbook":      RunbookPath + "#" + a.RunbookAnchor(),
		"summary":      a.Summary,
		"first_action": a.Action,
		"component":    a.Component,
		"severity":     string(a.Severity),
		"alert_id":     a.ID,
	}
	if a.Ratio {
		labels["min_requests"] = fmt.Sprint(a.MinRequest)
	}
	return map[string]any{
		"displayName": "intel: " + a.Title,
		"combiner":    "OR",
		"conditions":  []any{cond},
		"userLabels":  labels,
		// Channel ids are per project and not ours to invent, so the runbook says
		// which placeholder to replace before applying the policies.
		"notificationChannels": []any{"projects/PROJECT_ID/notificationChannels/CHANNEL_ID"},
	}
}

func metricFilter(path string) string { return `metric."` + path + `"` }

// Policies returns one policy per alert, in table order.
func Policies() []map[string]any {
	out := make([]map[string]any, 0, len(Alerts))
	for _, a := range Alerts {
		out = append(out, a.policy())
	}
	return out
}

// RenderLogMetrics and RenderAlertPolicies produce the committed artifacts.
func RenderLogMetrics() ([]byte, error)    { return render(LogMetrics()) }
func RenderAlertPolicies() ([]byte, error) { return render(Policies()) }

func render(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("monitoring: render: %w", err)
	}
	return buf.Bytes(), nil
}
