# Runbook: on-call alerts for Intel

Alert rules for the conditions intel #54 lists — ingestion halt and each of its
causes, the ledger gap, an undecodable XDR, a lost writer lock, snapshot age,
signing and publish failures, a refused snapshot file, API errors, a panic and a
stopped process — plus one net for any alert the table does not know, and one
section per alert for whoever is paged.

The rules are not hand-maintained. `internal/monitoring/alerts.go` is the table:
every alert's id, log line, metric, window and threshold live there, and
`make gen-alerts` writes `deploy/monitoring/log-metrics.json` and
`deploy/monitoring/alert-policies.json` from it. The tests in
`internal/monitoring/alerts_test.go` fail if a rule keys on a log line no code
emits, if code emits an alert id with no rule, if this page loses a section, or
if the committed JSON and the table disagree. So a rule that goes stale is a red
build, not a silent hole in the fail-loud promise (AGENTS.md §3.2).

Related: `protocol-upgrade.md` (what to do when the halt is XDR),
`docs/ARCHITECTURE.md` §4 (the pipeline these alerts watch), ADR 0006 (GCP and
log-based alert routing), intel #54.

## 0. The log fields the rules read

Intel logs JSON to stderr. Three fields are the monitoring contract:

| Field | Where | Meaning |
|---|---|---|
| `alert` | always `true` on a line that needs an operator | the coarse "wake someone up" flag |
| `alert_id` | one of the ids in the sections below | which rule this line belongs to |
| `halt_kind` | on `worker stopped` and `ingest halted` | why ingestion stopped, named by `ingest.HaltKind` |

`halt_kind` values are `gap`, `inconsistent`, `wrong_network`, `writer_active`,
`no_start`, `unknown_xdr`, `unsupported_protocol`, `invalid_data`,
`retries_exhausted`, and `unclassified` for anything that exited without a named
cause. `unclassified` still fires `INGEST_HALT`: the general rule deliberately
does not narrow on the list, so an unforeseen cause pages rather than goes
quiet. A lost writer lock is not an ingestion cause, so its line carries
`alert_id=WRITER_LOCK_LOST` and no `halt_kind` at all.

Only three commands write these fields — `intel-worker`, `intel-ingest` and
`intel-api` — and they write them through `monitoring.AlertFields(id)` rather
than by hand, so a line either has both `alert` and `alert_id` or neither.
One-shot dev tools (`intel-fuzz-seeds`, `internal/store/cmd/migrate`) log errors
and exit non-zero instead: whoever ran them reads the output. Dev-tool logs are
not alerting input.

That leaves one case the taxonomy cannot see statically: a line with `alert=true`
and no `alert_id`, or an id nobody listed. `UNCLASSIFIED_ALERT` is the net under
that, and it is why the flag still means something on its own — see its section.

Two rules read the opposite kind of line: a *success* line with no alert fields at
all. `SNAPSHOT_STALE` counts `msg="snapshot published"` and `INGEST_LAG` counts
`msg="ledger processed"`, and each fires when its series goes quiet for longer
than the window, which is how a stopped publisher is told apart from one that is
publishing slowly. They are also the only rules that see a process that exited
*cleanly* — a SIGTERM, or a deploy that did not come back — because that path
logs an informational line and no alert.

Log lines carry counts, ids and durations only — never raw XDR, account
addresses, domains or key material (AGENTS.md §6). The API's per-request line
carries the matched route *pattern* (`/v1/entities/{type}/{id}`), status, byte
count and duration, not the path. `API_ERROR_RATE` is built on that line, which
is why it can count 5xx responses without a request path reaching a metric
label.

Two thresholds come from the documents rather than from this page: the snapshot
heartbeat is twice the worker's default `-snapshot-interval` (5 min → 600 s),
matching the PRD §7 target of a new verdict in a snapshot within five minutes;
and the ingestion-progress heartbeat is 900 s, the "ingest halted > 15 min" line
in ARCHITECTURE_ESSENTIALS.

## 1. Applying the rules

Nothing in this repo provisions a cloud account. The artifacts are applied by an
operator, deliberately, after intel #33's project exists:

```sh
make gen-alerts                          # rewrite deploy/monitoring/ from the table
go run ./cmd/gen-alerts -check           # fails if the committed files diverged
go run ./cmd/gen-alerts -split /tmp/lm   # one config file per metric, for the loop

for f in /tmp/lm/intel_*.json; do
  gcloud logging metrics create "$(basename "$f" .json)" \
    --project=PROJECT_ID --config-from-file="$f"
done
```

`gcloud logging metrics create` takes one metric per call, and the config file is
the whole `LogMetric` — name, filter, description and the kind/value/unit fields.
The synopsis is `METRIC_NAME (--config-from-file=PATH | --description=TEXT
--log-filter=FILTER)`, so the flag forms are alternatives: use `-split` and the
file, not `--log-filter`, because the short flag form cannot express `DELTA` over
`INT64`. The committed `log-metrics.json` is the same set as one array, which is
the version to review as a whole; `-split` exists because the CLI reads one metric
per file. Cloud Logging's `LogMetric` requires only `filter`; everything Intel
uses is a `DELTA`/`INT64` counter.

Alerting policies have no `gcloud` create command; they are a
`monitoring/v3` `projects.alertPolicies` POST, one per element of
`alert-policies.json`:

```sh
curl -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/policy.json \
  "https://monitoring.googleapis.com/v3/projects/PROJECT_ID/alertPolicies"
```

Before that POST, replace the two placeholders the generator writes:
`PROJECT_ID` and `CHANNEL_ID` in `notificationChannels`. Those are per-project
values this repo must not carry. The generator leaves them in place so a
half-configured apply fails loudly instead of notifying nobody.

`alertStrategy` is left unset on purpose: the default close behaviour and
no-notification-remaining handling are the Cloud defaults, and a policy that
mutes itself by default would hide the outage it exists to report.

Each threshold policy carries two counts and they mean different things.
`thresholdValue` is how many log lines one window must hold for that datapoint to
breach; the comparison is `GT`, so it is one below the event count the table
names. `conditions[].trigger.count` is how many consecutive breaching windows
must agree before anything notifies. Wanting two failures inside one window is not
the same rule as waiting for two windows, and only the second one takes twenty
minutes to say anything.

## 2. Severity

`page` means the protection Intel provides is degraded right now, so somebody
acts now. `ticket` means the system is already retrying and the same person
looks the same day. The `severity` label is on every policy.

---

## INGEST_HALT — Intel ingestion halted
<a id="ingest-halt"></a>

**Rule:** `intel_ingest_halt` counts `alert_id="INGEST_HALT"`, and the policy
fires on any datapoint above 0 within 300 s, one datapoint deep.

**What happened.** `intel-worker` exited non-zero. It does that only when a
ledger could not be ingested correctly, or a component inside it failed;
`intel-ingest`, the facts-only debug command, logs the same id. Nothing new is
being recorded, so the snapshot will age out and Guard clients will start
showing "protection data stale".

**First move.** Read `halt_kind` in the same line and go to that section: a gap,
an XDR problem and a wrong-network problem have different remedies, and the
wrong remedy loses data. The `err` field is a message from
`internal/ingest`/`xdrcompat` — it names ledger numbers and reasons, not
addresses.

**Do not** restart the worker to quiet the alert. Restarting resumes at
checkpoint+1, so if the cause is still there it halts again, and if the cause was
a source that briefly served something inconsistent you may now be skipping
evidence. Confirm the checkpoint first:

```sh
psql "$INTEL_DATABASE_URL" -c 'SELECT network, last_ledger, updated_at FROM ingest_checkpoint;'
```

**Do not** raise `xdrcompat.MaxProtocol` to get past an XDR halt. That constant
states which XDR definitions this build was checked against; see
`protocol-upgrade.md` §"Never work around a halt by raising MaxProtocol".

## LEDGER_GAP — Intel ingestion hit a ledger gap
<a id="ledger-gap"></a>

**Rule:** `intel_ledger_gap`, the halt line narrowed to `halt_kind="gap"`.
Threshold: any occurrence in 300 s.

**What happened.** The next ledger the checkpoint asks for is not what the source
can serve. Three causes, all data-completeness problems rather than process
problems: the source no longer retains it (RPC history is about seven days),
another writer moved the checkpoint by more than one, or the source's oldest
ledger is already past our next one. `internal/store.Checkpoint.Set` also refuses
any advance that is not exactly `last+1`, so a gap cannot be written by accident.

**First move.** Establish which ledgers are missing, from the checkpoint row and
the error's ledger number. Then compare with the source's range. A gap Intel can
still fetch is a bug worth stopping for; a gap the source has already dropped
needs the backfill path (intel #52) before the checkpoint can move, and faking
forward with a manual `UPDATE` would silently mark those ledgers as ingested.

**Consequence to state in the incident note.** Every verdict computed after the
gap is based on incomplete evidence for the skipped range. The snapshot keeps its
`generated_at` and its own version, so nothing looks worse than it is, but the
coverage claim for that window is what is in question.

## XDR_UNSUPPORTED — Intel cannot decode this ledger stream
<a id="xdr-unsupported"></a>

**Rule:** `intel_xdr_unsupported`, the halt line narrowed to
`unknown_xdr`, `unsupported_protocol` or `invalid_data`. Any occurrence pages.

**What happened.** The pinned XDR definitions could not decode a ledger
completely and exactly, the ledger's protocol is above `MaxProtocol`, or a
decoded value breaks a ledger rule the package relies on. This is the alert that
fires on protocol-upgrade day: testnet activates Protocol 30 on 2026-11-03 and
Intel's pin is `go-stellar-sdk` v0.7.3 (Protocol 28 XDR, `MaxProtocol` 29).

**First move.** Read the protocol version from the line, then follow
`protocol-upgrade.md`. If the date is the scheduled activation of a known
protocol, a halt is the designed outcome and the fix is the dependency bump at
its eligible date, not a workaround. If it is *not* an upgrade day, treat it as
a source problem or a hostile input: the endpoint is serving something that
claims to be a ledger and does not decode.

**Check the endpoint too.** A halt from an `invalid_data` kind on one endpoint
and not another is evidence about that endpoint, so record which RPC URL was
configured before drawing conclusions.

## WRITER_LOCK_LOST — Intel lost its single-writer lock
<a id="writer-lock-lost"></a>

**Rule:** `intel_writer_lock_lost` counts `alert_id="WRITER_LOCK_LOST"`. Any
occurrence in 300 s pages.

**What happened.** The Postgres advisory connection that makes one process the
writer for a network dropped, so `store.Watch` closed `Lost` and the worker
exited rather than keep writing without proof it holds the lock. The risk this
alert exists for is two writers assigning snapshot versions and checkpoints to
each other.

**First move.** Before restarting anything, check who holds the lock now:

```sh
psql "$INTEL_DATABASE_URL" -c \
  "SELECT pid, locktype, granted FROM pg_locks WHERE locktype = 'advisory';"
```

Then confirm only one `intel-worker` process per network is running
(`-network` is the unit of the lock). If a second worker is up, decide which one
keeps running and stop the other; starting a third makes the version sequence
ambiguous, which Guard's verification will later reject.

**Also look at Postgres.** A dropped connection usually means the database
restarted, failed over, or killed a session. If the database itself is unhealthy,
the API is degraded too, and `API_ERROR_RATE` will likely have fired alongside.

## SNAPSHOT_SIGN_FAILED — Intel could not sign a snapshot
<a id="snapshot-sign-failed"></a>

**Rule:** `intel_snapshot_sign_failed` counts `alert_id="SNAPSHOT_SIGN_FAILED"`
on the publish line. Any occurrence in 300 s pages.

**What happened.** The signing call failed, so no new snapshot exists — this is
not a slow publish, it is no publish. `snapshot.Build` wraps the failure in
`snapshot.ErrSigning`, which is how the worker tells it apart from a disk or
record failure.

**First move.** Look at the key: `-signing-key-id` and the signer in use. Until
the Cloud KMS signer lands (intel #34), the only signer is a PEM PKCS#8 Ed25519
file at mode 0600 — so the usual causes are the file being rotated away, its
permissions tightened past the service account, or a KMS permission change once
KMS is live. Do not print, copy or recreate key material while chasing this; the
key id in the log line is enough to identify which key is being asked for.

**Second move.** Confirm the stale path is behaving: the last good snapshot stays
served, Guard refuses past its max age and shows stale protection data. If
`SNAPSHOT_STALE` fired first and this after, you have a signing outage, not a
storage one.

## SNAPSHOT_FILE_REJECTED — Intel refused to serve a snapshot
<a id="snapshot-file-rejected"></a>

**Rule:** `intel_snapshot_rejected` counts `alert_id="SNAPSHOT_FILE_REJECTED"`.
Any occurrence in 300 s pages.

**What happened.** The API has a recorded snapshot row but the file behind it is
missing, oversized, not a snapshot document, or disagrees with the row on
`generated_at`, header, key id, entry count or signature. The API answered 503
rather than serve bytes it cannot tie to the record.

**First move.** Do not delete or edit the row to make the request succeed; the
row is what the signature was checked against. Compare the file with the row and
work out which is wrong:

```sh
psql "$INTEL_DATABASE_URL" -c \
  'SELECT network, version, generated_at, entry_count, object_key, signing_key_id FROM snapshot ORDER BY version DESC LIMIT 5;'
ls -l "$SNAPSHOT_DIR"
```

A row with no file usually means the publish directory moved or was pruned; a
file that disagrees with its row means something wrote into the directory out of
band. Either way the right action is to let the worker publish a fresh version,
not to reconcile the old one by hand.

## API_PANIC — An Intel API handler panicked
<a id="api-panic"></a>

**Rule:** `intel_api_panic` counts `alert_id="API_PANIC"`. Any occurrence pages.

**What happened.** A handler crashed after the middleware had already accepted
the request. The recoverer answered `{"error":"internal"}` with a 500 and did not
log the panic value, because a panic value can contain request data.

**First move.** Find the neighbouring `request` line by `request_id` — it holds
the route pattern, status, bytes and duration. That tells you which route and
which shape of call panicked. Reproduce it against the same snapshot version with
a read-only request; the API only reads, so a reproduction is safe to run.

**If it repeats.** A panic driven by stored data is a data problem, not a code
style problem: check what changed in the last published snapshot before
suspecting the handler.

## API_STOPPED — The Intel API stopped
<a id="api-stopped"></a>

**Rule:** `intel_api_stopped` counts `alert_id="API_STOPPED"`. Any occurrence
pages.

**What happened.** `intel-api` exited non-zero. It exits that way when it could
not start (database unreachable, bad config) or when the listener died.

**First move.** Check the two things it needs: `INTEL_DATABASE_URL` reachability
and the snapshot directory the worker writes to. The API refuses to serve from a
directory it cannot read, and it will not guess a methodology or review URL, so a
missing `-methodology-url` or `-review-url` is also an exit — that is a
configuration drift, and the fail-closed behaviour is the point.

**Look for the correlated alert.** If `WRITER_LOCK_LOST` or `INGEST_HALT` fired
in the same window, the platform is degraded at the source and this line is
noise from the read side.

## SNAPSHOT_STALE — The published snapshot is going stale
<a id="snapshot-stale"></a>

**Rule:** absence rule on `intel_snapshot_published` (the worker's success line):
if no datapoint arrives within 600 s, the policy fires.

**What happened.** The worker has not published in twice its default interval.
Guard clients compare a snapshot's `generated_at` with their own max-age and
switch to a "protection data stale" state; this alert is meant to fire before
that becomes user-visible.

**First move.** Establish whether the worker is running at all, then whether it
is running and failing to publish. The second case always logs
`SNAPSHOT_PUBLISH_FAILED` or `SNAPSHOT_SIGN_FAILED`, so read the last ten minutes
of both before touching anything:

```sh
gcloud logging read 'jsonPayload.alert_id="SNAPSHOT_PUBLISH_FAILED" OR jsonPayload.alert_id="SNAPSHOT_SIGN_FAILED"' \
  --project=PROJECT_ID --freshness=10m --order=desc --limit 10 \
  --format='table(timestamp, jsonPayload.alert_id, jsonPayload.err)'
```

If neither appears, ask whether anything published at all in the window:

```sh
gcloud logging read 'jsonPayload.msg="snapshot published"' \
  --project=PROJECT_ID --freshness=10m --order=desc --limit 5 \
  --format='table(timestamp, jsonPayload.network, jsonPayload.version, jsonPayload.entries)'
```

If the worker is healthy but quiet, check `-snapshot-interval`: an operator
who raised the interval above 300 s has made this alert fire by configuration.
Change the interval or the window, and say which in the ticket, so the next
person does not hunt for a fault that was a setting.

## INGEST_LAG — Ingestion has made no progress
<a id="ingest-lag"></a>

**Rule:** absence rule on `intel_ledger_processed` (the pipeline's per-ledger
line): 900 s without a datapoint fires it.

**What happened.** No ledger was processed for fifteen minutes, and no halt was
reported either — so the worker is stuck rather than stopped. The common shape is
a source that keeps answering with nothing new, or a request hanging until its
timeout and then retrying quietly.

**First move.** Compare the checkpoint with the network's latest ledger. If the
source is ahead and we are not moving, this is our pipeline; if the source itself
is not advancing, it is the endpoint or the network, and the fix is the endpoint,
not a restart.

```sh
psql "$INTEL_DATABASE_URL" -c 'SELECT network, last_ledger, updated_at FROM ingest_checkpoint;'
curl -s -X POST "$RPC_URL/jrpc" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getLedgers","params":{"startLedger":0,"endLedger":1}}'
```

**Why this is a separate alert.** A halt is loud by design; a stall is the quiet
failure mode, and the absence rule is what makes it loud too. `retries_exhausted`
in `INGEST_HALT` is its loud cousin — after `MaxRetries` consecutive retryable
errors the worker gives up and pages.

## UNCLASSIFIED_ALERT — An Intel alert has no rule
<a id="unclassified-alert"></a>

**Rule:** `intel_unclassified_alert` counts
`jsonPayload.alert=true AND NOT jsonPayload.alert_id=*` — the coarse flag on a
line that names no rule; one datapoint per 300 s window, and a `ticket`, because
the failure it describes is a missing rule, not necessarily a missing service.

**What happened.** Code asked for an operator, and nothing in
`internal/monitoring/alerts.go` owns that ask. Two shapes cause it: a new log
site set `alert: true` without an `alert_id`, or it named an id the table does
not list. Either way the underlying fault may already be handled by another rule
and this is noise on top, or it is a real condition nobody has written a rule for
yet — which is the case this net exists to catch.

**First move.** Find the line itself; the rule is the only way to see it, so
search the last hour for the flag rather than for an id:

```sh
gcloud logging read 'jsonPayload.alert=true AND NOT jsonPayload.alert_id=*' \
  --project=PROJECT_ID --freshness=1h --order=desc --limit 20 \
  --format='table(timestamp, jsonPayload.msg, jsonPayload.err)'
```

Then give it a rule: add the id and its threshold to the table, wire the site to
`monitoring.AlertFields(<that id>)`, write the section, run `make gen-alerts` and
apply the new pair. The tests in `internal/monitoring` fail the build if any of
those steps is missing, so the fix is forced to be complete.

**Do not** delete the `alert` field from the log line to silence this. That turns
a monitoring gap into a monitoring gap with no evidence, and the fault that
prompted the line stays unwatched. If the site is genuinely a dev tool that
should not alert, remove the field *and* say so in §0's list of monitored
commands, in the same change.

## SNAPSHOT_PUBLISH_FAILED — An Intel snapshot publish failed
<a id="snapshot-publish-failed"></a>

**Rule:** `intel_snapshot_publish_failed` counts
`alert_id="SNAPSHOT_PUBLISH_FAILED"`; the policy fires when **one** 600 s window
holds two or more failures (`thresholdValue` 1, one datapoint deep), and is a
`ticket`, not a page.

**What happened.** One publish attempt failed and the loop retries at the next
tick. Causes are storage-side (directory full, rename failed), the record insert
failing, or the flagged-entity query erroring — explicitly not signing, which has
its own alert.

**First move.** One hit needs no action; confirm it is not becoming a run by
counting the line over the last hour. Two or more in a row means the next tick
will be late, and three means `SNAPSHOT_STALE` is about to fire — escalate to
that section rather than waiting.

```sh
gcloud logging read 'jsonPayload.alert_id="SNAPSHOT_PUBLISH_FAILED"' \
  --project=PROJECT_ID --freshness=1h --order=desc --limit 20 \
  --format='table(timestamp, jsonPayload.err)'
```

**Do not** delete orphaned snapshot files to "clean up". The publisher writes the
versioned file, records the row, then replaces `-latest`; an orphaned versioned
file is overwritten by the next attempt with the same version number. Removing
the `-latest` pointer is what breaks readers.

## API_ERROR_RATE — The Intel API is returning too many errors
<a id="api-error-rate"></a>

**Rule:** ratio policy: `intel_api_5xx` (request lines with
`jsonPayload.status>=500`) over `intel_api_requests` (all request lines),
COMPARISON_GT 0.01 (one percent) per 300 s window, two datapoints, `ticket`.

**What happened.** More than one percent of read-API requests were answered 5xx.
The API maps a store timeout to 503 `unavailable` and every other store failure to
500 `internal`, so an error-rate spike is normally a database story, not a handler
story. A `SNAPSHOT_FILE_REJECTED` burst also lands here as 503s.

**First move.** Check database latency and connection saturation before
anything else. Then split the spike by route pattern: only `/v1/snapshots/*`
being bad points at the snapshot directory, while everything being bad points at
Postgres.

**The volume caveat.** `min_requests=100` is a label, not a second condition: a
policy that compares a ratio needs real volume beneath it, or one failed request
out of ten reads as 10 percent. The generator records the number so an operator
can add the composite condition (`AND intel_api_requests > 100`) per project.
That is deliberately left to the apply step rather than invented here, because a
composite policy needs a `conditionComposite` the table does not model yet, and a
rule nobody can verify is worse than a rule with a documented caveat.
