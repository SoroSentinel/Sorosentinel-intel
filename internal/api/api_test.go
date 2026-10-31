package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/strkey"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/pipeline"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/snapshot"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/store"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/verdict"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/wording"
)

var (
	testNow  = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	testAsOf = time.Date(2026, 10, 28, 9, 30, 15, 123000, time.UTC)
)

// Valid strkeys built from fixed bytes, so checksums are real.
func gKey(b byte) string {
	return strkey.MustEncode(strkey.VersionByteAccountID, bytes.Repeat([]byte{b}, 32))
}

func cKey(b byte) string {
	return strkey.MustEncode(strkey.VersionByteContract, bytes.Repeat([]byte{b}, 32))
}

func mKey(t *testing.T, g string, id uint64) string {
	t.Helper()
	var m strkey.MuxedAccount
	if err := m.SetAccountID(g); err != nil {
		t.Fatal(err)
	}
	m.SetID(id)
	a, err := m.Address()
	if err != nil {
		t.Fatal(err)
	}
	return a
}

var (
	refIssuer  = gKey(1)
	lookIssuer = gKey(2)
	refAsset   = "USDC:" + refIssuer
	lookAsset  = "USDC:" + lookIssuer
)

// fakeStore holds results by "network|type|key" and records the keys asked for.
type fakeStore struct {
	results   map[string]store.LookupResult
	snapshots map[string]store.SnapshotRecord // "network|version"; version 0 = latest
	err       error
	asked     []store.LookupKey
}

func (f *fakeStore) LookupEntities(ctx context.Context, keys []store.LookupKey) ([]store.LookupResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.asked = append(f.asked, keys...)
	out := make([]store.LookupResult, len(keys))
	for i, k := range keys {
		out[i] = f.results[string(k.Network)+"|"+string(k.Type)+"|"+k.Key]
	}
	return out, nil
}

func (f *fakeStore) Snapshot(ctx context.Context, n entity.Network, version uint64) (store.SnapshotRecord, error) {
	if f.err != nil {
		return store.SnapshotRecord{}, f.err
	}
	r, ok := f.snapshots[fmt.Sprintf("%s|%d", n, version)]
	if !ok {
		return store.SnapshotRecord{}, store.ErrNotFound
	}
	return r, nil
}

func payload(t *testing.T, facts ...string) json.RawMessage {
	t.Helper()
	type fact struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	var fs []fact
	for i := 0; i+1 < len(facts); i += 2 {
		fs = append(fs, fact{facts[i], facts[i+1]})
	}
	b, err := json.Marshal(map[string]any{"entity": "x", "max_level": "suspicious", "facts": fs})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// lookalikeResult is a suspicious verdict on lookAsset backed by look-alike
// and home-domain evidence, shaped like what internal/pipeline stores.
func lookalikeResult(t *testing.T) store.LookupResult {
	return store.LookupResult{
		Verdict: &verdict.Verdict{
			ID: 7, EntityID: 3, Level: signal.Suspicious, Status: verdict.Active, Category: "lookalike_asset",
			RuleID: verdict.RuleAutomated, DecidedBy: "analyst-internal-7", RulesetVersion: verdict.V1.Version,
			AsOf: testAsOf, EvidenceIDs: []int64{11, 12},
		},
		Evidence: []store.LookupEvidence{
			{ID: 12, Detector: "D-HOMEDOMAIN-MISMATCH", ObservedAt: testAsOf, Payload: payload(t,
				"asset", lookAsset, "issuer", lookIssuer, "home_domain", "issuer.example",
				"toml_url", "https://issuer.example/.well-known/stellar.toml", "reason", "asset_not_listed")},
			{ID: 11, Detector: "D-ASSET-LOOKALIKE", ObservedAt: testAsOf.Add(-time.Minute), Payload: payload(t,
				"asset", lookAsset, "code", "USDC", "issuer", lookIssuer, "reference_code", "USDC",
				"match", "exact", "known_issuer_count", "1", "known_assets", refAsset)},
		},
	}
}

func newServer(t *testing.T, st Store, dir string, rnd *wording.Renderer) http.Handler {
	t.Helper()
	if rnd == nil {
		reg, err := wording.LoadEmbedded()
		if err != nil {
			t.Fatal(err)
		}
		if rnd, err = wording.NewRenderer(reg, testRenderConfig); err != nil {
			t.Fatal(err)
		}
	}
	if dir == "" {
		dir = t.TempDir()
	}
	s, err := New(Config{Store: st, Renderer: rnd, SnapshotDir: dir, Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	return s.Handler()
}

var testRenderConfig = wording.Config{MethodologyURL: "https://sorosentinel.invalid/m", ReviewURL: "https://sorosentinel.invalid/r"}

func do(t *testing.T, h http.Handler, method, target, contentType string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func entityPath(typ, key, network string) string {
	return "/v1/entities/" + typ + "/" + url.PathEscape(key) + "?network=" + network
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	dec := json.NewDecoder(rec.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode %T: %v", v, err)
	}
	return v
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	return decode[errorBody](t, rec).Error
}

func TestKnownEntityCautionWithFacts(t *testing.T) {
	st := &fakeStore{results: map[string]store.LookupResult{"testnet|asset|" + lookAsset: lookalikeResult(t)}}
	rec := do(t, newServer(t, st, "", nil), "GET", entityPath("asset", lookAsset, "testnet"), "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	raw := rec.Body.String()
	got := decode[EntitySignal](t, rec)
	if got.SignalLevel != signal.Caution {
		t.Errorf("signal_level = %s, want caution", got.SignalLevel)
	}
	if got.Entity != (Entity{Network: "testnet", Type: "asset", Key: lookAsset}) {
		t.Errorf("entity = %+v", got.Entity)
	}
	if got.AsOf != "2026-10-28T09:30:15Z" || got.RulesetVersion != verdict.V1.Version {
		t.Errorf("as_of %q ruleset %q", got.AsOf, got.RulesetVersion)
	}
	if got.Disputed == nil || *got.Disputed {
		t.Errorf("disputed = %v, want false", got.Disputed)
	}
	want := map[string]string{
		"known_asset": refAsset, "known_issuer": refIssuer,
		"issuer": lookIssuer, "asset": lookAsset, "home_domain": "issuer.example",
		"as_of": "2026-10-28T09:30:15Z",
	}
	if fmt.Sprint(got.Facts) != fmt.Sprint(want) {
		t.Errorf("facts = %v\nwant    %v", got.Facts, want)
	}
	// Every shipped template is a draft: rendering fails closed.
	if got.Statements == nil || len(got.Statements) != 0 {
		t.Errorf("statements = %v, want empty array", got.Statements)
	}
	if !strings.Contains(raw, `"statements":[]`) {
		t.Error("statements must serialize as [] (required by the schema)")
	}
}

func TestUnknownEntityNoSignals(t *testing.T) {
	st := &fakeStore{}
	rec := do(t, newServer(t, st, "", nil), "GET", entityPath("account", gKey(9), "public"), "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	got := decode[EntitySignal](t, rec)
	if got.SignalLevel != signal.NoSignals || got.AsOf != "2026-10-28T12:00:00Z" {
		t.Errorf("got %+v", got)
	}
	if len(got.Facts) != 0 || len(got.Statements) != 0 || got.Disputed != nil || got.RulesetVersion != "" {
		t.Errorf("unknown entity must carry no facts or verdict fields: %+v", got)
	}
}

func TestNoActiveVerdictLevelsMapToPublicNames(t *testing.T) {
	for internal, public := range map[signal.Internal]signal.Public{
		signal.Benign: signal.Consistent, signal.Unknown: signal.NoSignals,
		signal.Suspicious: signal.Caution, signal.Malicious: signal.HighCaution,
	} {
		res := lookalikeResult(t)
		res.Verdict.Level = internal
		st := &fakeStore{results: map[string]store.LookupResult{"testnet|asset|" + lookAsset: res}}
		rec := do(t, newServer(t, st, "", nil), "GET", entityPath("asset", lookAsset, "testnet"), "", nil)
		if got := decode[EntitySignal](t, rec); got.SignalLevel != public {
			t.Errorf("%s -> %s, want %s", internal, got.SignalLevel, public)
		}
	}
}

func TestUnmappedLevelFailsLoud(t *testing.T) {
	res := lookalikeResult(t)
	res.Verdict.Level = "corrupt"
	st := &fakeStore{results: map[string]store.LookupResult{"testnet|asset|" + lookAsset: res}}
	rec := do(t, newServer(t, st, "", nil), "GET", entityPath("asset", lookAsset, "testnet"), "", nil)
	if rec.Code != http.StatusInternalServerError || errorCode(t, rec) != codeInternal {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestStoreErrorsAreNeverNoSignals(t *testing.T) {
	for err, want := range map[error]int{
		errors.New("connection refused"):                  http.StatusInternalServerError,
		fmt.Errorf("query: %w", context.DeadlineExceeded): http.StatusServiceUnavailable,
	} {
		st := &fakeStore{err: err}
		rec := do(t, newServer(t, st, "", nil), "GET", entityPath("account", gKey(9), "public"), "", nil)
		if rec.Code != want || strings.Contains(rec.Body.String(), "no_signals") {
			t.Errorf("%v: status %d body %s", err, rec.Code, rec.Body)
		}
	}
}

// Response bytes never contain internal levels or internal verdict fields,
// whatever the internal state.
func TestResponsesCarryNoInternalVocabulary(t *testing.T) {
	forbidden := []string{"benign", "suspicious", "malicious", `"unknown"`, "safe",
		"rule_id", "R-AUTOMATED", "lookalike_asset", "category", "evidence_ids", "decided_by",
		"analyst-internal-7", "reason", "asset_not_listed", "toml_url", "max_level", "status"}
	for _, lvl := range []signal.Internal{signal.Benign, signal.Unknown, signal.Suspicious, signal.Malicious} {
		for _, disputed := range []bool{false, true} {
			res := lookalikeResult(t)
			res.Verdict.Level, res.Verdict.Disputed = lvl, disputed
			st := &fakeStore{results: map[string]store.LookupResult{"testnet|asset|" + lookAsset: res}}
			h := newServer(t, st, "", approvedRenderer(t))
			single := do(t, h, "GET", entityPath("asset", lookAsset, "testnet"), "", nil).Body.String()
			batch := do(t, h, "POST", "/v1/entities:batchGet", "application/json",
				batchBody(t, Entity{"testnet", "asset", lookAsset}, Entity{"public", "account", gKey(9)})).Body.String()
			for _, body := range []string{single, batch} {
				for _, term := range forbidden {
					if strings.Contains(strings.ToLower(body), strings.ToLower(term)) {
						t.Errorf("level %s disputed %v: response contains %q: %s", lvl, disputed, term, body)
					}
				}
			}
		}
	}
}

func TestMuxedAccountIsNormalized(t *testing.T) {
	g := gKey(5)
	st := &fakeStore{}
	rec := do(t, newServer(t, st, "", nil), "GET", entityPath("account", mKey(t, g, 42), "testnet"), "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if got := decode[EntitySignal](t, rec); got.Entity.Key != g {
		t.Errorf("entity key = %s, want %s", got.Entity.Key, g)
	}
	if len(st.asked) != 1 || st.asked[0].Key != g {
		t.Errorf("store asked for %+v", st.asked)
	}
}

func TestInvalidInputIsRejectedWithoutReflection(t *testing.T) {
	g := gKey(5)
	badChecksum := g[:55] + map[bool]string{true: "A", false: "B"}[g[55] != 'A']
	muxed := mKey(t, g, 1)
	cases := []struct {
		name, path, code string
	}{
		{"unknown network", entityPath("account", g, "futurenet"), "unknown_network"},
		{"missing network", "/v1/entities/account/" + g, "unknown_network"},
		{"repeated network", entityPath("account", g, "public") + "&network=testnet", codeInvalidQuery},
		{"bad query", "/v1/entities/account/" + g + "?network=%zz", codeInvalidQuery},
		{"unknown type", entityPath("liquidity_pool", g, "public"), "unknown_type"},
		{"bad checksum", entityPath("account", badChecksum, "public"), "invalid_key"},
		{"lowercase account", entityPath("account", strings.ToLower(g), "public"), "invalid_key"},
		{"corrupt muxed", entityPath("account", muxed[:len(muxed)-1]+"A", "public"), "invalid_key"},
		{"muxed issuer", entityPath("asset", "USDC:"+muxed, "public"), "muxed_not_normalized"},
		{"contract checksum", entityPath("contract", cKey(3)[:55]+"Q", "public"), "invalid_key"},
		{"asset code too long", entityPath("asset", "ABCDEFGHIJKLM:"+g, "public"), "invalid_key"},
		{"non-ascii domain", entityPath("domain", "exämple.com", "public"), "non_ascii"},
		{"bidi domain", entityPath("domain", "example‮.com", "public"), "non_ascii"},
		{"slash in id", "/v1/entities/domain/" + "a%2Fb.com?network=public", "invalid_key"},
		{"oversized key", entityPath("domain", strings.Repeat("a", 400)+".com", "public"), "invalid_key"},
		{"script", entityPath("domain", "<script>alert(1)</script>", "public"), "invalid_key"},
	}
	h := newServer(t, &fakeStore{}, "", nil)
	for _, c := range cases {
		rec := do(t, h, "GET", c.path, "", nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", c.name, rec.Code)
			continue
		}
		body := rec.Body.String()
		if got := errorCode(t, rec); got != c.code {
			t.Errorf("%s: code %q, want %q", c.name, got, c.code)
		}
		for _, echo := range []string{g, "futurenet", "liquidity_pool", "script", "ABCDEFGHIJKLM", "exämple"} {
			if strings.Contains(body, echo) {
				t.Errorf("%s: error body reflects input %q", c.name, echo)
			}
		}
	}
	// The contract case above must fail on the checksum, not the shape.
	if _, err := entity.NormalizeKey(entity.Contract, cKey(3)[:55]+"Q"); err != nil {
		t.Fatalf("contract fixture should be well-shaped: %v", err)
	}
}

func batchBody(t *testing.T, es ...Entity) []byte {
	t.Helper()
	b, err := json.Marshal(batchRequest{Entities: es})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBatchReturnsResultsInRequestOrder(t *testing.T) {
	st := &fakeStore{results: map[string]store.LookupResult{"testnet|asset|" + lookAsset: lookalikeResult(t)}}
	g := gKey(5)
	body := batchBody(t,
		Entity{"public", "account", g},
		Entity{"testnet", "asset", lookAsset},
		Entity{"testnet", "account", mKey(t, g, 7)},
		Entity{"testnet", "asset", lookAsset},
		Entity{"public", "domain", "Example.COM."},
	)
	rec := do(t, newServer(t, st, "", nil), "POST", "/v1/entities:batchGet", "application/json; charset=utf-8", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	got := decode[batchResponse](t, rec).Results
	want := []struct {
		key   string
		level signal.Public
	}{
		{g, signal.NoSignals}, {lookAsset, signal.Caution}, {g, signal.NoSignals},
		{lookAsset, signal.Caution}, {"example.com", signal.NoSignals},
	}
	if len(got) != len(want) {
		t.Fatalf("%d results, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Entity.Key != w.key || got[i].SignalLevel != w.level {
			t.Errorf("result %d = %s %s, want %s %s", i, got[i].Entity.Key, got[i].SignalLevel, w.key, w.level)
		}
	}
}

func TestBatchLimits(t *testing.T) {
	g := gKey(5)
	many := func(n int) []byte {
		es := make([]Entity, n)
		for i := range es {
			es[i] = Entity{"public", "account", g}
		}
		return batchBody(t, es...)
	}
	cases := []struct {
		name, contentType string
		body              []byte
		status            int
		code              string
	}{
		{"100 entities", "application/json", many(100), http.StatusOK, ""},
		{"101 entities", "application/json", many(101), http.StatusBadRequest, codeTooManyEntities},
		{"empty list", "application/json", []byte(`{"entities":[]}`), http.StatusBadRequest, codeInvalidBody},
		{"null list", "application/json", []byte(`{"entities":null}`), http.StatusBadRequest, codeInvalidBody},
		{"no body", "application/json", nil, http.StatusBadRequest, codeInvalidBody},
		{"unknown field", "application/json", []byte(`{"entities":[{"network":"public","type":"account","key":"` + g + `","level":"x"}]}`), http.StatusBadRequest, codeInvalidBody},
		{"trailing data", "application/json", append(many(1), []byte(`{}`)...), http.StatusBadRequest, codeInvalidBody},
		{"oversized body", "application/json", []byte(`{"entities":[` + strings.Repeat(" ", MaxBodyBytes) + `]}`), http.StatusRequestEntityTooLarge, codeBodyTooLarge},
		{"wrong media type", "text/plain", many(1), http.StatusUnsupportedMediaType, codeUnsupportedMedia},
		{"no media type", "", many(1), http.StatusUnsupportedMediaType, codeUnsupportedMedia},
		{"invalid entity", "application/json", batchBody(t, Entity{"public", "account", g}, Entity{"public", "account", "M123"}), http.StatusBadRequest, "invalid_key"},
		{"unknown network", "application/json", batchBody(t, Entity{"pubnet", "account", g}), http.StatusBadRequest, "unknown_network"},
	}
	for _, c := range cases {
		st := &fakeStore{}
		rec := do(t, newServer(t, st, "", nil), "POST", "/v1/entities:batchGet", c.contentType, c.body)
		if rec.Code != c.status {
			t.Errorf("%s: status %d, want %d (%s)", c.name, rec.Code, c.status, rec.Body)
			continue
		}
		if c.code != "" {
			if got := errorCode(t, rec); got != c.code {
				t.Errorf("%s: code %q, want %q", c.name, got, c.code)
			}
			if len(st.asked) != 0 {
				t.Errorf("%s: store was queried for a rejected request", c.name)
			}
		}
	}
}

func TestRoutingErrorsAreJSONWithSecurityHeaders(t *testing.T) {
	h := newServer(t, &fakeStore{}, "", nil)
	cases := []struct {
		method, path string
		status       int
		code         string
	}{
		{"GET", "/v1/nope", http.StatusNotFound, codeNotFound},
		{"GET", "/", http.StatusNotFound, codeNotFound},
		{"POST", entityPath("account", gKey(5), "public"), http.StatusMethodNotAllowed, codeMethodNotAllowed},
		{"GET", "/v1/entities:batchGet", http.StatusMethodNotAllowed, codeMethodNotAllowed},
		{"DELETE", "/v1/snapshots/latest?network=public", http.StatusMethodNotAllowed, codeMethodNotAllowed},
	}
	for _, c := range cases {
		rec := do(t, h, c.method, c.path, "application/json", nil)
		if rec.Code != c.status || errorCode(t, rec) != c.code {
			t.Errorf("%s %s: %d", c.method, c.path, rec.Code)
		}
		for k, v := range map[string]string{
			"Content-Type":           "application/json",
			"X-Content-Type-Options": "nosniff",
			"Cache-Control":          "no-store",
			"X-Frame-Options":        "DENY",
		} {
			if got := rec.Header().Get(k); got != v {
				t.Errorf("%s %s: %s = %q, want %q", c.method, c.path, k, got, v)
			}
		}
	}
}

func TestPanicIsInternalErrorAndNotLogged(t *testing.T) {
	var logs bytes.Buffer
	reg, _ := wording.LoadEmbedded()
	rnd, _ := wording.NewRenderer(reg, testRenderConfig)
	s, err := New(Config{Store: panicStore{&fakeStore{}}, Renderer: rnd, SnapshotDir: t.TempDir(),
		Log: slogTo(&logs)})
	if err != nil {
		t.Fatal(err)
	}
	g := gKey(5)
	rec := do(t, s.Handler(), "GET", entityPath("account", g, "public"), "", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(logs.String(), g) || strings.Contains(logs.String(), "secret-panic-value") {
		t.Errorf("logs contain request data: %s", logs.String())
	}
	if !strings.Contains(logs.String(), `"route":"/v1/entities/{type}/{id}"`) {
		t.Errorf("access log should name the route pattern: %s", logs.String())
	}
}

// TestLogsCarryNoRequestData covers intel #54's third acceptance criterion at the
// API boundary: the log describes the route, never what the client asked about.
// Every way a client can supply a string is loaded with something recognisable,
// and the run is repeated against a failing store so the error line is checked
// too, not only the access line. An address in a log is an address in a search
// index, a ticket, or someone's terminal scrollback (AGENTS.md §6).
func TestLogsCarryNoRequestData(t *testing.T) {
	addr := gKey(7)
	contract := cKey(8)
	muxed := mKey(t, addr, 4242)
	domain := "give-us-your-secret-keys.example"
	asset := "USD1:" + addr
	blob := base64.StdEncoding.EncodeToString([]byte("an-enum-encoding-of-a-transaction-envelope"))

	cases := []struct {
		method, target string
		body           string
	}{
		{"GET", entityPath("account", addr, "public"), ""},
		{"GET", entityPath("account", muxed, "public"), ""},
		{"GET", entityPath("contract", contract, "public"), ""},
		{"GET", entityPath("asset", asset, "public"), ""},
		{"GET", "/v1/entities/account/" + addr + "?network=" + domain, ""},
		{"GET", "/v1/snapshots/latest?network=public&cursor=" + blob, ""},
		{"GET", "/v1/snapshots/4294967296?network=public&cursor=" + blob, ""},
		{"GET", "/v1/entities/account/..%2F..%2Fetc%2Fpasswd?network=public", ""},
		{"GET", "/v1/entities/account/" + strings.Repeat("A", 4096) + "?network=public", ""},
		{"POST", "/v1/entities:batchGet", `{"keys":[{"network":"public","type":"account","key":"` + addr + `"}]}`},
		{"POST", "/v1/entities:batchGet", blob},
	}
	for _, failing := range []bool{false, true} {
		var logs bytes.Buffer
		reg, _ := wording.LoadEmbedded()
		rnd, _ := wording.NewRenderer(reg, testRenderConfig)
		st := &fakeStore{results: map[string]store.LookupResult{}, snapshots: map[string]store.SnapshotRecord{}}
		if failing {
			st.err = errors.New("store: connection reset by peer")
		}
		s, err := New(Config{Store: st, Renderer: rnd, SnapshotDir: t.TempDir(), Log: slogTo(&logs)})
		if err != nil {
			t.Fatal(err)
		}
		h := s.Handler()
		for _, c := range cases {
			rec := do(t, h, c.method, c.target, "application/json", []byte(c.body))
			if rec.Code >= 500 && !failing {
				t.Errorf("%s %s: status %d with a working store", c.method, c.target, rec.Code)
			}
		}
		text := logs.String()
		for _, hostile := range []string{addr, muxed, contract, asset, domain, blob} {
			if strings.Contains(text, hostile) {
				t.Errorf("store failing=%v: a log line contains request data %q\n%s", failing, hostile, text)
			}
		}
		// Positive controls, so the absence above is about the code and not about
		// a run that logged nothing at all.
		for _, want := range []string{`"route":"/v1/entities/{type}/{id}"`, `"route":"/v1/snapshots/{version}"`, `"route":"/v1/entities:batchGet"`} {
			if !strings.Contains(text, want) {
				t.Errorf("store failing=%v: no access line for %s\n%s", failing, want, text)
			}
		}
		if failing && !strings.Contains(text, "store read failed") {
			t.Errorf("a store failure logged no error line: %s", text)
		}
	}
}

type panicStore struct{ *fakeStore }

func (panicStore) LookupEntities(context.Context, []store.LookupKey) ([]store.LookupResult, error) {
	panic("secret-panic-value")
}

// --- snapshots ---

type snapFixture struct {
	dir string
	st  *fakeStore
	raw map[uint64][]byte
}

func writeSnapshots(t *testing.T, n entity.Network, versions ...uint64) snapFixture {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := snapshot.NewEd25519Signer("intel-test-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	f := snapFixture{dir: t.TempDir(), st: &fakeStore{snapshots: map[string]store.SnapshotRecord{}}, raw: map[uint64][]byte{}}
	for _, v := range versions {
		gen := testNow.Add(time.Duration(v) * time.Minute)
		s, err := snapshot.Build(snapshot.Input{Network: n, Version: v, GeneratedAt: gen, RulesetVersion: verdict.V1.Version,
			Entities: []snapshot.Entity{{Type: entity.Asset, Key: lookAsset}}}, signer)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(s)
		body = append(body, '\n')
		name := pipeline.VersionedName(n, v)
		if err := os.WriteFile(filepath.Join(f.dir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
		sig, _ := base64.StdEncoding.DecodeString(s.Signature)
		rec := store.SnapshotRecord{Network: n, Version: v, GeneratedAt: gen, RulesetVersion: verdict.V1.Version,
			EntryCount: len(s.Entries), ObjectKey: name, SigningKeyID: s.KeyID, Signature: sig}
		f.st.snapshots[fmt.Sprintf("%s|%d", n, v)] = rec
		f.st.snapshots[fmt.Sprintf("%s|0", n)] = rec
		f.raw[v] = body
	}
	return f
}

func TestSnapshotLatestAndVersionAreServedVerbatim(t *testing.T) {
	f := writeSnapshots(t, entity.Testnet, 1, 2)
	h := newServer(t, f.st, f.dir, nil)
	for _, c := range []struct {
		path  string
		want  uint64
		cache string
	}{
		{"/v1/snapshots/latest?network=testnet", 2, "public, max-age=60"},
		{"/v1/snapshots/1?network=testnet", 1, "public, max-age=31536000, immutable"},
		{"/v1/snapshots/2?network=testnet", 2, "public, max-age=31536000, immutable"},
	} {
		for range 2 { // second request comes from the cache
			rec := do(t, h, "GET", c.path, "", nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: status %d %s", c.path, rec.Code, rec.Body)
			}
			if !bytes.Equal(rec.Body.Bytes(), f.raw[c.want]) {
				t.Errorf("%s: body is not the published file", c.path)
			}
			if rec.Header().Get("Cache-Control") != c.cache || rec.Header().Get("Content-Type") != "application/json" {
				t.Errorf("%s: headers %v", c.path, rec.Header())
			}
		}
	}
}

func TestSnapshotErrors(t *testing.T) {
	f := writeSnapshots(t, entity.Testnet, 1)
	h := newServer(t, f.st, f.dir, nil)
	cases := []struct {
		path   string
		status int
		code   string
	}{
		{"/v1/snapshots/latest?network=public", http.StatusNotFound, codeNotFound},
		{"/v1/snapshots/9?network=testnet", http.StatusNotFound, codeNotFound},
		{"/v1/snapshots/latest", http.StatusBadRequest, "unknown_network"},
		{"/v1/snapshots/1?network=futurenet", http.StatusBadRequest, "unknown_network"},
		{"/v1/snapshots/0?network=testnet", http.StatusBadRequest, codeInvalidVersion},
		{"/v1/snapshots/01?network=testnet", http.StatusBadRequest, codeInvalidVersion},
		{"/v1/snapshots/-1?network=testnet", http.StatusBadRequest, codeInvalidVersion},
		{"/v1/snapshots/1e3?network=testnet", http.StatusBadRequest, codeInvalidVersion},
		{"/v1/snapshots/+1?network=testnet", http.StatusBadRequest, codeInvalidVersion},
		{"/v1/snapshots/99999999999999999999?network=testnet", http.StatusBadRequest, codeInvalidVersion},
		{"/v1/snapshots/9223372036854775808?network=testnet", http.StatusBadRequest, codeInvalidVersion},
		{"/v1/snapshots/..%2F..%2Fetc?network=testnet", http.StatusBadRequest, codeInvalidVersion},
	}
	for _, c := range cases {
		rec := do(t, h, "GET", c.path, "", nil)
		if rec.Code != c.status || errorCode(t, rec) != c.code {
			t.Errorf("%s: %d %s", c.path, rec.Code, rec.Body)
		}
	}
}

// A recorded snapshot whose file is missing, altered or misnamed is never served.
func TestSnapshotFileMustMatchItsRecord(t *testing.T) {
	cases := map[string]func(f snapFixture){
		"missing file": func(f snapFixture) {
			os.Remove(filepath.Join(f.dir, pipeline.VersionedName(entity.Testnet, 1)))
		},
		"other signature": func(f snapFixture) {
			r := f.st.snapshots["testnet|1"]
			r.Signature = bytes.Repeat([]byte{1}, 64)
			f.st.snapshots["testnet|1"] = r
		},
		"altered entries": func(f snapFixture) {
			p := filepath.Join(f.dir, pipeline.VersionedName(entity.Testnet, 1))
			b, _ := os.ReadFile(p)
			os.WriteFile(p, bytes.Replace(b, []byte(`"entries":["`), []byte(`"entries":["00000000000000000000000000000000","`), 1), 0o644)
		},
		"extra field": func(f snapFixture) {
			p := filepath.Join(f.dir, pipeline.VersionedName(entity.Testnet, 1))
			b, _ := os.ReadFile(p)
			os.WriteFile(p, bytes.Replace(b, []byte(`{`), []byte(`{"note":"x",`), 1), 0o644)
		},
		"object key elsewhere": func(f snapFixture) {
			r := f.st.snapshots["testnet|1"]
			r.ObjectKey = "../../etc/passwd"
			f.st.snapshots["testnet|1"] = r
		},
		"other ruleset": func(f snapFixture) {
			r := f.st.snapshots["testnet|1"]
			r.RulesetVersion = "2027.01.1"
			f.st.snapshots["testnet|1"] = r
		},
	}
	for name, breakIt := range cases {
		f := writeSnapshots(t, entity.Testnet, 1)
		breakIt(f)
		var logs bytes.Buffer
		reg, _ := wording.LoadEmbedded()
		rnd, _ := wording.NewRenderer(reg, testRenderConfig)
		s, _ := New(Config{Store: f.st, Renderer: rnd, SnapshotDir: f.dir, Log: slogTo(&logs)})
		rec := do(t, s.Handler(), "GET", "/v1/snapshots/1?network=testnet", "", nil)
		if rec.Code != http.StatusServiceUnavailable || errorCode(t, rec) != codeUnavailable {
			t.Errorf("%s: status %d", name, rec.Code)
		}
		if !strings.Contains(logs.String(), `"alert":true`) {
			t.Errorf("%s: no alert logged", name)
		}
	}
}

func TestHTTPServerHasTimeouts(t *testing.T) {
	hs := HTTPServer(":0", http.NotFoundHandler(), slogTo(io.Discard))
	if hs.ReadHeaderTimeout <= 0 || hs.ReadTimeout <= 0 || hs.WriteTimeout <= 0 || hs.IdleTimeout <= 0 || hs.MaxHeaderBytes <= 0 {
		t.Errorf("server timeouts must all be set: %+v", hs)
	}
}
