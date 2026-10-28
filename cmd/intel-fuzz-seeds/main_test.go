package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/xdrcompat"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/xdrcompat/xdrtest"
)

// fakeSource serves pre-built ledgers and records what was asked for.
type fakeSource struct {
	passphrase string
	ledgers    map[uint32]ingest.RawLedger
	oldest     uint32
	latest     uint32
	asked      []uint32
}

func (f *fakeSource) NetworkPassphrase(context.Context) (string, error) {
	if f.passphrase == "" {
		return "", errors.New("no network")
	}
	return f.passphrase, nil
}

func (f *fakeSource) Range(context.Context) (ingest.Range, error) {
	return ingest.Range{Oldest: f.oldest, Latest: f.latest}, nil
}

func (f *fakeSource) Ledgers(_ context.Context, start, limit uint32) ([]ingest.RawLedger, error) {
	f.asked = append(f.asked, start)
	var out []ingest.RawLedger
	for s := start; s < start+limit; s++ {
		if l, ok := f.ledgers[s]; ok {
			out = append(out, l)
		}
	}
	return out, nil
}

// withModule builds one ledger that writes code as a ContractCode entry.
func withModule(seq uint32, code []byte) ingest.RawLedger {
	l := xdrtest.Ledger{Seq: seq, Prev: xdrtest.Hash(seq - 1),
		Ops: []xdr.LedgerEntryChanges{{xdrtest.Created(xdrtest.ContractModule(code))}},
	}
	return ingest.RawLedger{Sequence: seq, Hash: "unused", Meta: l.Bytes()}
}

// withoutModule is a ledger that touched no contract.
func withoutModule(seq uint32) ingest.RawLedger {
	l := xdrtest.Ledger{Seq: seq, Prev: xdrtest.Hash(seq - 1),
		Ops: []xdr.LedgerEntryChanges{{xdrtest.Created(xdrtest.Trustline(1, "USDC", 2))}},
	}
	return ingest.RawLedger{Sequence: seq, Hash: "unused", Meta: l.Bytes()}
}

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
}

func TestRunWritesModulesByNameAndCountsDuplicates(t *testing.T) {
	dir := t.TempDir()
	a, b := []byte("\x00asm\x01\x00\x00\x00alpha"), []byte("\x00asm\x01\x00\x00\x00bravo")
	src := &fakeSource{
		passphrase: ingest.TestnetPassphrase, oldest: 10, latest: 13,
		ledgers: map[uint32]ingest.RawLedger{
			10: withModule(10, a),
			11: withoutModule(11),
			12: withModule(12, a), // same module redeployed: deduplicated
			13: withModule(13, b),
		},
	}
	o := &options{url: "https://x", out: dir, span: 4, page: 2, maxModules: 100,
		maxModuleBytes: 1 << 20, maxTotalBytes: 1 << 24}
	s, err := run(context.Background(), src, o, quietLog())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if s.LedgersRead != 4 || s.ModulesSeen != 3 || s.Written != 2 || s.Duplicates != 1 {
		t.Errorf("stats = %+v, want 4 ledgers, 3 seen, 2 written, 1 duplicate", s)
	}
	if s.StoppedBy != "range" {
		t.Errorf("StoppedBy = %q, want range", s.StoppedBy)
	}
	if s.Bytes != int64(len(a)+len(b)) {
		t.Errorf("Bytes = %d, want %d", s.Bytes, len(a)+len(b))
	}
	names, err := filepath.Glob(filepath.Join(dir, "*.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("wrote %d files, want 2", len(names))
	}
	got := map[string]bool{}
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		got[string(b)] = true
		if base := filepath.Base(n); len(base) != 69 || !strings.HasSuffix(base, ".wasm") {
			t.Errorf("file name %q is not <64-hex>.wasm", base)
		}
	}
	if !got[string(a)] || !got[string(b)] {
		t.Errorf("content set = %v, want both modules", got)
	}
}

func TestRunIsAdditiveAcrossRuns(t *testing.T) {
	dir := t.TempDir()
	a := []byte("\x00asm\x01\x00\x00\x00one")
	src := &fakeSource{passphrase: ingest.PublicPassphrase, oldest: 5, latest: 5,
		ledgers: map[uint32]ingest.RawLedger{5: withModule(5, a)}}
	o := &options{out: dir, span: 1, page: 1, maxModules: 10, maxModuleBytes: 1 << 20, maxTotalBytes: 1 << 20}
	if _, err := run(context.Background(), src, o, quietLog()); err != nil {
		t.Fatal(err)
	}
	s, err := run(context.Background(), src, o, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if s.Written != 0 || s.AlreadyPresent != 1 {
		t.Errorf("second run: written=%d already_present=%d, want 0 and 1", s.Written, s.AlreadyPresent)
	}
}

func TestRunRefusesAnUnknownNetwork(t *testing.T) {
	src := &fakeSource{passphrase: "Some Other Network ; 2030"}
	s, err := run(context.Background(), src, &options{out: t.TempDir(), span: 1, page: 1,
		maxModules: 1, maxModuleBytes: 1, maxTotalBytes: 1}, quietLog())
	if !errors.Is(err, errUnknownNetwork) {
		t.Fatalf("err = %v, want errUnknownNetwork", err)
	}
	if s.LedgersRead != 0 || len(src.asked) != 0 {
		t.Errorf("read %d ledgers after %d requests; must not fetch at all", s.LedgersRead, len(src.asked))
	}
}

func TestRunHaltsOnAMissingLedger(t *testing.T) {
	dir := t.TempDir()
	// Ledger 12 is absent from the source: a gap, not a quiet ledger.
	src := &fakeSource{passphrase: ingest.TestnetPassphrase, oldest: 11, latest: 13,
		ledgers: map[uint32]ingest.RawLedger{11: withoutModule(11), 13: withoutModule(13)}}
	_, err := run(context.Background(), src, &options{out: dir, span: 3, page: 3,
		maxModules: 10, maxModuleBytes: 1 << 20, maxTotalBytes: 1 << 20}, quietLog())
	if !errors.Is(err, ingest.ErrGap) {
		t.Fatalf("err = %v, want ingest.ErrGap", err)
	}
}

// A ledger this build cannot decode must stop the run: a seed corpus that is
// silently missing the newest protocols looks complete and is not.
func TestRunHaltsOnUndecodableLedger(t *testing.T) {
	dir := t.TempDir()
	bad := xdrtest.Ledger{Seq: 12, Prev: xdrtest.Hash(11), Protocol: xdrcompat.MaxProtocol + 1}
	src := &fakeSource{passphrase: ingest.TestnetPassphrase, oldest: 11, latest: 12,
		ledgers: map[uint32]ingest.RawLedger{11: withModule(11, []byte("x")), 12: {Sequence: 12, Meta: bad.Bytes()}}}
	s, err := run(context.Background(), src, &options{out: dir, span: 2, page: 2,
		maxModules: 10, maxModuleBytes: 1 << 20, maxTotalBytes: 1 << 20}, quietLog())
	if !errors.Is(err, xdrcompat.ErrUnsupportedProtocol) {
		t.Fatalf("err = %v, want ErrUnsupportedProtocol", err)
	}
	if s.Written != 1 {
		t.Logf("modules written before the halt: %d (additive output, no half file)", s.Written)
	}
}

func TestRunStopsAtCaps(t *testing.T) {
	cases := []struct {
		name string
		o    *options
		want string
	}{
		{"max_modules", nil, "max_modules"},
		{"max_bytes", nil, "max_bytes"},
	}
	for i, tc := range cases {
		dir := t.TempDir()
		code := bytes.Repeat([]byte{7}, 100)
		src := &fakeSource{passphrase: ingest.TestnetPassphrase, oldest: 1, latest: 4,
			ledgers: map[uint32]ingest.RawLedger{
				1: withModule(1, append(code, byte(i), 1)),
				2: withModule(2, append(code, byte(i), 2)),
				3: withModule(3, append(code, byte(i), 3)),
				4: withModule(4, append(code, byte(i), 4)),
			}}
		o := &options{out: dir, span: 4, page: 4, maxModules: 10,
			maxModuleBytes: 1 << 20, maxTotalBytes: 1 << 20}
		if tc.want == "max_modules" {
			o.maxModules = 2
		} else {
			o.maxTotalBytes = 150
		}
		s, err := run(context.Background(), src, o, quietLog())
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if s.StoppedBy != tc.want {
			t.Errorf("%s: StoppedBy = %q, want %q (written %d, bytes %d)", tc.name, s.StoppedBy, tc.want, s.Written, s.Bytes)
		}
	}
}

// An oversized module is counted and skipped, never truncated to fit.
func TestRunSkipsOversizedModules(t *testing.T) {
	dir := t.TempDir()
	src := &fakeSource{passphrase: ingest.TestnetPassphrase, oldest: 1, latest: 2,
		ledgers: map[uint32]ingest.RawLedger{
			1: withModule(1, bytes.Repeat([]byte{1}, 5000)),
			2: withModule(2, []byte("small")),
		}}
	s, err := run(context.Background(), src, &options{out: dir, span: 2, page: 2, maxModules: 10,
		maxModuleBytes: 1024, maxTotalBytes: 1 << 20}, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if s.Skipped != 1 || s.Written != 1 {
		t.Errorf("skipped=%d written=%d, want 1 and 1", s.Skipped, s.Written)
	}
}

func TestWriteModuleRejectsNonHexNames(t *testing.T) {
	dir := t.TempDir()
	for _, key := range []string{"", "../escape", strings.Repeat("g", 64), strings.Repeat("0", 63)} {
		if err := writeModule(dir, key, []byte("x")); err == nil {
			t.Errorf("writeModule accepted key %q", key)
		}
	}
	if files, _ := os.ReadDir(dir); len(files) != 0 {
		t.Errorf("hostile keys wrote %d files", len(files))
	}
}

func TestParseFlags(t *testing.T) {
	newFS := func() *flag.FlagSet {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(&bytes.Buffer{})
		return fs
	}
	o, err := parseFlags(newFS(), nil)
	if err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if o.span != defaultSpan || o.page != defaultPage || o.maxModules != defaultMaxModules || o.out != defaultOut {
		t.Errorf("defaults = %+v", o)
	}
	if o.url == "" || !strings.HasPrefix(o.url, "https://") {
		t.Errorf("url default = %q", o.url)
	}
	cases := [][]string{
		{"-span", "0"},
		{"-span", "100001"},
		{"-page", "0"},
		{"-page", "201"},
		{"-max-modules", "0"},
		{"-max-module-bytes", "0"},
		{"-max-total-bytes", "-1"},
		{"-from-ledger", "-5"},
		{"-from-ledger", "abc"},
		{"-span", "-1"},
		{"-unknown-flag", "1"},
	}
	for _, args := range cases {
		if _, err := parseFlags(newFS(), args); err == nil {
			t.Errorf("%v accepted, want an error", args)
		}
	}
	o, err = parseFlags(newFS(), []string{"-from-ledger", "42", "-span", "7", "-out", "/tmp/x", "-rpc-url", "https://rpc.example"})
	if err != nil {
		t.Fatalf("valid flags: %v", err)
	}
	if o.from != 42 || o.span != 7 || o.out != "/tmp/x" || o.url != "https://rpc.example" {
		t.Errorf("parsed = %+v", o)
	}
}

func TestBoundsUsesTheRetainedRange(t *testing.T) {
	src := &fakeSource{oldest: 100, latest: 1_000_100}
	from, to, err := bounds(context.Background(), src, &options{span: 500})
	if err != nil {
		t.Fatal(err)
	}
	if from != 999_601 || to != 1_000_100 {
		t.Errorf("from=%d to=%d, want the newest 500 ledgers", from, to)
	}
	if from, to, err = bounds(context.Background(), src, &options{from: 10, span: 3}); err != nil || from != 10 || to != 12 {
		t.Errorf("explicit start: from=%d to=%d err=%v", from, to, err)
	}
	// A span wider than retention clamps to what exists rather than inventing
	// ledgers the source never had.
	src2 := &fakeSource{oldest: 50, latest: 60}
	if from, to, err = bounds(context.Background(), src2, &options{span: 500}); err != nil || from != 50 || to != 60 {
		t.Errorf("clamped: from=%d to=%d err=%v, want 50..60", from, to, err)
	}
}

func TestPageLimitSplit(t *testing.T) {
	dir := t.TempDir()
	ledgers := map[uint32]ingest.RawLedger{}
	var seqs []uint32
	for s := uint32(1); s <= 5; s++ {
		ledgers[s] = withoutModule(s)
		seqs = append(seqs, s)
	}
	src := &fakeSource{passphrase: ingest.TestnetPassphrase, oldest: 1, latest: 5, ledgers: ledgers}
	s, err := run(context.Background(), src, &options{out: dir, span: 5, page: 2,
		maxModules: 10, maxModuleBytes: 1 << 20, maxTotalBytes: 1 << 20}, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if s.LedgersRead != 5 {
		t.Errorf("read %d ledgers, want 5", s.LedgersRead)
	}
	if want := []uint32{1, 3, 5}; !slices.Equal(src.asked, want) {
		t.Errorf("page starts = %v, want %v (last page must be clamped, not over-requested)", src.asked, want)
	}
}
