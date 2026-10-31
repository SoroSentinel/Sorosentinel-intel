// Command intel-fuzz-seeds writes deployed contract WASM, read from Stellar RPC
// ledger metadata, into a directory of .wasm files. It is the fetcher half of
// sorosentinel-scan issue #10: Scan depends on neither an HTTP client nor the
// Stellar XDR definitions and cannot fetch, while Intel already has both.
//
// Logs counts only: no module hash, address or transaction content is printed.
// Nothing here is evidence or a verdict - the files are parser inputs for
// `make fuzz`. Output is never committed; the default directory is gitignored.
//
// Run: go run ./cmd/intel-fuzz-seeds -out ../Sorosentinel-scan/fuzz/seeds/scan
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/source/rpc"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/xdrcompat"
)

const (
	defaultOut         = "seeds/wasm"
	defaultSpan        = 500       // ledgers walked when -from-ledger is absent
	defaultPage        = 20        // ledgers per getLedgers call
	defaultMaxModules  = 200       // files written per run
	defaultModuleBytes = 4 << 20   // larger modules are counted, not written
	defaultTotalBytes  = 256 << 20 // cap on bytes written per run
	maxSpan            = 100_000
	hashHexLen         = 64 // sha256 as hex, which names every output file
)

var (
	// errUnknownNetwork is a precondition failure, not a run failure: the
	// endpoint is not a network this repo knows.
	errUnknownNetwork = errors.New("intel-fuzz-seeds: endpoint serves an unknown network")
	// errAlreadyPresent marks a module whose file already exists on disk.
	errAlreadyPresent = errors.New("intel-fuzz-seeds: module already present")
)

// source is the part of the RPC client this command uses.
type source interface {
	NetworkPassphrase(ctx context.Context) (string, error)
	Range(ctx context.Context) (ingest.Range, error)
	Ledgers(ctx context.Context, start, limit uint32) ([]ingest.RawLedger, error)
}

type options struct {
	url, out       string
	from           uint32 // 0 = derive from the source's retained range
	span           uint32
	page           uint32
	maxModules     uint32
	maxModuleBytes int64
	maxTotalBytes  int64
}

type uintFlag struct{ dst *uint32 }

func (f uintFlag) String() string { return fmt.Sprint(*f.dst) }

// Set rejects negatives and overflow instead of wrapping them.
func (f uintFlag) Set(v string) error {
	var n int64
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return fmt.Errorf("not a number: %q", v)
	}
	if n < 0 || n > 1<<31-1 {
		return fmt.Errorf("outside 0..2147483647: %q", v)
	}
	*f.dst = uint32(n)
	return nil
}

func parseFlags(fs *flag.FlagSet, args []string) (*options, error) {
	o := &options{span: defaultSpan, page: defaultPage, maxModules: defaultMaxModules}
	fs.StringVar(&o.url, "rpc-url", rpc.DefaultTestnetURL, "Stellar RPC endpoint (https only)")
	fs.StringVar(&o.out, "out", defaultOut, "directory for <sha256>.wasm files")
	fs.Var(uintFlag{&o.from}, "from-ledger", "first ledger; default is the newest -span the source retains")
	fs.Var(uintFlag{&o.span}, "span", fmt.Sprintf("ledgers to walk (default %d)", defaultSpan))
	fs.Var(uintFlag{&o.page}, "page", fmt.Sprintf("ledgers per getLedgers call, 1-200 (default %d)", defaultPage))
	fs.Var(uintFlag{&o.maxModules}, "max-modules", fmt.Sprintf("largest number of files to write (default %d)", defaultMaxModules))
	maxModuleBytes := fs.Int64("max-module-bytes", defaultModuleBytes, "skip modules larger than this")
	maxTotalBytes := fs.Int64("max-total-bytes", defaultTotalBytes, "stop after writing this many bytes")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: intel-fuzz-seeds [-rpc-url URL] [-out DIR] [-from-ledger N] [-span N] [-page N] [-max-modules N] [-max-module-bytes N] [-max-total-bytes N]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	o.maxModuleBytes, o.maxTotalBytes = *maxModuleBytes, *maxTotalBytes
	switch {
	case o.span == 0 || o.span > maxSpan:
		return nil, fmt.Errorf("-span must be 1..%d", maxSpan)
	case o.page == 0 || o.page > 200:
		return nil, errors.New("-page must be 1..200")
	case o.maxModules == 0:
		return nil, errors.New("-max-modules must be at least 1")
	case o.maxModuleBytes <= 0, o.maxTotalBytes <= 0:
		return nil, errors.New("size caps must be positive")
	}
	return o, nil
}

// stats counts one run. Counts only, by design: the hashes are filenames and
// the ledgers are public, but neither belongs in a log line.
type stats struct {
	LedgersRead    int
	ModulesSeen    int
	Written        int
	Duplicates     int // same module twice in one run
	AlreadyPresent int // file left from an earlier run
	Skipped        int
	Bytes          int64
	StoppedBy      string
	FirstLedger    uint32
	LastLedger     uint32
}

// run walks the ledger range in pages and writes each module it has not seen,
// stopping at the caps. It returns an error rather than a partial result if any
// ledger is missing or cannot be decoded exactly by the pinned XDR: an
// incomplete corpus that looks complete is the failure mode to avoid, and it is
// the same halt condition ingestion uses (ARCHITECTURE §12 step 5).
func run(ctx context.Context, src source, o *options, log *slog.Logger) (stats, error) {
	var s stats
	pass, err := src.NetworkPassphrase(ctx)
	if err != nil {
		return s, err
	}
	switch pass {
	case ingest.TestnetPassphrase, ingest.PublicPassphrase:
	default:
		return s, fmt.Errorf("%w: refusing to fetch", errUnknownNetwork)
	}
	from, to, err := bounds(ctx, src, o)
	if err != nil {
		return s, err
	}
	s.FirstLedger, s.LastLedger = from, to
	if err := os.MkdirAll(o.out, 0o755); err != nil {
		return s, err
	}
	seen := map[string]bool{}

page:
	for start := from; start <= to; start += o.page {
		limit := o.page
		if rest := to - start + 1; rest < limit {
			limit = rest
		}
		ledgers, err := src.Ledgers(ctx, start, limit)
		if err != nil {
			return s, err
		}
		for i, l := range ledgers {
			want := start + uint32(i)
			if want > to {
				return s, fmt.Errorf("source returned %d ledgers for a page of %d", len(ledgers), limit)
			}
			if l.Sequence != want {
				return s, fmt.Errorf("%w: expected ledger %d, got %d", ingest.ErrGap, want, l.Sequence)
			}
			s.LedgersRead++
			modules, err := xdrcompat.Modules(l.Meta)
			if err != nil {
				return s, fmt.Errorf("ledger %d: %w", l.Sequence, err)
			}
			for _, m := range modules {
				s.ModulesSeen++
				key := hex.EncodeToString(m.Hash[:])
				if seen[key] {
					s.Duplicates++
					continue
				}
				seen[key] = true
				if int64(len(m.Code)) > o.maxModuleBytes {
					s.Skipped++
					continue
				}
				if uint32(s.Written) >= o.maxModules {
					s.StoppedBy = "max_modules"
					break page
				}
				if s.Bytes+int64(len(m.Code)) > o.maxTotalBytes {
					s.StoppedBy = "max_bytes"
					break page
				}
				switch err := writeModule(o.out, key, m.Code); {
				case errors.Is(err, errAlreadyPresent):
					s.AlreadyPresent++
				case err != nil:
					return s, err
				default:
					s.Written++
					s.Bytes += int64(len(m.Code))
				}
			}
		}
	}
	if s.StoppedBy == "" {
		s.StoppedBy = "range"
	}
	log.Info("intel-fuzz-seeds", "ledgers", s.LedgersRead, "modules_seen", s.ModulesSeen,
		"written", s.Written, "duplicates", s.Duplicates, "already_present", s.AlreadyPresent,
		"skipped_too_large", s.Skipped, "bytes", s.Bytes, "stopped_by", s.StoppedBy, "out", o.out)
	return s, nil
}

// bounds resolves the ledger range to walk: the requested start, or the newest
// -span ledgers the source still retains (RPC keeps about 7 days).
func bounds(ctx context.Context, src source, o *options) (from, to uint32, err error) {
	if o.from != 0 {
		return o.from, o.from + o.span - 1, nil
	}
	r, err := src.Range(ctx)
	if err != nil {
		return 0, 0, err
	}
	if r.Latest == 0 {
		return 0, 0, errors.New("source reports no ledgers")
	}
	to = r.Latest
	if to-r.Oldest+1 > o.span {
		from = to - o.span + 1
	} else {
		from = r.Oldest
	}
	return from, to, nil
}

// writeModule writes <out>/<hash>.wasm atomically. An existing file is left
// untouched and reported as errAlreadyPresent, so runs are additive and a re-run
// costs no network for modules already collected.
func writeModule(out, key string, code []byte) error {
	// key comes from ledger bytes, so it is re-verified here: a name that is
	// not exactly 64 hex chars must not reach filepath.Join.
	if len(key) != hashHexLen {
		return fmt.Errorf("module name %q is not %d characters", key, hashHexLen)
	}
	for _, r := range key {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return fmt.Errorf("module name %q is not hexadecimal", key)
		}
	}
	p := filepath.Join(out, key+".wasm")
	if _, err := os.Stat(p); err == nil {
		return errAlreadyPresent
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, code, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	o, err := parseFlags(flag.CommandLine, os.Args[1:])
	if err != nil {
		log.Error("intel-fuzz-seeds: bad flags", "err", err)
		os.Exit(2)
	}
	src, err := rpc.New(rpc.Config{URL: o.url})
	if err != nil {
		log.Error("intel-fuzz-seeds: bad config", "err", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s, err := run(ctx, src, o, log)
	if err != nil {
		// This is a one-shot dev tool: whoever runs it reads this stderr line
		// directly, so it carries no `alert`/`alert_id` fields. Those are the
		// monitored services' contract (internal/monitoring, intel #54).
		log.Error("intel-fuzz-seeds: stopped", "ledgers", s.LedgersRead, "written", s.Written,
			"unknown_network", errors.Is(err, errUnknownNetwork), "err", err)
		os.Exit(1)
	}
	if s.Written == 0 {
		log.Error("intel-fuzz-seeds: no contract WASM written", "ledgers", s.LedgersRead,
			"first", s.FirstLedger, "last", s.LastLedger)
		os.Exit(1)
	}
}
