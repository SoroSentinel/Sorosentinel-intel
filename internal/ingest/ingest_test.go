package ingest_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/source/rpc"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/xdrcompat"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/xdrcompat/xdrtest"
)

// fakeRPC serves getNetwork, getHealth and getLedgers from in-memory ledgers.
type fakeRPC struct {
	mu         sync.Mutex
	passphrase string
	oldest     uint32
	latest     uint32
	ledgers    map[uint32]served
	skip       map[uint32]bool // omitted from getLedgers pages (a gap)
	failNext   int             // next N requests get HTTP 500
	requests   int
}

type served struct {
	hash string
	meta []byte
}

func newFake(ls []xdrtest.Ledger) *fakeRPC {
	f := &fakeRPC{passphrase: ingest.TestnetPassphrase, ledgers: map[uint32]served{}, skip: map[uint32]bool{}}
	for _, l := range ls {
		f.put(l.Seq, xdrtest.Hash(l.Seq), l.Bytes())
	}
	return f
}

func (f *fakeRPC) put(seq uint32, h xdr.Hash, meta []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ledgers[seq] = served{hash: hex.EncodeToString(h[:]), meta: meta}
	if f.oldest == 0 || seq < f.oldest {
		f.oldest = seq
	}
	if seq > f.latest {
		f.latest = seq
	}
}

func (f *fakeRPC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	if f.failNext > 0 {
		f.failNext--
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var req struct {
		ID     uint64 `json:"id"`
		Method string `json:"method"`
		Params struct {
			StartLedger uint32 `json:"startLedger"`
			Pagination  struct {
				Limit uint32 `json:"limit"`
			} `json:"pagination"`
		} `json:"params"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	var result any
	switch req.Method {
	case "getNetwork":
		result = map[string]any{"passphrase": f.passphrase, "protocolVersion": 29}
	case "getHealth":
		result = map[string]any{"status": "healthy", "oldestLedger": f.oldest, "latestLedger": f.latest}
	case "getLedgers":
		if req.Params.StartLedger < f.oldest || req.Params.StartLedger > f.latest {
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"error":{"code":-32600,"message":"out of range"}}`, req.ID)
			return
		}
		var page []map[string]any
		for s := req.Params.StartLedger; s <= f.latest && uint32(len(page)) < req.Params.Pagination.Limit; s++ {
			l, ok := f.ledgers[s]
			if !ok || f.skip[s] {
				continue
			}
			page = append(page, map[string]any{
				"hash": l.hash, "sequence": s, "ledgerCloseTime": "0", "headerXdr": "",
				"metadataXdr": base64.StdEncoding.EncodeToString(l.meta),
			})
		}
		result = map[string]any{"ledgers": page, "latestLedger": f.latest, "oldestLedger": f.oldest, "cursor": ""}
	}
	json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
}

func (f *fakeRPC) client(t *testing.T) *rpc.Client {
	t.Helper()
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	c, err := rpc.New(rpc.Config{URL: srv.URL, TLSConfig: srv.Client().Transport.(*http.Transport).TLSClientConfig})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// recordSink records every delivered ledger.
type recordSink struct {
	mu   sync.Mutex
	got  []ingest.LedgerFacts
	fail bool
}

func (s *recordSink) Ledger(_ context.Context, f ingest.LedgerFacts) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("sink down")
	}
	s.got = append(s.got, f)
	return nil
}

func (s *recordSink) seqs() []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []uint32
	for _, f := range s.got {
		out = append(out, f.Sequence)
	}
	return out
}

func newIngester(t *testing.T, src ingest.Source, cp ingest.Checkpoint, sink ingest.Sink, start uint32) *ingest.Ingester {
	t.Helper()
	in, err := ingest.New(ingest.Config{Network: entity.Testnet, StartLedger: start, PageSize: 3,
		PollInterval: time.Millisecond, MaxRetries: 3}, src, cp, sink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(in.Close)
	return in
}

// drain steps until caught up or an error.
func drain(in *ingest.Ingester) error {
	for {
		n, err := in.Step(context.Background())
		if err != nil || n == 0 {
			return err
		}
	}
}

func last(t *testing.T, cp ingest.Checkpoint) uint32 {
	t.Helper()
	s, _, err := cp.Last(context.Background(), entity.Testnet)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func lookalikeOps() map[uint32][]xdr.LedgerEntryChanges {
	return map[uint32][]xdr.LedgerEntryChanges{
		102: {{xdrtest.Created(xdrtest.Trustline(1, "USDC", 9))}},
		105: {{xdrtest.State(xdrtest.Account(9, "")), xdrtest.Updated(xdrtest.Account(9, "issuer.example"))}},
	}
}

func TestNormalSequence(t *testing.T) {
	f := newFake(xdrtest.Chain(100, 107, lookalikeOps()))
	cp, sink := ingest.NewMemoryCheckpoint(), &recordSink{}
	in := newIngester(t, f.client(t), cp, sink, 100)
	if err := drain(in); err != nil {
		t.Fatal(err)
	}
	if got := sink.seqs(); fmt.Sprint(got) != "[100 101 102 103 104 105 106 107]" {
		t.Fatalf("delivered %v", got)
	}
	if last(t, cp) != 107 {
		t.Fatalf("checkpoint = %d", last(t, cp))
	}
	f102, f105 := sink.got[2], sink.got[5]
	if len(f102.Facts.Assets) != 1 || f102.Facts.Assets[0] != (xdrcompat.Asset{Code: "USDC", Issuer: xdrtest.Address(9)}) {
		t.Errorf("ledger 102 facts = %+v", f102.Facts)
	}
	if len(f105.Facts.HomeDomains) != 1 || f105.Facts.HomeDomains[0].Domain != "issuer.example" {
		t.Errorf("ledger 105 facts = %+v", f105.Facts)
	}
	if f102.Network != entity.Testnet || f102.CloseTime != 1_790_000_000+102*5 {
		t.Errorf("ledger 102 = %+v", f102)
	}
	// Caught up: nothing new, no error.
	if n, err := in.Step(context.Background()); n != 0 || err != nil {
		t.Fatalf("caught-up step = %d, %v", n, err)
	}
	// New ledgers arrive and are picked up.
	for _, l := range xdrtest.Chain(108, 109, nil) {
		f.put(l.Seq, xdrtest.Hash(l.Seq), l.Bytes())
	}
	if err := drain(in); err != nil || last(t, cp) != 109 {
		t.Fatalf("after new ledgers: checkpoint %d, %v", last(t, cp), err)
	}
}

func TestRestartFromCheckpointIsIdempotent(t *testing.T) {
	f := newFake(xdrtest.Chain(100, 107, lookalikeOps()))
	src := f.client(t)
	cp, sink := ingest.NewMemoryCheckpoint(), &recordSink{}

	first := newIngester(t, src, cp, sink, 100)
	if _, err := first.Step(context.Background()); err != nil { // one page: 100..102
		t.Fatal(err)
	}
	first.Close()
	// StartLedger is ignored once a checkpoint exists.
	second := newIngester(t, src, cp, sink, 100)
	if err := drain(second); err != nil {
		t.Fatal(err)
	}
	if got := sink.seqs(); fmt.Sprint(got) != "[100 101 102 103 104 105 106 107]" {
		t.Fatalf("delivered %v (each ledger exactly once)", got)
	}
}

func TestSinkFailureDoesNotAdvanceCheckpoint(t *testing.T) {
	f := newFake(xdrtest.Chain(100, 102, nil))
	cp, sink := ingest.NewMemoryCheckpoint(), &recordSink{fail: true}
	in := newIngester(t, f.client(t), cp, sink, 100)
	_, err := in.Step(context.Background())
	if err == nil || ingest.IsHalt(err) {
		t.Fatalf("err = %v, want retryable", err)
	}
	if _, ok, _ := cp.Last(context.Background(), entity.Testnet); ok {
		t.Fatal("checkpoint written for an undelivered ledger")
	}
	sink.fail = false
	if err := drain(in); err != nil || fmt.Sprint(sink.seqs()) != "[100 101 102]" {
		t.Fatalf("retry delivered %v, %v", sink.seqs(), err)
	}
}

func TestHalts(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(f *fakeRPC)
		start   uint32
		want    error
		lastSeq uint32 // checkpoint after the halt; 0 = none
	}{
		{"gap in page", func(f *fakeRPC) { f.skip[103] = true }, 100, ingest.ErrGap, 102},
		{"start older than retention", func(f *fakeRPC) {}, 90, ingest.ErrGap, 0},
		{"unknown XDR", func(f *fakeRPC) {
			b := xdrtest.Ledger{Seq: 104, Prev: xdrtest.Hash(103)}.Bytes()
			b[3] = 7 // LedgerCloseMeta v7
			f.put(104, xdrtest.Hash(104), b)
		}, 100, xdrcompat.ErrUnknownXDR, 103},
		{"protocol 30", func(f *fakeRPC) {
			f.put(101, xdrtest.Hash(101), xdrtest.Ledger{Seq: 101, Prev: xdrtest.Hash(100), Protocol: 30}.Bytes())
		}, 100, xdrcompat.ErrUnsupportedProtocol, 100},
		{"hash differs from meta", func(f *fakeRPC) {
			f.put(101, xdrtest.Hash(999), xdrtest.Ledger{Seq: 101, Prev: xdrtest.Hash(100)}.Bytes())
		}, 100, ingest.ErrInconsistent, 100},
		{"meta sequence differs", func(f *fakeRPC) {
			f.put(101, xdrtest.Hash(555), xdrtest.Ledger{Seq: 555, Prev: xdrtest.Hash(100)}.Bytes())
		}, 100, ingest.ErrInconsistent, 100},
		{"broken hash chain", func(f *fakeRPC) {
			f.put(102, xdrtest.Hash(102), xdrtest.Ledger{Seq: 102, Prev: xdrtest.Hash(42)}.Bytes())
		}, 100, ingest.ErrInconsistent, 101},
		{"wrong network", func(f *fakeRPC) { f.passphrase = ingest.PublicPassphrase }, 100, ingest.ErrWrongNetwork, 0},
		{"no start ledger", func(f *fakeRPC) {}, 0, ingest.ErrNoStart, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(xdrtest.Chain(100, 107, nil))
			c.setup(f)
			cp, sink := ingest.NewMemoryCheckpoint(), &recordSink{}
			in := newIngester(t, f.client(t), cp, sink, c.start)
			err := drain(in)
			if !errors.Is(err, c.want) || !ingest.IsHalt(err) {
				t.Fatalf("err = %v, want halt %v", err, c.want)
			}
			if got := last(t, cp); got != c.lastSeq {
				t.Fatalf("checkpoint = %d, want %d", got, c.lastSeq)
			}
			// Halted stays halted: stepping again does not skip past the bad ledger.
			if err2 := drain(in); !errors.Is(err2, c.want) || last(t, cp) != c.lastSeq {
				t.Fatalf("second attempt: %v, checkpoint %d", err2, last(t, cp))
			}
		})
	}
}

func TestRunRetriesThenGivesUp(t *testing.T) {
	f := newFake(xdrtest.Chain(100, 101, nil))
	src := f.client(t)
	f.failNext = 2 // two 500s, then healthy
	cp, sink := ingest.NewMemoryCheckpoint(), &recordSink{}
	in := newIngester(t, src, cp, sink, 100)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		for last(t, cp) != 101 && ctx.Err() == nil {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()
	if err := in.Run(ctx); !errors.Is(err, context.Canceled) || last(t, cp) != 101 {
		t.Fatalf("Run = %v, checkpoint %d", err, last(t, cp))
	}
	in.Close()

	f.failNext = 1000
	in2 := newIngester(t, src, ingest.NewMemoryCheckpoint(), sink, 100)
	err := in2.Run(context.Background())
	if err == nil || ingest.IsHalt(err) || !errors.Is(err, rpc.ErrBadResponse) {
		t.Fatalf("Run = %v, want give-up after retries", err)
	}
}

func TestRunStopsOnHalt(t *testing.T) {
	f := newFake(xdrtest.Chain(100, 103, nil))
	f.skip[101] = true
	in := newIngester(t, f.client(t), ingest.NewMemoryCheckpoint(), &recordSink{}, 100)
	if err := in.Run(context.Background()); !errors.Is(err, ingest.ErrGap) {
		t.Fatalf("Run = %v", err)
	}
}

func TestSingleWriterPerNetwork(t *testing.T) {
	f := newFake(xdrtest.Chain(100, 100, nil))
	src := f.client(t)
	a := newIngester(t, src, ingest.NewMemoryCheckpoint(), &recordSink{}, 100)
	if _, err := ingest.New(ingest.Config{Network: entity.Testnet}, src, ingest.NewMemoryCheckpoint(), &recordSink{}); !errors.Is(err, ingest.ErrWriterActive) {
		t.Fatalf("second writer: %v", err)
	}
	pub, err := ingest.New(ingest.Config{Network: entity.Public}, src, ingest.NewMemoryCheckpoint(), &recordSink{})
	if err != nil {
		t.Fatalf("other network: %v", err)
	}
	pub.Close()
	a.Close()
	b, err := ingest.New(ingest.Config{Network: entity.Testnet}, src, ingest.NewMemoryCheckpoint(), &recordSink{})
	if err != nil {
		t.Fatalf("after close: %v", err)
	}
	b.Close()
}

func TestConfigValidation(t *testing.T) {
	if _, err := ingest.New(ingest.Config{Network: "futurenet"}, nil, nil, nil); !errors.Is(err, ingest.ErrWrongNetwork) {
		t.Errorf("unknown network: %v", err)
	}
	if _, err := ingest.New(ingest.Config{Network: entity.Testnet, PageSize: 201}, nil, nil, nil); err == nil {
		t.Error("page size 201 accepted")
	}
}

func TestMemoryCheckpointOnlyAdvancesByOne(t *testing.T) {
	cp, ctx := ingest.NewMemoryCheckpoint(), context.Background()
	if err := cp.Set(ctx, entity.Testnet, 10); err != nil {
		t.Fatal(err)
	}
	for _, s := range []uint32{10, 9, 12} {
		if err := cp.Set(ctx, entity.Testnet, s); !errors.Is(err, ingest.ErrGap) {
			t.Errorf("Set(%d) = %v", s, err)
		}
	}
	if err := cp.Set(ctx, entity.Testnet, 11); err != nil {
		t.Fatal(err)
	}
}
