package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/xdrcompat"
)

// Intel #54 AC 3: an ingest log line carries ledger coordinates and counts, never
// the strings it read out of the ledger. A home domain is attacker-owned text;
// echoing it into logs puts it in front of whatever reads them, and an issuer or
// contract id in a log is a person's account in a search box.
//
// The check is an allowlist of field names rather than a list of banned strings,
// so adding a field to the sink is a deliberate act instead of a silent widening.
func TestLogSinkLogsCountsOnly(t *testing.T) {
	const (
		issuer  = "GD3MH5CY4ZXLHD4XJHZ5HFTP7HNYJBNGWBZJGQPZJJVX"
		account = "GBZYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7VUB"
		domain  = "give-us-your-secret-keys.example"
		seed    = "AAAAAgAAAAB" + issuer
	)
	f := ingest.LedgerFacts{
		Network: entity.Testnet, Sequence: 42, CloseTime: 1_700_000_000,
		Facts: xdrcompat.Facts{
			Assets:      []xdrcompat.Asset{{Code: "USD1", Issuer: issuer}, {Code: "EVIL", Issuer: issuer}},
			HomeDomains: []xdrcompat.HomeDomain{{Account: account, Domain: domain}},
		},
	}
	var logs bytes.Buffer
	if err := (logSink{slog.New(slog.NewJSONHandler(&logs, nil))}).Ledger(context.Background(), f); err != nil {
		t.Fatalf("sink: %v", err)
	}
	line := strings.TrimSpace(logs.String())
	if n := strings.Count(line, "\n"); n != 0 {
		t.Fatalf("one ledger, %d log lines", n+1)
	}
	got := map[string]any{}
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("line is not JSON: %v", err)
	}
	for k := range got {
		if !allowedSinkFields[k] {
			t.Errorf("the sink logged a new field %q; widen the allowlist only with a reason", k)
		}
	}
	for _, hostile := range []string{issuer, account, domain, seed, "USD1", "EVIL"} {
		if strings.Contains(line, hostile) {
			t.Errorf("the sink logged untrusted ledger content %q", hostile)
		}
	}
	// And the counts it is supposed to carry are really there, or the allowlist
	// above would also pass an empty line.
	if got["seq"] != float64(42) || got["assets"] != float64(2) || got["home_domains"] != float64(1) {
		t.Errorf("counts missing from the ledger line: %s", line)
	}
}

var allowedSinkFields = map[string]bool{
	"time": true, "level": true, "msg": true, "network": true,
	"seq": true, "assets": true, "home_domains": true,
}

// TestHaltKindAlwaysNamesACause is the other half of the same promise: the alert
// line must match a rule, so an exit that cannot be classified still gets a kind
// rather than a blank field an operator would have to guess at.
func TestHaltKindAlwaysNamesACause(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{ingest.ErrGap, ingest.HaltGap},
		{fmt.Errorf("ledger 100: %w", ingest.ErrGap), ingest.HaltGap},
		{errors.New("something nobody has classified"), "unclassified"},
	}
	for _, c := range cases {
		if got := haltKind(c.err); got != c.want {
			t.Errorf("haltKind(%v) = %q, want %q", c.err, got, c.want)
		}
		if got := haltKind(c.err); got == "" {
			t.Errorf("haltKind returned empty for %v: no rule could match it", c.err)
		}
	}
	if got := haltKind(nil); got != "unclassified" {
		t.Errorf("haltKind(nil) = %q; a nil exit still needs a label", got)
	}
}
