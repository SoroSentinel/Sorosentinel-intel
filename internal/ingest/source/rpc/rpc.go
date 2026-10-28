// Package rpc is an ingest.Source backed by Stellar RPC (JSON-RPC 2.0 over
// HTTPS). The endpoint is trusted configuration, but every response is
// treated as hostile input: size and time caps, no redirects, strict shape
// checks. Methods and fields follow developers.stellar.org (checked
// 2026-10-28): getNetwork, getHealth, getLedgers.
package rpc

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest"
)

// DefaultTestnetURL is SDF's public testnet RPC (developers.stellar.org,
// "RPC providers", checked 2026-10-28). Mainnet has no default: configure one.
const DefaultTestnetURL = "https://soroban-testnet.stellar.org"

const (
	// DefaultMaxBodyBytes caps one response. A page of 10 busy mainnet
	// ledgers is several MB of base64 meta. TODO(verify) against E4 numbers.
	DefaultMaxBodyBytes = 64 << 20
	// DefaultTimeout covers one whole request, body included.
	DefaultTimeout = 30 * time.Second
	userAgent      = "SoroSentinel-ingest/1"
)

var (
	// ErrBadResponse: the response is not a well-formed answer to the request.
	ErrBadResponse = errors.New("rpc: bad response")
	// ErrTooLarge: the body exceeded MaxBodyBytes.
	ErrTooLarge = errors.New("rpc: response too large")
)

// Error is a JSON-RPC error object returned by the server.
type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("rpc: server error %d", e.Code) }

// Config for a Client.
type Config struct {
	URL          string // https only
	Timeout      time.Duration
	MaxBodyBytes int64
	TLSConfig    *tls.Config // tests only; nil uses system roots
}

// Client implements ingest.Source.
type Client struct {
	url     string
	maxBody int64
	http    *http.Client
	id      atomic.Uint64
}

var _ ingest.Source = (*Client)(nil)

func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, errors.New("rpc: endpoint must be a plain https URL")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	transport := &http.Transport{
		Proxy:           nil,
		DialContext:     (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSClientConfig: cfg.TLSConfig,
		// HTTP/1.1: a 15 MB getLedgers page from SDF testnet took 17.7s over
		// Go's HTTP/2 and 5.3s over HTTP/1.1 (2026-10-28).
		ForceAttemptHTTP2:      false,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  cfg.Timeout,
		MaxResponseHeaderBytes: 16 << 10,
		DisableCompression:     true, // the cap applies to bytes on the wire
	}
	return &Client{
		url:     u.String(),
		maxBody: cfg.MaxBodyBytes,
		http: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
			Jar:       nil,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return fmt.Errorf("%w: redirect refused", ErrBadResponse)
			},
		},
	}, nil
}

type request struct {
	JSONRPC string `json:"jsonrpc"`
	ID      uint64 `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type envelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *uint64         `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    *int   `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// call posts one request and decodes result into out.
func (c *Client) call(ctx context.Context, method string, params, out any) error {
	id := c.id.Add(1)
	body, err := json.Marshal(request{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("rpc: %s: %w", method, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return fmt.Errorf("rpc: %s: %w", method, err)
	}
	if int64(len(raw)) > c.maxBody {
		return fmt.Errorf("%w: %s", ErrTooLarge, method)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s: HTTP %d", ErrBadResponse, method, resp.StatusCode)
	}
	var env envelope
	if err := strictUnmarshal(raw, &env); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrBadResponse, method, err)
	}
	if env.JSONRPC != "2.0" || env.ID == nil || *env.ID != id {
		return fmt.Errorf("%w: %s: envelope", ErrBadResponse, method)
	}
	if env.Error != nil {
		if env.Error.Code == nil {
			return fmt.Errorf("%w: %s: error without code", ErrBadResponse, method)
		}
		return &Error{Code: *env.Error.Code, Message: env.Error.Message}
	}
	if len(env.Result) == 0 || bytes.Equal(env.Result, []byte("null")) {
		return fmt.Errorf("%w: %s: no result", ErrBadResponse, method)
	}
	if err := strictUnmarshal(env.Result, out); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrBadResponse, method, err)
	}
	return nil
}

// strictUnmarshal rejects trailing data after the JSON value. Unknown fields
// are allowed: RPC adds fields over time.
func strictUnmarshal(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	if err := d.Decode(v); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// NetworkPassphrase calls getNetwork.
func (c *Client) NetworkPassphrase(ctx context.Context) (string, error) {
	var r struct {
		Passphrase *string `json:"passphrase"`
	}
	if err := c.call(ctx, "getNetwork", nil, &r); err != nil {
		return "", err
	}
	if r.Passphrase == nil {
		return "", fmt.Errorf("%w: getNetwork: missing passphrase", ErrBadResponse)
	}
	return *r.Passphrase, nil
}

// Range calls getHealth and requires status "healthy".
func (c *Client) Range(ctx context.Context) (ingest.Range, error) {
	var r struct {
		Status       *string `json:"status"`
		LatestLedger *uint32 `json:"latestLedger"`
		OldestLedger *uint32 `json:"oldestLedger"`
	}
	if err := c.call(ctx, "getHealth", nil, &r); err != nil {
		return ingest.Range{}, err
	}
	if r.Status == nil || r.LatestLedger == nil || r.OldestLedger == nil {
		return ingest.Range{}, fmt.Errorf("%w: getHealth: missing fields", ErrBadResponse)
	}
	// The docs type status as a string without listing values; "healthy" is
	// what SDF testnet returned on 2026-10-28. TODO(verify) other values.
	if *r.Status != "healthy" {
		return ingest.Range{}, fmt.Errorf("%w: getHealth: status not healthy", ErrBadResponse)
	}
	return ingest.Range{Oldest: *r.OldestLedger, Latest: *r.LatestLedger}, nil
}

type ledgersParams struct {
	StartLedger uint32     `json:"startLedger"`
	Pagination  pagination `json:"pagination"`
	XDRFormat   string     `json:"xdrFormat"`
}

type pagination struct {
	Limit uint32 `json:"limit"`
}

// Ledgers calls getLedgers with base64 XDR and decodes each ledger's meta.
func (c *Client) Ledgers(ctx context.Context, start, limit uint32) ([]ingest.RawLedger, error) {
	if limit == 0 || limit > 200 {
		return nil, fmt.Errorf("rpc: getLedgers limit %d outside 1..200", limit)
	}
	var r struct {
		Ledgers []struct {
			Hash        *string `json:"hash"`
			Sequence    *uint32 `json:"sequence"`
			MetadataXDR *string `json:"metadataXdr"`
		} `json:"ledgers"`
	}
	p := ledgersParams{StartLedger: start, Pagination: pagination{Limit: limit}, XDRFormat: "base64"}
	if err := c.call(ctx, "getLedgers", p, &r); err != nil {
		return nil, err
	}
	if r.Ledgers == nil {
		return nil, fmt.Errorf("%w: getLedgers: missing ledgers", ErrBadResponse)
	}
	out := make([]ingest.RawLedger, 0, len(r.Ledgers))
	for i, l := range r.Ledgers {
		if l.Hash == nil || l.Sequence == nil || l.MetadataXDR == nil {
			return nil, fmt.Errorf("%w: getLedgers: ledger %d missing fields", ErrBadResponse, i)
		}
		if h, err := hex.DecodeString(*l.Hash); err != nil || len(h) != 32 || hex.EncodeToString(h) != *l.Hash {
			return nil, fmt.Errorf("%w: getLedgers: ledger %d hash", ErrBadResponse, *l.Sequence)
		}
		meta, err := base64.StdEncoding.Strict().DecodeString(*l.MetadataXDR)
		if err != nil {
			return nil, fmt.Errorf("%w: getLedgers: ledger %d metadataXdr", ErrBadResponse, *l.Sequence)
		}
		out = append(out, ingest.RawLedger{Sequence: *l.Sequence, Hash: *l.Hash, Meta: meta})
	}
	return out, nil
}
