// Command issue-lookalike sets up the local demo's look-alike asset on
// TESTNET ONLY (docs/runbooks/local-demo.md). It never runs against mainnet:
// it refuses any RPC endpoint whose network passphrase is not testnet's.
//
// It creates three throwaway accounts with Friendbot: an issuer (home_domain
// set, so D-HOMEDOMAIN-MISMATCH runs too), a holder that opens a trustline to
// <code>:<issuer> on-chain (what Intel ingests and flags), and a signer. For
// the signer it builds, but does not sign or submit, two change-trust
// transactions for Guard to analyze: one to the look-alike and a control to
// the reference issuer.
//
// Stdout is one JSON object with public data only: addresses, the trustline
// ledger and the two unsigned envelopes. Secret keys stay in memory and are
// never printed; the accounts are abandoned after the run.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/source/rpc"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/ingest/xdrcompat"
)

const (
	defaultFriendbot = "https://friendbot.stellar.org"
	// Testnet USDC in config/reference-assets.testnet.json.
	defaultReferenceIssuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
	maxResponseBytes       = 1 << 20
	txTimeout              = 5 * time.Minute
	baseFee                = 100 // stroops
	maxTrustlineLimit      = int64(^uint64(0) >> 1)
)

type output struct {
	Network         string `json:"network"`
	AssetCode       string `json:"asset_code"`
	Issuer          string `json:"issuer"`
	IssuerDomain    string `json:"issuer_home_domain"`
	Holder          string `json:"holder"`
	Signer          string `json:"signer"`
	TrustlineLedger uint32 `json:"trustline_ledger"`
	LookalikeTx     string `json:"lookalike_tx"`
	ReferenceIssuer string `json:"reference_issuer"`
	ControlTx       string `json:"control_tx"`
}

func main() {
	rpcURL := flag.String("rpc-url", rpc.DefaultTestnetURL, "testnet Stellar RPC endpoint")
	friendbot := flag.String("friendbot-url", defaultFriendbot, "testnet Friendbot")
	code := flag.String("code", "USDC", "asset code to issue (a look-alike of a reference asset)")
	domain := flag.String("home-domain", "example.com", "home_domain set on the issuer")
	refIssuer := flag.String("reference-issuer", defaultReferenceIssuer, "reference issuer for the control transaction")
	timeout := flag.Duration("timeout", 3*time.Minute, "overall time budget")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	c := &client{rpcURL: *rpcURL, friendbot: *friendbot, http: &http.Client{Timeout: 30 * time.Second}}
	out, err := run(ctx, c, *code, *domain, *refIssuer)
	if err != nil {
		fmt.Fprintln(os.Stderr, "issue-lookalike:", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out) //nolint:errcheck // stdout
}

func run(ctx context.Context, c *client, code, domain, refIssuer string) (*output, error) {
	pass, err := c.passphrase(ctx)
	if err != nil {
		return nil, err
	}
	if pass != network.TestNetworkPassphrase {
		return nil, errors.New("RPC endpoint is not testnet; this tool runs on testnet only")
	}

	var kps [3]*keypair.Full
	for i := range kps {
		if kps[i], err = keypair.Random(); err != nil {
			return nil, err
		}
		if err := c.fund(ctx, kps[i].Address()); err != nil {
			return nil, err
		}
	}
	issuer, holder, signer := kps[0], kps[1], kps[2]

	home := xdr.String32(domain)
	setDomain := xdr.OperationBody{Type: xdr.OperationTypeSetOptions, SetOptionsOp: &xdr.SetOptionsOp{HomeDomain: &home}}
	if _, err := c.submit(ctx, issuer, setDomain); err != nil {
		return nil, fmt.Errorf("set home_domain: %w", err)
	}
	lookalike, err := changeTrust(code, issuer.Address())
	if err != nil {
		return nil, err
	}
	ledger, err := c.submit(ctx, holder, lookalike)
	if err != nil {
		return nil, fmt.Errorf("holder trustline: %w", err)
	}

	lookTx, err := c.unsigned(ctx, signer.Address(), lookalike)
	if err != nil {
		return nil, err
	}
	control, err := changeTrust(code, refIssuer)
	if err != nil {
		return nil, err
	}
	controlTx, err := c.unsigned(ctx, signer.Address(), control)
	if err != nil {
		return nil, err
	}
	return &output{
		Network: "testnet", AssetCode: code, Issuer: issuer.Address(), IssuerDomain: domain,
		Holder: holder.Address(), Signer: signer.Address(), TrustlineLedger: ledger,
		LookalikeTx: lookTx, ReferenceIssuer: refIssuer, ControlTx: controlTx,
	}, nil
}

type client struct {
	rpcURL, friendbot string
	http              *http.Client
}

func (c *client) fund(ctx context.Context, addr string) error {
	u := c.friendbot + "/?addr=" + url.QueryEscape(addr)
	var last error
	for attempt := range 4 {
		if attempt > 0 {
			if err := sleep(ctx, time.Duration(attempt)*3*time.Second); err != nil {
				return err
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		resp, err := c.http.Do(req)
		if err != nil {
			last = errors.New("friendbot unreachable")
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes)) //nolint:errcheck // drain
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		last = fmt.Errorf("friendbot status %d", resp.StatusCode)
	}
	return last
}

func changeTrust(code, issuer string) (xdr.OperationBody, error) {
	// The XDR package accepts codes Stellar does not (e.g. spaces); use
	// Intel's canonical asset rules first.
	if _, err := entity.NormalizeKey(entity.Asset, code+":"+issuer); err != nil {
		return xdr.OperationBody{}, fmt.Errorf("asset: %w", err)
	}
	asset, err := xdr.NewCreditAsset(code, issuer)
	if err != nil {
		return xdr.OperationBody{}, fmt.Errorf("asset: %w", err)
	}
	return xdr.OperationBody{Type: xdr.OperationTypeChangeTrust, ChangeTrustOp: &xdr.ChangeTrustOp{
		Line: asset.ToChangeTrustAsset(), Limit: xdr.Int64(maxTrustlineLimit),
	}}, nil
}

// submit signs and sends a one-operation transaction from kp and waits for
// it to succeed, returning its ledger.
func (c *client) submit(ctx context.Context, kp *keypair.Full, op xdr.OperationBody) (uint32, error) {
	env, err := c.build(ctx, kp.Address(), op)
	if err != nil {
		return 0, err
	}
	h, err := network.HashTransactionInEnvelope(env, network.TestNetworkPassphrase)
	if err != nil {
		return 0, err
	}
	sig, err := kp.SignDecorated(h[:])
	if err != nil {
		return 0, err
	}
	env.V1.Signatures = []xdr.DecoratedSignature{sig}
	b64, err := xdr.MarshalBase64(env)
	if err != nil {
		return 0, err
	}
	var sent struct {
		Status string `json:"status"`
	}
	if err := c.call(ctx, "sendTransaction", map[string]string{"transaction": b64}, &sent); err != nil {
		return 0, err
	}
	if sent.Status != "PENDING" && sent.Status != "DUPLICATE" {
		return 0, fmt.Errorf("sendTransaction status %q", sent.Status)
	}
	hash := hex.EncodeToString(h[:])
	for {
		var got struct {
			Status string `json:"status"`
			Ledger uint32 `json:"ledger"`
		}
		if err := c.call(ctx, "getTransaction", map[string]string{"hash": hash}, &got); err != nil {
			return 0, err
		}
		switch got.Status {
		case "SUCCESS":
			return got.Ledger, nil
		case "NOT_FOUND":
			if err := sleep(ctx, time.Second); err != nil {
				return 0, fmt.Errorf("transaction not confirmed: %w", err)
			}
		default:
			return 0, fmt.Errorf("transaction status %q", got.Status)
		}
	}
}

// unsigned builds the base64 envelope of a one-operation transaction from
// source, at its next sequence number, without signing it.
func (c *client) unsigned(ctx context.Context, source string, op xdr.OperationBody) (string, error) {
	env, err := c.build(ctx, source, op)
	if err != nil {
		return "", err
	}
	return xdr.MarshalBase64(env)
}

func (c *client) build(ctx context.Context, source string, op xdr.OperationBody) (xdr.TransactionEnvelope, error) {
	seq, err := c.sequence(ctx, source)
	if err != nil {
		return xdr.TransactionEnvelope{}, err
	}
	src, err := xdr.AddressToMuxedAccount(source)
	if err != nil {
		return xdr.TransactionEnvelope{}, err
	}
	tb := xdr.TimeBounds{MaxTime: xdr.TimePoint(time.Now().Add(txTimeout).Unix())}
	return xdr.TransactionEnvelope{Type: xdr.EnvelopeTypeEnvelopeTypeTx, V1: &xdr.TransactionV1Envelope{Tx: xdr.Transaction{
		SourceAccount: src,
		Fee:           baseFee,
		SeqNum:        xdr.SequenceNumber(seq + 1),
		Cond:          xdr.NewPreconditionsWithTimeBounds(&tb),
		Memo:          xdr.Memo{Type: xdr.MemoTypeMemoNone},
		Operations:    []xdr.Operation{{Body: op}},
	}}}, nil
}

// sequence reads an account's current sequence number, waiting briefly for
// a just-funded account to become visible.
func (c *client) sequence(ctx context.Context, account string) (int64, error) {
	key, err := xdrcompat.AccountKey(account)
	if err != nil {
		return 0, err
	}
	for {
		var r struct {
			Entries []struct {
				XDR string `json:"xdr"`
			} `json:"entries"`
		}
		p := map[string]any{"keys": []string{key}, "xdrFormat": "base64"}
		if err := c.call(ctx, "getLedgerEntries", p, &r); err != nil {
			return 0, err
		}
		if len(r.Entries) == 1 {
			var data xdr.LedgerEntryData
			if err := xdr.SafeUnmarshalBase64(r.Entries[0].XDR, &data); err != nil {
				return 0, errors.New("getLedgerEntries: undecodable account entry")
			}
			acct, ok := data.GetAccount()
			if !ok {
				return 0, errors.New("getLedgerEntries: entry is not an account")
			}
			return int64(acct.SeqNum), nil
		}
		if err := sleep(ctx, time.Second); err != nil {
			return 0, fmt.Errorf("account not visible on RPC: %w", err)
		}
	}
}

func (c *client) passphrase(ctx context.Context) (string, error) {
	var r struct {
		Passphrase string `json:"passphrase"`
	}
	if err := c.call(ctx, "getNetwork", nil, &r); err != nil {
		return "", err
	}
	return r.Passphrase, nil
}

func (c *client) call(ctx context.Context, method string, params, out any) error {
	body, err := json.Marshal(struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Method  string `json:"method"`
		Params  any    `json:"params,omitempty"`
	}{"2.0", 1, method, params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.rpcURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("rpc %s: unreachable", method)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(raw) > maxResponseBytes {
		return fmt.Errorf("rpc %s: response unreadable or too large", method)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rpc %s: status %d", method, resp.StatusCode)
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("rpc %s: malformed response", method)
	}
	if env.Error != nil {
		return fmt.Errorf("rpc %s: error code %d", method, env.Error.Code)
	}
	if len(env.Result) == 0 {
		return fmt.Errorf("rpc %s: empty result", method)
	}
	if err := json.Unmarshal(env.Result, out); err != nil {
		return fmt.Errorf("rpc %s: malformed result", method)
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
