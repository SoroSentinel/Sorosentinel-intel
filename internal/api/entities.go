package api

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/strkey"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/entity"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/store"
	"github.com/SoroSentinel/Sorosentinel-intel/internal/wording"
)

// Response types mirror schemas/jsonschema field for field. Nothing else is
// serialized: verdict level, rule, category, evidence ids, analyst actors and
// reasons stay internal.

// Entity mirrors Entity.json.
type Entity struct {
	Network string `json:"network"`
	Type    string `json:"type"`
	Key     string `json:"key"`
}

// EntitySignal mirrors EntitySignal.json.
type EntitySignal struct {
	Entity         Entity            `json:"entity"`
	SignalLevel    signal.Public     `json:"signal_level"`
	AsOf           string            `json:"as_of"`
	RulesetVersion string            `json:"ruleset_version,omitempty"`
	Disputed       *bool             `json:"disputed,omitempty"`
	Facts          map[string]string `json:"facts"`
	Statements     []PublicStatement `json:"statements"`
}

// PublicStatement mirrors PublicStatement.json.
type PublicStatement struct {
	TemplateID     string            `json:"template_id"`
	SignalLevel    signal.Public     `json:"signal_level"`
	Text           string            `json:"text"`
	Attribution    string            `json:"attribution"`
	Facts          map[string]string `json:"facts"`
	AsOf           string            `json:"as_of"`
	Method         string            `json:"method"`
	RulesetVersion string            `json:"ruleset_version"`
	MethodologyURL string            `json:"methodology_url"`
	ReviewURL      string            `json:"review_url"`
}

type batchRequest struct {
	Entities []Entity `json:"entities"`
}

type batchResponse struct {
	Results []EntitySignal `json:"results"`
}

func (s *Server) getEntity(w http.ResponseWriter, r *http.Request) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q["network"]) > 1 {
		writeError(w, http.StatusBadRequest, codeInvalidQuery)
		return
	}
	key, code := lookupKey(q.Get("network"), r.PathValue("type"), r.PathValue("id"))
	if code != "" {
		writeError(w, http.StatusBadRequest, code)
		return
	}
	out, err := s.signals(r, []store.LookupKey{key})
	if err != nil {
		s.storeFailed(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out[0])
}

func (s *Server) batchGet(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, codeUnsupportedMedia)
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	dec.DisallowUnknownFields()
	var req batchRequest
	err := dec.Decode(&req)
	if err == nil && dec.Decode(&struct{}{}) != io.EOF {
		err = errors.New("trailing data")
	}
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			writeError(w, http.StatusRequestEntityTooLarge, codeBodyTooLarge)
			return
		}
		writeError(w, http.StatusBadRequest, codeInvalidBody)
		return
	}
	switch {
	case len(req.Entities) == 0:
		writeError(w, http.StatusBadRequest, codeInvalidBody)
		return
	case len(req.Entities) > MaxBatch:
		writeError(w, http.StatusBadRequest, codeTooManyEntities)
		return
	}
	keys := make([]store.LookupKey, len(req.Entities))
	for i, e := range req.Entities {
		k, code := lookupKey(e.Network, e.Type, e.Key)
		if code != "" {
			writeError(w, http.StatusBadRequest, code)
			return
		}
		keys[i] = k
	}
	out, err := s.signals(r, keys)
	if err != nil {
		s.storeFailed(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, batchResponse{Results: out})
}

// lookupKey canonicalizes request input. A muxed M… account is reduced to
// its G… account; strkeys must carry a valid checksum. The error code is one
// of the shared entity.ErrorCode values.
func lookupKey(network, typ, key string) (store.LookupKey, string) {
	n, t := entity.Network(network), entity.Type(typ)
	if n != entity.Public && n != entity.Testnet {
		return store.LookupKey{}, string(entity.ErrUnknownNetwork)
	}
	if t == entity.Account && strings.HasPrefix(key, "M") {
		m, err := strkey.DecodeMuxedAccount(key)
		if err != nil {
			return store.LookupKey{}, string(entity.ErrInvalidKey)
		}
		if key, err = m.AccountID(); err != nil {
			return store.LookupKey{}, string(entity.ErrInvalidKey)
		}
	}
	norm, err := entity.NormalizeKey(t, key)
	if err != nil {
		if e, ok := errors.AsType[*entity.Error](err); ok {
			return store.LookupKey{}, string(e.Code)
		}
		return store.LookupKey{}, string(entity.ErrInvalidKey)
	}
	if !validChecksum(t, norm) {
		return store.LookupKey{}, string(entity.ErrInvalidKey)
	}
	return store.LookupKey{Network: n, Type: t, Key: norm}, ""
}

func validChecksum(t entity.Type, norm string) bool {
	switch t {
	case entity.Account:
		return strkey.IsValidEd25519PublicKey(norm)
	case entity.Contract:
		return strkey.IsValidContractAddress(norm)
	case entity.Asset:
		_, issuer, ok := strings.Cut(norm, ":")
		return !ok || strkey.IsValidEd25519PublicKey(issuer)
	}
	return true
}

func (s *Server) signals(r *http.Request, keys []store.LookupKey) ([]EntitySignal, error) {
	results, err := s.cfg.Store.LookupEntities(r.Context(), keys)
	if err != nil {
		return nil, err
	}
	if len(results) != len(keys) {
		return nil, errors.New("api: store returned the wrong number of results")
	}
	now := s.cfg.Now()
	out := make([]EntitySignal, len(keys))
	for i, k := range keys {
		if out[i], err = s.signal(k, results[i], now); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// signal builds the public view of one lookup. An entity without an active
// verdict is no_signals as of now: absence of data, never reassurance.
func (s *Server) signal(k store.LookupKey, res store.LookupResult, now time.Time) (EntitySignal, error) {
	out := EntitySignal{
		Entity:     Entity{Network: string(k.Network), Type: string(k.Type), Key: k.Key},
		Facts:      map[string]string{},
		Statements: []PublicStatement{},
	}
	v := res.Verdict
	if v == nil {
		out.SignalLevel = signal.NoSignals
		out.AsOf = now.UTC().Format(time.RFC3339)
		return out, nil
	}
	level, err := signal.ToPublic(v.Level)
	if err != nil {
		return EntitySignal{}, err // fail loud: an unmapped level is an error, not a default
	}
	disputed := v.Disputed
	out.SignalLevel = level
	out.AsOf = v.AsOf.UTC().Format(time.RFC3339)
	out.RulesetVersion = v.RulesetVersion
	out.Disputed = &disputed

	for _, req := range statementRequests(level, v.AsOf, v.RulesetVersion, res.Evidence) {
		for name, val := range wording.Facts(req) {
			if _, seen := out.Facts[name]; !seen {
				out.Facts[name] = val
			}
		}
		st, err := s.cfg.Renderer.Render(req)
		if err != nil {
			continue // fail closed: facts stay, no prose
		}
		out.Statements = append(out.Statements, publicStatement(st))
	}
	return out, nil
}

func publicStatement(st wording.Statement) PublicStatement {
	return PublicStatement{
		TemplateID:     st.TemplateID,
		SignalLevel:    st.SignalLevel,
		Text:           st.Text,
		Attribution:    st.Attribution,
		Facts:          st.Facts,
		AsOf:           st.AsOf.UTC().Format(time.RFC3339),
		Method:         st.Method,
		RulesetVersion: st.RulesetVersion,
		MethodologyURL: st.MethodologyURL,
		ReviewURL:      st.ReviewURL,
	}
}
