package evidence

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/signal"
)

func valid() New {
	return New{EntityID: 1, SourceID: 1, Detector: DetectorAssetLookalike, Class: ClassOnchainPattern,
		Category: "impersonation_asset", Payload: json.RawMessage(`{"code":"USDC"}`),
		ObservedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
}

func TestValidate(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatal(err)
	}
	past := valid().ObservedAt.Add(-time.Hour)
	cases := map[string]func(*New){
		"no entity":          func(n *New) { n.EntityID = 0 },
		"bad detector":       func(n *New) { n.Detector = "lookalike" },
		"bad class":          func(n *New) { n.Class = "Human" },
		"bad category":       func(n *New) { n.Category = "Scam!" },
		"payload array":      func(n *New) { n.Payload = json.RawMessage(`[1]`) },
		"payload null":       func(n *New) { n.Payload = json.RawMessage(`null`) },
		"payload too big":    func(n *New) { n.Payload = json.RawMessage(`{"a":"` + strings.Repeat("x", MaxPayloadBytes) + `"}`) },
		"no observed_at":     func(n *New) { n.ObservedAt = time.Time{} },
		"expires first":      func(n *New) { n.ExpiresAt = &past },
		"half confirmation":  func(n *New) { n.ConfirmedLevel = signal.Malicious },
		"auto confirmation":  func(n *New) { n.ConfirmedLevel, n.ConfirmedBy = signal.Malicious, "a" },
		"empty artifact ref": func(n *New) { n.ArtifactRefs = []string{""} },
		"bad level": func(n *New) {
			n.Detector, n.Class, n.ConfirmedLevel, n.ConfirmedBy = DetectorCurated, ClassHuman, "safe", "a"
		},
	}
	for name, mut := range cases {
		n := valid()
		mut(&n)
		if n.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestActiveAt(t *testing.T) {
	obs := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	exp := obs.Add(time.Hour)
	e := Evidence{ObservedAt: obs, ExpiresAt: &exp}
	if e.ActiveAt(obs.Add(-time.Second)) || !e.ActiveAt(obs) || e.ActiveAt(exp) {
		t.Fatal("ActiveAt boundaries wrong")
	}
}
