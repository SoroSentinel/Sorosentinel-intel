package signal

import "testing"

func TestToPublic(t *testing.T) {
	cases := map[Internal]Public{
		Benign:     Consistent,
		Unknown:    NoSignals,
		Suspicious: Caution,
		Malicious:  HighCaution,
	}
	for in, want := range cases {
		got, err := ToPublic(in)
		if err != nil || got != want {
			t.Errorf("ToPublic(%s) = %s, %v; want %s", in, got, err, want)
		}
		if !got.Valid() {
			t.Errorf("%s not Valid", got)
		}
	}
}

func TestToPublicRejectsUnknownInput(t *testing.T) {
	for _, in := range []Internal{"", "safe", "BENIGN", "verified"} {
		if got, err := ToPublic(in); err == nil {
			t.Errorf("ToPublic(%q) = %q, want error", in, got)
		}
	}
}

func TestPublicNeverUsesInternalNames(t *testing.T) {
	for _, p := range []Public{"benign", "unknown", "suspicious", "malicious", "safe"} {
		if p.Valid() {
			t.Errorf("%q must not be a valid public signal", p)
		}
	}
}
