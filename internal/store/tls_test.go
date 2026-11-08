package store_test

import (
	"testing"

	"github.com/SoroSentinel/Sorosentinel-intel/internal/store"
)

func TestValidateDatabaseURL(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		// Permitted local/compose connections
		{"localhost with disable", "postgres://user:pass@localhost:5432/intel?sslmode=disable", false},
		{"127.0.0.1 with disable", "postgres://user:pass@127.0.0.1:5432/intel?sslmode=disable", false},
		{"::1 with disable", "postgres://user:pass@[::1]:5432/intel?sslmode=disable", false},
		{"postgres compose host with disable", "postgres://user:pass@postgres:5432/intel?sslmode=disable", false},
		{"db compose host with disable", "postgres://user:pass@db:5432/intel?sslmode=disable", false},
		{"localhost DSN", "host=localhost user=intel dbname=intel sslmode=disable", false},

		// Remote hosts with insecure sslmode rejected
		{"remote host with sslmode=disable", "postgres://user:pass@10.0.0.5:5432/intel?sslmode=disable", true},
		{"remote host with sslmode=allow", "postgres://user:pass@sql.example.com:5432/intel?sslmode=allow", true},
		{"remote host with sslmode=prefer", "postgres://user:pass@sql.example.com:5432/intel?sslmode=prefer", true},
		{"remote host with omitted sslmode", "postgres://user:pass@sql.example.com:5432/intel", true},
		{"remote DSN with sslmode=disable", "host=10.0.0.5 sslmode=disable", true},
		{"remote DSN with sslmode=prefer", "host=sql.example.com sslmode=prefer", true},
		{"remote DSN without sslmode", "host=sql.example.com user=intel", true},

		// Remote hosts with TLS enforcement accepted
		{"remote host with sslmode=require", "postgres://user:pass@10.0.0.5:5432/intel?sslmode=require", false},
		{"remote host with sslmode=verify-ca", "postgres://user:pass@sql.example.com:5432/intel?sslmode=verify-ca", false},
		{"remote host with sslmode=verify-full", "postgres://user:pass@sql.example.com:5432/intel?sslmode=verify-full", false},
		{"remote DSN with verify-full", "host=sql.example.com sslmode=verify-full", false},

		// Invalid inputs
		{"empty string", "", true},
		{"malformed url", "not-a-valid-url-or-dsn :///", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := store.ValidateDatabaseURL(tc.url)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateDatabaseURL(%q) err = %v, wantErr = %v", tc.name, err, tc.wantErr)
			}
		})
	}
}
