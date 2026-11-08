package store

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ValidateDatabaseURL verifies that the database connection string adheres to
// security rules: non-local and non-container hosts must enforce TLS with
// certificate verification (sslmode=verify-full, verify-ca, or require).
// Plaintext modes (disable, allow, prefer) or omitted sslmode are refused for
// remote hosts to prevent credentials and evidence from being transmitted in clear.
func ValidateDatabaseURL(rawURL string) error {
	if strings.TrimSpace(rawURL) == "" {
		return errors.New("database URL is empty")
	}

	cfg, err := pgxpool.ParseConfig(rawURL)
	if err != nil {
		return errors.New("database configuration is invalid")
	}

	host, sslmode, err := parseHostAndSSLMode(rawURL)
	if err != nil {
		return err
	}

	if host == "" {
		host = cfg.ConnConfig.Host
	}

	hosts := strings.Split(host, ",")
	allLocal := true
	for _, h := range hosts {
		if !isLocalOrComposeHost(h) {
			allLocal = false
			break
		}
	}

	if allLocal {
		return nil
	}

	switch sslmode {
	case "verify-full", "verify-ca", "require":
		return nil
	case "disable", "allow", "prefer", "":
		return errors.New("remote database host requires TLS enforcement (sslmode=verify-full, verify-ca, or require; disable, allow, and prefer are refused for non-local hosts)")
	default:
		return fmt.Errorf("unknown sslmode %q for remote database host", sslmode)
	}
}

func isLocalOrComposeHost(host string) bool {
	h := strings.Trim(strings.TrimSpace(host), "[]")
	if sh, _, err := net.SplitHostPort(h); err == nil {
		h = sh
	}
	switch strings.ToLower(h) {
	case "localhost", "127.0.0.1", "::1", "postgres", "db":
		return true
	default:
		return false
	}
}

func parseHostAndSSLMode(rawURL string) (string, string, error) {
	if strings.HasPrefix(rawURL, "postgres://") || strings.HasPrefix(rawURL, "postgresql://") {
		u, err := url.Parse(rawURL)
		if err != nil {
			return "", "", errors.New("invalid database URL")
		}
		host := u.Hostname()
		sslmode := strings.ToLower(strings.TrimSpace(u.Query().Get("sslmode")))
		return host, sslmode, nil
	}

	fields := strings.Fields(rawURL)
	var host, sslmode string
	for _, f := range fields {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if k == "host" {
			host = v
		} else if k == "sslmode" {
			sslmode = strings.ToLower(v)
		}
	}
	if host == "" {
		host = "localhost"
	}
	return host, sslmode, nil
}
