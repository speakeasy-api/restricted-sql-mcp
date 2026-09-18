package tunnel

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
)

// TokenParam is the query parameter the in-process tunnel agent pins on its
// local MCP URL. The agent's director merges the pinned query into every
// request it proxies, so only requests that came through the agent carry it.
const TokenParam = "tunnel_token"

// Gate refuses /mcp requests that did not arrive through the in-process tunnel
// agent. The token is generated per boot and never leaves process memory: it
// is not logged, not exposed on any endpoint, and not derived from config.
type Gate struct {
	token string
}

// NewGate generates a fresh 256-bit token.
func NewGate() (*Gate, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("generate tunnel token: %w", err)
	}
	return &Gate{token: hex.EncodeToString(b[:])}, nil
}

// LocalMCPURL returns base with the token pinned as a query parameter.
func (g *Gate) LocalMCPURL(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("local mcp url: %w", err)
	}
	q := u.Query()
	q.Set(TokenParam, g.token)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Wrap returns next guarded by the token. A request without the exact token
// gets 401 and never reaches the MCP handler; a request with it is forwarded
// with the token stripped so nothing downstream sees or logs it.
func (g *Gate) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		got := q.Get(TokenParam)
		if len(got) != len(g.token) || subtle.ConstantTimeCompare([]byte(got), []byte(g.token)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"direct access refused: this endpoint only accepts requests via the gram tunnel"}`))
			return
		}
		q.Del(TokenParam)
		r2 := r.Clone(r.Context())
		r2.URL.RawQuery = q.Encode()
		next.ServeHTTP(w, r2)
	})
}
