// Package tunnelidentity verifies AICP assertions for the private tunnel.
package tunnelidentity

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	Issuer  = "https://tunnel.speakeasy.com"
	Header  = "X-Speakeasy-Identity"
	jwksURL = Issuer + "/.well-known/jwks.json"
)

var errIdentity = errors.New("invalid tunnel identity assertion")

type Claims struct {
	jwt.RegisteredClaims
	Version        int             `json:"version"`
	Organization   string          `json:"organization_id"`
	AllowedMethods json.RawMessage `json:"allowed_methods"`
}

// AllowsMethod enforces the discovery restriction on the SDK's decoded
// method, including when a discovery assertion contains an empty list.
func (c *Claims) AllowsMethod(method string) bool {
	if c.AllowedMethods == nil {
		return true
	}
	switch method {
	case "server/discover", "initialize", "notifications/initialized", "ping", "tools/list":
		var methods []string
		if json.Unmarshal(c.AllowedMethods, &methods) == nil {
			for _, allowed := range methods {
				if method == allowed {
					return true
				}
			}
		}
	}
	return false
}

type Verifier struct {
	audience     string
	organization string
	client       *http.Client
	mu           sync.Mutex
	keys         map[string]*rsa.PublicKey
	expires      time.Time
	lastAttempt  time.Time
}

func New(audience, organization string) *Verifier {
	return &Verifier{
		audience:     audience,
		organization: organization,
		client: &http.Client{
			Timeout:       3 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (v *Verifier) Verify(r *http.Request) (*Claims, error) {
	headers := r.Header.Values(Header)
	if len(headers) != 1 || len(headers[0]) > 8192 {
		return nil, errIdentity
	}
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(headers[0], claims, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok || len(kid) != 43 || t.Header["typ"] != "speakeasy-identity+jwt" {
			return nil, errIdentity
		}
		return v.key(r.Context(), kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(Issuer), jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(5*time.Second))
	if err != nil || claims.Version != 1 || claims.Organization != v.organization ||
		len(claims.Audience) != 1 || claims.IssuedAt == nil || claims.ID == "" {
		return nil, errIdentity
	}
	lifetime := claims.ExpiresAt.Sub(claims.IssuedAt.Time)
	if lifetime <= 0 || lifetime > time.Minute {
		return nil, errIdentity
	}
	return claims, nil
}

func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := time.Now()
	if now.Before(v.expires) && v.keys[kid] != nil {
		return v.keys[kid], nil
	}
	// Bound outbound requests from repeated unknown key IDs.
	if now.Sub(v.lastAttempt) < 5*time.Second {
		return nil, errIdentity
	}
	v.lastAttempt = now
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, errIdentity
	}
	res, err := v.client.Do(req)
	if err != nil {
		return nil, errIdentity
	}
	defer res.Body.Close()
	var doc struct {
		Keys []struct {
			ID        string `json:"kid"`
			Type      string `json:"kty"`
			Algorithm string `json:"alg"`
			Use       string `json:"use"`
			N         string `json:"n"`
			E         string `json:"e"`
		} `json:"keys"`
	}
	if res.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&doc) != nil {
		return nil, errIdentity
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, key := range doc.Keys {
		nBytes, nErr := base64.RawURLEncoding.DecodeString(key.N)
		eBytes, eErr := base64.RawURLEncoding.DecodeString(key.E)
		n, e := new(big.Int).SetBytes(nBytes), new(big.Int).SetBytes(eBytes)
		if key.Type != "RSA" || (key.Algorithm != "" && key.Algorithm != "RS256") ||
			(key.Use != "" && key.Use != "sig") || nErr != nil || eErr != nil ||
			n.BitLen() < 2048 || n.BitLen() > 8192 || e.BitLen() > 31 || e.Int64() < 3 || e.Bit(0) != 1 {
			continue
		}
		if keys[key.ID] != nil {
			return nil, errIdentity
		}
		keys[key.ID] = &rsa.PublicKey{N: n, E: int(e.Int64())}
	}
	v.keys, v.expires = keys, now.Add(5*time.Minute)
	if keys[kid] == nil {
		return nil, errIdentity
	}
	return keys[kid], nil
}
