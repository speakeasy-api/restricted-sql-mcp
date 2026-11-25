package tunnelidentity

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAssertionVerification(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const audience = "tunneled-mcp-server:staff-pilot"
	const organization = "staff-org"
	now := time.Now().Truncate(time.Second)
	verifier := New(audience, organization)
	verifier.keys = map[string]*rsa.PublicKey{kid: &key.PublicKey}
	verifier.expires = now.Add(5 * time.Minute)

	cases := []struct {
		name   string
		change func(*Claims, *jwt.Token)
		want   bool
	}{
		{"runtime", func(*Claims, *jwt.Token) {}, true},
		{"organization", func(c *Claims, _ *jwt.Token) { c.Organization = "another-org" }, false},
		{"issuer", func(c *Claims, _ *jwt.Token) { c.Issuer = "https://example.test" }, false},
		{"audience", func(c *Claims, _ *jwt.Token) { c.Audience = []string{audience + "/"} }, false},
		{"multiple audiences", func(c *Claims, _ *jwt.Token) { c.Audience = append(c.Audience, "other") }, false},
		{"missing iat", func(c *Claims, _ *jwt.Token) { c.IssuedAt = nil }, false},
		{"missing exp", func(c *Claims, _ *jwt.Token) { c.ExpiresAt = nil }, false},
		{"long lived", func(c *Claims, _ *jwt.Token) { c.ExpiresAt = jwt.NewNumericDate(now.Add(61 * time.Second)) }, false},
		{"future issuance", func(c *Claims, _ *jwt.Token) { c.IssuedAt = jwt.NewNumericDate(now.Add(10 * time.Second)) }, false},
		{"expired", func(c *Claims, _ *jwt.Token) {
			c.IssuedAt = jwt.NewNumericDate(now.Add(-30 * time.Second))
			c.ExpiresAt = jwt.NewNumericDate(now.Add(-10 * time.Second))
		}, false},
		{"type", func(_ *Claims, tk *jwt.Token) { tk.Header["typ"] = "JWT" }, false},
		{"version", func(c *Claims, _ *jwt.Token) { c.Version++ }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := &Claims{
				Version: 1, Organization: organization,
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer: Issuer, Subject: "user:pilot", Audience: []string{audience},
					IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(60 * time.Second)), ID: "assertion",
				},
			}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"], token.Header["typ"] = kid, "speakeasy-identity+jwt"
			tc.change(claims, token)
			value, err := token.SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", "/mcp", nil)
			req.Header.Set(Header, value)
			if _, err := verifier.Verify(req); (err == nil) != tc.want {
				t.Fatalf("verify result = %v, want acceptance %v", err, tc.want)
			}
			req.Header.Add(Header, value)
			if _, err := verifier.Verify(req); err == nil {
				t.Fatal("accepted duplicate identity headers")
			}
		})
	}
}

func TestDiscoveryMethods(t *testing.T) {
	claims := Claims{AllowedMethods: json.RawMessage(`["tools/list","tools/call"]`)}
	if !claims.AllowsMethod("tools/list") || claims.AllowsMethod("tools/call") || claims.AllowsMethod("initialize") {
		t.Fatal("discovery must intersect the assertion list with discovery methods")
	}
	claims.AllowedMethods = json.RawMessage("null")
	if claims.AllowsMethod("tools/call") {
		t.Fatal("present null claim was treated as a runtime assertion")
	}
}
