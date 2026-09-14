// Package dbsec provisions least-privilege database roles from a bootstrap
// connection and routes tool traffic through pools connected as those roles.
// It is a second security layer, independent of the SQL guard: even if a
// statement slipped past the guard, the database itself would refuse access
// to anything outside the allowlist.
package dbsec

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
)

// Creds are the derived DSNs tool traffic runs on. WriteDSN is empty when
// writes are disabled.
type Creds struct {
	ReadDSN  string
	WriteDSN string
}

// Provisioner creates or updates the restricted roles and returns the DSNs
// that authenticate as them. Provision must be idempotent: it is retried until
// it succeeds and re-run on every boot.
type Provisioner interface {
	Provision(ctx context.Context) (Creds, error)
}

// NotProvisionedError is returned by every gated operation until provisioning
// has succeeded. Its text is the /readyz reason and the tool error.
type NotProvisionedError struct {
	Err error
}

func (e *NotProvisionedError) Error() string {
	return "connection-level security not provisioned: " + e.Err.Error()
}

func (e *NotProvisionedError) Unwrap() error { return e.Err }

// StatementError names the provisioning statement that failed. Passwords are
// never part of Statement; role statements are rendered with a placeholder.
type StatementError struct {
	Statement string
	Err       error
}

func (e *StatementError) Error() string {
	return fmt.Sprintf("statement %q failed: %v", e.Statement, e.Err)
}

func (e *StatementError) Unwrap() error { return e.Err }

// passwordBytes is the entropy of each generated password.
const passwordBytes = 32

// NewPassword returns a fresh random password as lowercase hex, so it is safe
// inside SQL string literals and URL userinfo without escaping.
func NewPassword() (string, error) {
	var b [passwordBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate password: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// credentialQueryKeys are query parameters that would override the userinfo
// credentials in pgx (libpq keywords) or clickhouse-go DSNs.
var credentialQueryKeys = []string{"user", "username", "password"}

// RewriteDSN replaces the credentials of a URL-form DSN, keeping scheme, host,
// port, path and every other query parameter. Errors never include the DSN.
func RewriteDSN(dsn, user, password string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", errors.New("dsn must be a URL of the form scheme://user:password@host:port/database")
	}
	u.User = url.UserPassword(user, password)
	q := u.Query()
	stripped := false
	for _, k := range credentialQueryKeys {
		if q.Has(k) {
			q.Del(k)
			stripped = true
		}
	}
	if stripped {
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}
