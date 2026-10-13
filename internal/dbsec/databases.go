package dbsec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
)

// maxRolePrefix is the longest prefix that leaves room for the "_ro"/"_rw"
// suffix inside Postgres's 63-byte identifier limit (see rolePrefixRE in
// package config).
const maxRolePrefix = 60

// roleHashLen is the number of hex characters of the name hash appended when
// a database name cannot be used verbatim in a role name.
const roleHashLen = 8

// WithDatabase points a URL-form DSN at another database on the same server,
// keeping credentials, host and every other parameter. Query parameters that
// would override the path's database are removed. Errors never include the DSN.
func WithDatabase(dsn, database string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", errors.New("dsn must be a URL of the form scheme://user:password@host:port/database")
	}
	u.Path = "/" + database
	u.RawPath = ""
	q := u.Query()
	stripped := false
	for _, k := range []string{"dbname", "database"} {
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

// DatabaseRolePrefix derives the role prefix for an additional database, so
// that every database served by one process gets its own login roles (roles
// are cluster-wide in Postgres). The result is <prefix>_<database> when the
// database name is already a plain lowercase identifier and fits; otherwise
// the sanitized name is truncated and a short hash of the original name is
// appended, so distinct databases always map to distinct prefixes. The result
// is at most 60 bytes of [a-z0-9_] and starts with the prefix's first byte.
func DatabaseRolePrefix(prefix, database string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(database) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	sanitized := b.String()
	candidate := prefix + "_" + sanitized
	if sanitized == database && len(candidate) <= maxRolePrefix {
		return candidate
	}
	sum := sha256.Sum256([]byte(prefix + "\x00" + database))
	hash := hex.EncodeToString(sum[:])[:roleHashLen]
	keep := maxRolePrefix - roleHashLen - 1
	if len(candidate) > keep {
		candidate = candidate[:keep]
	}
	return candidate + "_" + hash
}

// Roles lists the login roles this provisioner manages.
func (p *PostgresProvisioner) Roles() []string {
	roles := []string{p.readRole()}
	if p.Policy.WritesEnabled {
		roles = append(roles, p.writeRole())
	}
	return roles
}

// DropRoles drops the given roles over a bootstrap connection, continuing past
// failures. It returns the roles that were dropped (or were already absent)
// and the joined errors of the rest.
func DropRoles(ctx context.Context, dsn string, roles []string) ([]string, error) {
	if len(roles) == 0 {
		return nil, nil
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("bootstrap connection: %w", err)
	}
	defer closePG(conn)
	var dropped []string
	var errs []error
	for _, role := range roles {
		stmt := "DROP ROLE IF EXISTS " + pgx.Identifier{role}.Sanitize()
		if _, err := conn.Exec(ctx, stmt); err != nil {
			errs = append(errs, &StatementError{Statement: stmt, Err: err})
			continue
		}
		dropped = append(dropped, role)
	}
	return dropped, errors.Join(errs...)
}
