package dbsec

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/policy"
)

// scramIterations matches the Postgres default for SCRAM-SHA-256 verifiers.
const scramIterations = 4096

// PostgresProvisioner creates <prefix>_ro and, when writes are enabled,
// <prefix>_rw as LOGIN roles with fresh passwords and exactly the grants the
// policy needs. Everything runs in one transaction on a bootstrap connection
// that is closed before returning.
type PostgresProvisioner struct {
	DSN    string
	Policy *policy.Policy
	Prefix string
	Logger *slog.Logger
}

// statement is one provisioning statement and how it is reported.
type statement struct {
	sql     string
	display string // sql with the password replaced, for errors and logs
}

func (p *PostgresProvisioner) readRole() string  { return p.Prefix + "_ro" }
func (p *PostgresProvisioner) writeRole() string { return p.Prefix + "_rw" }

// Provision implements Provisioner.
func (p *PostgresProvisioner) Provision(ctx context.Context) (Creds, error) {
	log := p.Logger
	if log == nil {
		log = slog.Default()
	}
	roPass, err := NewPassword()
	if err != nil {
		return Creds{}, err
	}
	rwPass, err := NewPassword()
	if err != nil {
		return Creds{}, err
	}

	conn, err := pgx.Connect(ctx, p.DSN)
	if err != nil {
		return Creds{}, fmt.Errorf("bootstrap connection: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = conn.Close(closeCtx)
	}()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return Creds{}, fmt.Errorf("begin provisioning transaction: %w", err)
	}
	defer func() {
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(rbCtx)
	}()

	useScram, err := scramEnabled(ctx, tx)
	if err != nil {
		return Creds{}, err
	}
	schemas, err := revocableSchemas(ctx, tx)
	if err != nil {
		return Creds{}, err
	}
	readTables := sortedRefs(p.Policy.ReadTables)
	writeTables := sortedRefs(p.Policy.WriteTables)

	summary := log.With("read_role", p.readRole())
	roStmts, err := roleStatements(p.readRole(), roPass, useScram, p.Policy, schemas)
	if err != nil {
		return Creds{}, err
	}
	roStmts = append(roStmts, grantStatements(p.readRole(), readTables, nil, nil)...)
	if err := runStatements(ctx, tx, roStmts); err != nil {
		return Creds{}, err
	}
	summary = summary.With("read_role_select", refStrings(readTables))

	var writeSeqs []policy.TableRef
	if p.Policy.WritesEnabled {
		writeSeqs, err = ownedSequences(ctx, tx, writeTables)
		if err != nil {
			return Creds{}, err
		}
		rwStmts, err := roleStatements(p.writeRole(), rwPass, useScram, p.Policy, schemas)
		if err != nil {
			return Creds{}, err
		}
		rwStmts = append(rwStmts, grantStatements(p.writeRole(), readTables, writeTables, writeSeqs)...)
		if err := runStatements(ctx, tx, rwStmts); err != nil {
			return Creds{}, err
		}
		summary = summary.With("write_role", p.writeRole(),
			"write_role_select", refStrings(append(append([]policy.TableRef{}, readTables...), writeTables...)),
			"write_role_insert_update_delete", refStrings(writeTables),
			"write_role_sequences", refStrings(writeSeqs))
	}
	if err := tx.Commit(ctx); err != nil {
		return Creds{}, fmt.Errorf("commit provisioning transaction: %w", err)
	}
	summary.Info("postgres roles provisioned", "schemas_revoked", schemas, "password_rotated", true)

	creds := Creds{}
	if creds.ReadDSN, err = RewriteDSN(p.DSN, p.readRole(), roPass); err != nil {
		return Creds{}, err
	}
	if p.Policy.WritesEnabled {
		if creds.WriteDSN, err = RewriteDSN(p.DSN, p.writeRole(), rwPass); err != nil {
			return Creds{}, err
		}
	}
	return creds, nil
}

// scramEnabled reports whether the server hashes new passwords with
// SCRAM-SHA-256, in which case the verifier is computed client-side so the
// plaintext never appears in a statement (and so never in server logs).
func scramEnabled(ctx context.Context, tx pgx.Tx) (bool, error) {
	var enc string
	if err := tx.QueryRow(ctx, "SHOW password_encryption").Scan(&enc); err != nil {
		return false, &StatementError{Statement: "SHOW password_encryption", Err: err}
	}
	return strings.EqualFold(enc, "scram-sha-256"), nil
}

// revocableSchemas lists the schemas the bootstrap role can address with
// REVOKE ... IN SCHEMA (it needs USAGE to resolve them). System schemas are
// skipped: nothing is ever granted there and revoking is a no-op.
func revocableSchemas(ctx context.Context, tx pgx.Tx) ([]string, error) {
	const q = `
SELECT nspname FROM pg_catalog.pg_namespace
WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
  AND nspname NOT LIKE 'pg\_temp\_%'
  AND nspname NOT LIKE 'pg\_toast\_temp\_%'
  AND has_schema_privilege(nspname, 'USAGE')
ORDER BY nspname`
	rows, err := tx.Query(ctx, q)
	if err != nil {
		return nil, &StatementError{Statement: "SELECT nspname FROM pg_namespace", Err: err}
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, &StatementError{Statement: "SELECT nspname FROM pg_namespace", Err: err}
	}
	return out, nil
}

// ownedSequences finds the sequences the write tables depend on: serial and
// identity sequences (pg_depend auto/internal) and any sequence referenced by
// a column default (pg_attrdef).
func ownedSequences(ctx context.Context, tx pgx.Tx, tables []policy.TableRef) ([]policy.TableRef, error) {
	const q = `
SELECT n.nspname, s.relname
FROM pg_catalog.pg_class s
JOIN pg_catalog.pg_namespace n ON n.oid = s.relnamespace
JOIN pg_catalog.pg_depend d ON d.classid = 'pg_catalog.pg_class'::regclass AND d.objid = s.oid
JOIN pg_catalog.pg_class t ON d.refclassid = 'pg_catalog.pg_class'::regclass AND t.oid = d.refobjid
JOIN pg_catalog.pg_namespace tn ON tn.oid = t.relnamespace
WHERE s.relkind = 'S' AND d.deptype IN ('a', 'i') AND tn.nspname = $1 AND t.relname = $2
UNION
SELECT n.nspname, s.relname
FROM pg_catalog.pg_attrdef ad
JOIN pg_catalog.pg_class t ON t.oid = ad.adrelid
JOIN pg_catalog.pg_namespace tn ON tn.oid = t.relnamespace
JOIN pg_catalog.pg_depend d ON d.classid = 'pg_catalog.pg_attrdef'::regclass AND d.objid = ad.oid
JOIN pg_catalog.pg_class s ON d.refclassid = 'pg_catalog.pg_class'::regclass AND s.oid = d.refobjid AND s.relkind = 'S'
JOIN pg_catalog.pg_namespace n ON n.oid = s.relnamespace
WHERE tn.nspname = $1 AND t.relname = $2
ORDER BY 1, 2`
	seen := map[policy.TableRef]struct{}{}
	var out []policy.TableRef
	for _, t := range tables {
		rows, err := tx.Query(ctx, q, t.Schema, t.Name)
		if err != nil {
			return nil, &StatementError{Statement: "SELECT sequences owned by " + t.String(), Err: err}
		}
		for rows.Next() {
			var r policy.TableRef
			if err := rows.Scan(&r.Schema, &r.Name); err != nil {
				rows.Close()
				return nil, err
			}
			if _, dup := seen[r]; !dup {
				seen[r] = struct{}{}
				out = append(out, r)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, &StatementError{Statement: "SELECT sequences owned by " + t.String(), Err: err}
		}
	}
	return out, nil
}

// roleStatements creates or updates the role with a new password and the
// hardening attributes, pins its session settings, and revokes everything
// the bootstrap connection can address.
func roleStatements(role, password string, useScram bool, pol *policy.Policy, schemas []string) ([]statement, error) {
	ident := pgx.Identifier{role}.Sanitize()
	secret := password
	if useScram {
		verifier, err := scramVerifier(password)
		if err != nil {
			return nil, err
		}
		secret = verifier
	}
	const attrs = " WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION PASSWORD "
	stmts := []statement{{
		sql: fmt.Sprintf(`DO $rsq$ BEGIN
IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = %s) THEN
  EXECUTE 'ALTER ROLE ' || quote_ident(%s) || %s;
ELSE
  EXECUTE 'CREATE ROLE ' || quote_ident(%s) || %s;
END IF;
END $rsq$`,
			pgLiteral(role), pgLiteral(role), pgLiteral(attrs+pgLiteral(secret)),
			pgLiteral(role), pgLiteral(attrs+pgLiteral(secret))),
		display: "CREATE OR ALTER ROLE " + ident + attrs + "'<redacted>'",
	}}
	stmts = append(stmts,
		plain("ALTER ROLE "+ident+" SET search_path = "+pgx.Identifier{pol.DefaultSchema}.Sanitize()),
		plain(fmt.Sprintf("ALTER ROLE %s SET statement_timeout = %d", ident, pol.StatementTimeout.Milliseconds())),
	)
	for _, s := range schemas {
		sid := pgx.Identifier{s}.Sanitize()
		stmts = append(stmts,
			plain("REVOKE ALL ON ALL TABLES IN SCHEMA "+sid+" FROM "+ident),
			plain("REVOKE ALL ON ALL SEQUENCES IN SCHEMA "+sid+" FROM "+ident),
			plain("REVOKE ALL ON SCHEMA "+sid+" FROM "+ident),
		)
	}
	return stmts, nil
}

// grantStatements grants USAGE on the schemas of read ∪ write, SELECT on
// read ∪ write, INSERT/UPDATE/DELETE on write, and USAGE+SELECT on the write
// tables' sequences.
func grantStatements(role string, read, write, seqs []policy.TableRef) []statement {
	ident := pgx.Identifier{role}.Sanitize()
	var stmts []statement
	schemas := map[string]struct{}{}
	for _, t := range append(append([]policy.TableRef{}, read...), write...) {
		schemas[t.Schema] = struct{}{}
	}
	for _, s := range sortedKeys(schemas) {
		stmts = append(stmts, plain("GRANT USAGE ON SCHEMA "+pgx.Identifier{s}.Sanitize()+" TO "+ident))
	}
	for _, t := range read {
		stmts = append(stmts, plain("GRANT SELECT ON TABLE "+refIdent(t)+" TO "+ident))
	}
	for _, t := range write {
		stmts = append(stmts, plain("GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "+refIdent(t)+" TO "+ident))
	}
	for _, s := range seqs {
		stmts = append(stmts, plain("GRANT USAGE, SELECT ON SEQUENCE "+refIdent(s)+" TO "+ident))
	}
	return stmts
}

func runStatements(ctx context.Context, tx pgx.Tx, stmts []statement) error {
	for _, st := range stmts {
		if _, err := tx.Exec(ctx, st.sql); err != nil {
			return &StatementError{Statement: st.display, Err: err}
		}
	}
	return nil
}

// scramVerifier builds a SCRAM-SHA-256 verifier in the form Postgres stores
// in pg_authid, so the server receives a hash instead of the password.
func scramVerifier(password string) (string, error) {
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	salted, err := pbkdf2.Key(sha256.New, password, salt[:], scramIterations, sha256.Size)
	if err != nil {
		return "", fmt.Errorf("derive scram key: %w", err)
	}
	clientKey := hmacSHA256(salted, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	serverKey := hmacSHA256(salted, "Server Key")
	enc := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", scramIterations, enc(salt[:]), enc(storedKey[:]), enc(serverKey)), nil
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

func plain(sql string) statement { return statement{sql: sql, display: sql} }

// pgLiteral quotes s as a Postgres string literal. Backslashes are literal
// under standard_conforming_strings, the default since 9.1.
func pgLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func refIdent(t policy.TableRef) string { return pgx.Identifier{t.Schema, t.Name}.Sanitize() }

func sortedRefs(m map[policy.TableRef]struct{}) []policy.TableRef {
	out := make([]policy.TableRef, 0, len(m))
	for r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func refStrings(refs []policy.TableRef) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.String())
	}
	return out
}
