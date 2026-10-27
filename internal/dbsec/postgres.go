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

	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
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
	// The configured policy may predate a migration. Re-read the catalog for
	// every attempt rather than trying to grant privileges on deleted tables.
	// Keep the shared policy immutable; this only narrows this attempt's grants.
	configuredTables := p.Policy.AllTables()
	existing, err := existingPolicyTables(ctx, tx, configuredTables)
	if err != nil {
		return Creds{}, err
	}
	filter := func(configured map[policy.TableRef]struct{}) []policy.TableRef {
		var refs []policy.TableRef
		for _, ref := range sortedRefs(configured) {
			if existing[ref] {
				refs = append(refs, ref)
			}
		}
		return refs
	}
	readTables := filter(p.Policy.ReadTables)
	writeTables := filter(p.Policy.WriteTables)

	summary := log.With("read_role", p.readRole())
	roRevokes, err := heldPrivilegeRevokes(ctx, tx, p.readRole())
	if err != nil {
		return Creds{}, err
	}
	revoked := len(roRevokes)
	roStmts, err := roleStatements(p.readRole(), roPass, useScram, p.Policy, roRevokes)
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
		rwRevokes, err := heldPrivilegeRevokes(ctx, tx, p.writeRole())
		if err != nil {
			return Creds{}, err
		}
		revoked += len(rwRevokes)
		rwStmts, err := roleStatements(p.writeRole(), rwPass, useScram, p.Policy, rwRevokes)
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
	summary.Info("postgres roles provisioned", "stale_privileges_revoked", revoked, "password_rotated", true,
		"missing_tables_skipped", len(configuredTables)-len(existing))

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

// existingPolicyTables checks existence, not the bootstrap's privileges. A
// present table without grant permission must still fail provisioning.
func existingPolicyTables(ctx context.Context, tx pgx.Tx, refs []policy.TableRef) (map[policy.TableRef]bool, error) {
	found := make(map[policy.TableRef]bool, len(refs))
	if len(refs) == 0 {
		return found, nil
	}
	schemas, names := make([]string, len(refs)), make([]string, len(refs))
	for i, ref := range refs {
		schemas[i], names[i] = ref.Schema, ref.Name
	}
	const query = `SELECT n.nspname, c.relname
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
JOIN unnest($1::text[], $2::text[]) AS wanted(schema_name, table_name)
  ON wanted.schema_name = n.nspname AND wanted.table_name = c.relname`
	rows, err := tx.Query(ctx, query, schemas, names)
	if err != nil {
		return nil, &StatementError{Statement: "SELECT existing allowlisted tables", Err: err}
	}
	defer rows.Close()
	for rows.Next() {
		var ref policy.TableRef
		if err := rows.Scan(&ref.Schema, &ref.Name); err != nil {
			return nil, err
		}
		found[ref] = true
	}
	if err := rows.Err(); err != nil {
		return nil, &StatementError{Statement: "SELECT existing allowlisted tables", Err: err}
	}
	return found, nil
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

// heldPrivilegeRevokes returns a REVOKE for every table, sequence, column
// and schema whose ACL names role, so a role left over from an earlier
// process starts empty. It names only objects the role holds privileges on,
// so a bootstrap that does not own the schema never needs rights on unrelated
// objects. Privileges another grantor gave are not removed; the grant audit
// that follows rejects them.
func heldPrivilegeRevokes(ctx context.Context, tx pgx.Tx, role string) ([]statement, error) {
	const q = `
WITH r AS (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1)
SELECT CASE c.relkind WHEN 'S' THEN 'SEQUENCE' ELSE 'TABLE' END, n.nspname, c.relname
FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
  AND (EXISTS (SELECT 1 FROM pg_catalog.aclexplode(c.relacl) a WHERE a.grantee = (SELECT oid FROM r))
    OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute att, pg_catalog.aclexplode(att.attacl) a
               WHERE att.attrelid = c.oid AND a.grantee = (SELECT oid FROM r)))
UNION ALL
SELECT 'SCHEMA', n.nspname, ''
FROM pg_catalog.pg_namespace n
WHERE EXISTS (SELECT 1 FROM pg_catalog.aclexplode(n.nspacl) a WHERE a.grantee = (SELECT oid FROM r))
ORDER BY 1, 2, 3`
	rows, err := tx.Query(ctx, q, role)
	if err != nil {
		return nil, &StatementError{Statement: "SELECT privileges held by " + role, Err: err}
	}
	defer rows.Close()
	ident := pgx.Identifier{role}.Sanitize()
	var out []statement
	for rows.Next() {
		var kind, schema, name string
		if err := rows.Scan(&kind, &schema, &name); err != nil {
			return nil, err
		}
		target := pgx.Identifier{schema}.Sanitize()
		if kind != "SCHEMA" {
			target = pgx.Identifier{schema, name}.Sanitize()
		}
		out = append(out, plain("REVOKE ALL ON "+kind+" "+target+" FROM "+ident))
	}
	if err := rows.Err(); err != nil {
		return nil, &StatementError{Statement: "SELECT privileges held by " + role, Err: err}
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
// hardening attributes, pins its session settings, and revokes every
// privilege the role holds. It works for a superuser bootstrap and for a
// plain CREATEROLE bootstrap: a non-superuser may not name SUPERUSER,
// REPLICATION, BYPASSRLS or CREATEDB in ALTER ROLE, so for an existing role
// it asserts those are off instead of setting them.
func roleStatements(role, password string, useScram bool, pol *policy.Policy, revokes []statement) ([]statement, error) {
	ident := pgx.Identifier{role}.Sanitize()
	secret := password
	if useScram {
		verifier, err := scramVerifier(password)
		if err != nil {
			return nil, err
		}
		secret = verifier
	}
	const createAttrs = " WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD "
	const superAttrs = " WITH NOSUPERUSER NOCREATEDB NOREPLICATION NOBYPASSRLS"
	const alterAttrs = " WITH LOGIN NOCREATEROLE NOINHERIT PASSWORD "
	stmts := []statement{{
		sql: fmt.Sprintf(`DO $rsq$ BEGIN
IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = %[1]s) THEN
  IF (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user) THEN
    EXECUTE 'ALTER ROLE ' || quote_ident(%[1]s) || %[2]s;
  ELSIF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = %[1]s AND (rolsuper OR rolcreatedb OR rolreplication OR rolbypassrls)) THEN
    RAISE EXCEPTION 'existing role %% has SUPERUSER, CREATEDB, REPLICATION or BYPASSRLS, which a non-superuser bootstrap cannot remove', %[1]s;
  END IF;
  EXECUTE 'ALTER ROLE ' || quote_ident(%[1]s) || %[3]s;
ELSE
  EXECUTE 'CREATE ROLE ' || quote_ident(%[1]s) || %[4]s;
END IF;
END $rsq$`,
			pgLiteral(role), pgLiteral(superAttrs), pgLiteral(alterAttrs+pgLiteral(secret)), pgLiteral(createAttrs+pgLiteral(secret))),
		display: "CREATE OR ALTER ROLE " + ident + createAttrs + "'<redacted>'",
	}}
	stmts = append(stmts,
		plain("ALTER ROLE "+ident+" SET search_path = "+pgx.Identifier{pol.DefaultSchema}.Sanitize()),
		plain(fmt.Sprintf("ALTER ROLE %s SET statement_timeout = %d", ident, pol.StatementTimeout.Milliseconds())),
	)
	return append(stmts, revokes...), nil
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
