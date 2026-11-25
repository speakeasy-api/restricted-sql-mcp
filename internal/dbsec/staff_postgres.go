package dbsec

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
)

// ReconcileStaffGrants applies the confidential policy to existing, dedicated
// logins. Role creation and credentials are managed separately. The returned
// WAL position is a conservative replay floor for opening the replica.
func ReconcileStaffGrants(ctx context.Context, dsn string, roles []string, base *policy.Policy) (string, error) {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return "", errors.New("could not connect to the grant database")
	}
	defer closePG(conn)
	var replica, locked bool
	if err := conn.QueryRow(ctx, "SELECT pg_catalog.pg_is_in_recovery()").Scan(&replica); err != nil {
		return "", err
	}
	if replica {
		return "", errors.New("grant reconciliation requires the primary")
	}
	if err := conn.QueryRow(ctx, "SELECT pg_catalog.pg_try_advisory_lock(197321181, 5178021)").Scan(&locked); err != nil {
		return "", err
	}
	if !locked {
		return "", errors.New("another staff grant reconciliation is running")
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return "", err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, "SET LOCAL search_path = pg_catalog"); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, "SET LOCAL synchronous_commit = on"); err != nil {
		return "", err
	}
	catalog, err := loadPGAnnotations(ctx, tx)
	if err != nil {
		return "", err
	}
	pol := base.WithCatalog(catalog)
	for _, role := range roles {
		if err := verifyStaffRole(ctx, tx, role); err != nil {
			return "", err
		}
		stmts, err := staffColumnRevokes(ctx, tx, role)
		if err != nil {
			return "", err
		}
		relationRevokes, err := heldPrivilegeRevokes(ctx, tx, role)
		if err != nil {
			return "", err
		}
		stmts = append(stmts, relationRevokes...)
		ident := pgx.Identifier{role}.Sanitize()
		schemas := map[string]bool{}
		for _, ref := range pol.AllTables() {
			cols := pol.ReadableColumns(ref)
			if len(cols) == 0 {
				continue
			}
			if !schemas[ref.Schema] {
				stmts = append(stmts, plain("GRANT USAGE ON SCHEMA "+pgx.Identifier{ref.Schema}.Sanitize()+" TO "+ident))
				schemas[ref.Schema] = true
			}
			quote := func(s string) string { return pgx.Identifier{s}.Sanitize() }
			stmts = append(stmts, plain("GRANT SELECT ("+columnIdents(cols, quote)+") ON "+refIdent(ref)+" TO "+ident))
		}
		if err := runStatements(ctx, tx, stmts); err != nil {
			return "", err
		}
		if err := verifyStaffGrants(ctx, tx, role, pol); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	var lsn string
	err = conn.QueryRow(ctx, "SELECT pg_catalog.pg_current_wal_flush_lsn()::text").Scan(&lsn)
	return lsn, err
}

// ReplicaAnnotations adapts the existing annotation gate without any
// provisioner, ownership credentials, or role cleanup.
type ReplicaAnnotations struct {
	ReadDSN, Role, ExpectedLSN string
	VerifierDSN, VerifierRole  string
	Slots                      chan struct{}
}

func (p *ReplicaAnnotations) Load(ctx context.Context) (*policy.Catalog, error) {
	return p.inspect(ctx, nil)
}

func (p *ReplicaAnnotations) Reconcile(ctx context.Context, pol *policy.Policy) (Creds, error) {
	if err := p.Verify(ctx, pol); err != nil {
		return Creds{}, err
	}
	return Creds{ReadDSN: p.ReadDSN}, nil
}

func (p *ReplicaAnnotations) Verify(ctx context.Context, pol *policy.Policy) error {
	_, err := p.inspect(ctx, pol)
	return err
}

func (p *ReplicaAnnotations) Close(context.Context) error { return nil }

// CheckReplica requires a physical standby and the configured role and replay floor.
func (p *ReplicaAnnotations) CheckReplica(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) error {
	return p.checkReplica(ctx, db, p.Role)
}

func (p *ReplicaAnnotations) checkReplica(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, expectedRole string) error {
	var replica, replayed bool
	var role string
	if err := db.QueryRow(ctx, "SELECT pg_catalog.pg_is_in_recovery(), coalesce(pg_catalog.pg_last_wal_replay_lsn() >= $1::pg_lsn, false), session_user", p.ExpectedLSN).Scan(&replica, &replayed, &role); err != nil {
		return errors.New("could not verify the staff replica")
	}
	if !replica || !replayed || role != expectedRole {
		return errors.New("staff database must be the configured replica, login and replay position")
	}
	return nil
}

func (p *ReplicaAnnotations) inspect(ctx context.Context, pol *policy.Policy) (*policy.Catalog, error) {
	if p.Slots != nil {
		select {
		case p.Slots <- struct{}{}:
			defer func() { <-p.Slots }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	conn, err := pgx.Connect(ctx, p.VerifierDSN)
	if err != nil {
		return nil, errors.New("could not connect to the staff read replica")
	}
	defer closePG(conn)
	// Observe the replay floor before establishing the catalog snapshot.
	if err := p.checkReplica(ctx, conn, p.VerifierRole); err != nil {
		return nil, err
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())
	cat, err := loadPGAnnotations(ctx, tx)
	if err != nil {
		return nil, err
	}
	if pol != nil {
		if pol.Catalog.Digest != cat.Digest {
			return nil, errors.New("replica catalog changed during grant verification")
		}
		if err := verifyStaffRole(ctx, tx, p.Role); err != nil {
			return nil, err
		}
		if err := verifyStaffGrants(ctx, tx, p.Role, pol); err != nil {
			return nil, err
		}
	}
	return cat, tx.Commit(ctx)
}

func verifyStaffRole(ctx context.Context, tx pgx.Tx, role string) error {
	var permitted bool
	err := tx.QueryRow(ctx, `
SELECT rolcanlogin AND (rolname <> session_user OR pg_catalog.pg_is_in_recovery())
FROM pg_catalog.pg_roles WHERE rolname=$1`, role).Scan(&permitted)
	if err != nil || !permitted {
		return fmt.Errorf("staff role %q must be an existing dedicated login", role)
	}
	var excess bool
	err = tx.QueryRow(ctx, `
SELECT pg_catalog.has_database_privilege($1, current_database(), 'CREATE')
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname <> 'information_schema' AND n.nspname !~ '^pg_' AND c.relkind IN ('r','p','m')
 AND CASE WHEN current_setting('server_version_num')::int >= 170000
 THEN pg_catalog.has_table_privilege($1,c.oid,'MAINTAIN') ELSE false END)
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname <> 'information_schema' AND n.nspname !~ '^pg_' AND c.relkind='S'
 AND CASE WHEN c.relkind='S' THEN pg_catalog.has_sequence_privilege($1,c.oid,'USAGE,SELECT,UPDATE') ELSE false END)`, role).Scan(&excess)
	if err != nil {
		return err
	}
	if excess {
		return fmt.Errorf("staff role %q has database CREATE, table MAINTAIN or sequence access", role)
	}
	return nil
}

func staffColumnRevokes(ctx context.Context, tx pgx.Tx, role string) ([]statement, error) {
	rows, err := tx.Query(ctx, `
SELECT n.nspname, c.relname, a.attname
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
WHERE EXISTS (SELECT 1 FROM pg_catalog.aclexplode(a.attacl) acl
 WHERE acl.grantee=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1))
ORDER BY n.nspname,c.relname,a.attnum`, role)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ident := pgx.Identifier{role}.Sanitize()
	var out []statement
	for rows.Next() {
		var schema, table, column string
		if err := rows.Scan(&schema, &table, &column); err != nil {
			return nil, err
		}
		out = append(out, plain("REVOKE ALL ("+pgx.Identifier{column}.Sanitize()+") ON "+
			pgx.Identifier{schema, table}.Sanitize()+" FROM "+ident))
	}
	return out, rows.Err()
}

func verifyStaffGrants(ctx context.Context, tx pgx.Tx, role string, pol *policy.Policy) error {
	if err := verifyPGAnnotations(ctx, tx, role, pol); err != nil {
		return err
	}
	schemas := map[string]bool{}
	for _, ref := range pol.AllTables() {
		if len(pol.ReadableColumns(ref)) > 0 {
			schemas[ref.Schema] = true
		}
	}
	for schema := range schemas {
		var usage bool
		if err := tx.QueryRow(ctx, "SELECT pg_catalog.has_schema_privilege($1, $2, 'USAGE')", role, schema).Scan(&usage); err != nil {
			return err
		}
		if !usage {
			return fmt.Errorf("staff login is missing USAGE on schema %q", schema)
		}
	}
	return nil
}
