package dbsec

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
)

// ReconcileReplicaGrants applies the configured annotation policy to existing, dedicated
// logins. Role creation and credentials are managed separately. The returned
// WAL position is a conservative replay floor for opening the replica.
func ReconcileReplicaGrants(ctx context.Context, dsn string, roles []string, base *policy.Policy) (string, error) {
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
		return "", errors.New("another replica grant reconciliation is running")
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
		if err := verifyReplicaRole(ctx, tx, role); err != nil {
			return "", err
		}
		// PostgreSQL also revokes the matching column ACLs on a table REVOKE.
		stmts, err := heldPrivilegeRevokes(ctx, tx, role)
		if err != nil {
			return "", err
		}
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
		if err := verifyReplicaGrants(ctx, tx, role, pol); err != nil {
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

// ReplicaProbe publishes one immutable catalog and grant snapshot for all
// configured logins. The caller runs Refresh serially.
type ReplicaProbe struct {
	VerifierDSN, VerifierRole, ExpectedLSN string
	Roles                                  []string
	latest                                 atomic.Pointer[replicaSnapshot]
}

type replicaSnapshot struct {
	catalog    *policy.Catalog
	roleErrors map[string]error
	err        error
}

func (p *ReplicaProbe) Refresh(ctx context.Context, base *policy.Policy) error {
	snapshot, err := p.inspect(ctx, base)
	if err != nil {
		snapshot = &replicaSnapshot{err: err}
	}
	p.latest.Store(snapshot)
	return err
}

func (p *ReplicaProbe) inspect(ctx context.Context, base *policy.Policy) (*replicaSnapshot, error) {
	conn, err := pgx.Connect(ctx, p.VerifierDSN)
	if err != nil {
		return nil, errors.New("could not connect to the read replica")
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
	catalog, err := loadPGAnnotations(ctx, tx)
	if err != nil {
		return nil, err
	}
	pol := base.WithCatalog(catalog)
	snapshot := &replicaSnapshot{catalog: catalog, roleErrors: make(map[string]error, len(p.Roles))}
	for _, role := range p.Roles {
		err := verifyReplicaRole(ctx, tx, role)
		if err == nil {
			err = verifyReplicaGrants(ctx, tx, role, pol)
		}
		snapshot.roleErrors[role] = err
	}
	// An existing hot-standby connection can survive promotion.
	if err := p.checkReplica(ctx, conn, p.VerifierRole); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return snapshot, nil
}

// ReplicaAnnotations supplies one login to the annotation gate. It reads the
// shared probe result and never provisions, changes, or drops database roles.
type ReplicaAnnotations struct {
	ReadDSN, Role string
	Probe         *ReplicaProbe
}

func (p *ReplicaAnnotations) snapshot() (*policy.Catalog, error) {
	snapshot := p.Probe.latest.Load()
	if snapshot == nil {
		return nil, errors.New("replica grant verification has not completed")
	}
	if snapshot.err != nil {
		return nil, snapshot.err
	}
	err, ok := snapshot.roleErrors[p.Role]
	if !ok {
		return nil, errors.New("replica login was omitted from grant verification")
	}
	return snapshot.catalog, err
}

func (p *ReplicaAnnotations) Load(context.Context) (*policy.Catalog, error) {
	return p.snapshot()
}

func (p *ReplicaAnnotations) Reconcile(ctx context.Context, pol *policy.Policy) (Creds, error) {
	if err := p.Verify(ctx, pol); err != nil {
		return Creds{}, err
	}
	return Creds{ReadDSN: p.ReadDSN}, nil
}

func (p *ReplicaAnnotations) Verify(_ context.Context, pol *policy.Policy) error {
	catalog, err := p.snapshot()
	if err != nil {
		return err
	}
	if catalog.Digest != pol.Catalog.Digest {
		return errors.New("replica catalog changed during grant verification")
	}
	return nil
}

func (p *ReplicaAnnotations) Close(context.Context) error { return nil }

// CheckReplica requires a physical standby and the configured role and replay floor.
func (p *ReplicaAnnotations) CheckReplica(ctx context.Context, conn *pgx.Conn) error {
	return p.Probe.checkReplica(ctx, conn, p.Role)
}

func (p *ReplicaProbe) checkReplica(ctx context.Context, conn *pgx.Conn, expectedRole string) error {
	var replica, replayed bool
	var role string
	if err := conn.QueryRow(ctx, "SELECT pg_catalog.pg_is_in_recovery(), coalesce(pg_catalog.pg_last_wal_replay_lsn() >= $1::pg_lsn, false), session_user", p.ExpectedLSN).Scan(&replica, &replayed, &role); err != nil {
		return errors.New("could not verify the read replica")
	}
	if !replica || !replayed || role != expectedRole {
		return errors.New("database must be the configured replica, login and replay position")
	}
	return nil
}

func verifyReplicaRole(ctx context.Context, tx pgx.Tx, role string) error {
	var permitted bool
	err := tx.QueryRow(ctx, `
SELECT rolcanlogin
 AND rolname <> session_user
 AND coalesce(pg_catalog.shobj_description(oid, 'pg_authid') = 'restricted-sql-mcp:reader', false)
FROM pg_catalog.pg_roles WHERE rolname=$1`, role).Scan(&permitted)
	if err != nil || !permitted {
		return fmt.Errorf("replica role %q must be marked with the restricted-sql-mcp:reader role comment", role)
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
		return fmt.Errorf("replica role %q has database CREATE, table MAINTAIN or sequence access", role)
	}
	return nil
}

func verifyReplicaGrants(ctx context.Context, tx pgx.Tx, role string, pol *policy.Policy) error {
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
			return fmt.Errorf("replica login is missing USAGE on schema %q", schema)
		}
	}
	return nil
}
