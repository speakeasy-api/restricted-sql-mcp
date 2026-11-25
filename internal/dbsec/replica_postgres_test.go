package dbsec

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
)

// Run against an isolated primary and its streaming standby. The primary
// must accept the test admin DSN. Never point this test at a shared database.
func TestGrantsOnPrimaryAndReplica(t *testing.T) {
	primary, replica := os.Getenv("REPLICA_TEST_PRIMARY"), os.Getenv("REPLICA_TEST_REPLICA")
	if primary == "" || replica == "" {
		t.Skip("requires isolated REPLICA_TEST_PRIMARY and REPLICA_TEST_REPLICA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, primary)
	if err != nil {
		t.Fatal(err)
	}
	defer closePG(admin)

	_, err = admin.Exec(ctx, `
CREATE ROLE "example_reader" LOGIN PASSWORD 'pilot-password';
CREATE ROLE restricted_sql_verify LOGIN PASSWORD 'verify-password';
CREATE ROLE restricted_sql_grants LOGIN PASSWORD 'grant-password';
CREATE SCHEMA replica_test;
CREATE TABLE replica_test.records (allowed text, hidden text);
INSERT INTO replica_test.records VALUES ('a', 'b');
COMMENT ON COLUMN replica_test.records.allowed IS '@access: confidential';
GRANT USAGE ON SCHEMA replica_test TO restricted_sql_grants WITH GRANT OPTION;
GRANT SELECT ON replica_test.records TO restricted_sql_grants WITH GRANT OPTION;
`)
	if err != nil {
		t.Fatal(err)
	}
	const role = "example_reader"
	grantsDSN, _ := RewriteDSN(primary, "restricted_sql_grants", "grant-password")
	readDSN, _ := RewriteDSN(replica, role, "pilot-password")
	verifyDSN, _ := RewriteDSN(replica, "restricted_sql_verify", "verify-password")
	pol := &policy.Policy{Dialect: policy.Postgres, AnnotationTiers: map[policy.Tier]bool{"confidential": true}}
	reconcile := func() string {
		t.Helper()
		lsn, err := ReconcileReplicaGrants(ctx, grantsDSN, []string{role}, pol)
		if err != nil {
			t.Fatal(err)
		}
		return lsn
	}
	reconcile()
	lsn := reconcile()
	probe := &ReplicaProbe{
		Roles: []string{role, "missing_reader"}, ExpectedLSN: lsn,
		VerifierDSN: verifyDSN, VerifierRole: "restricted_sql_verify",
	}
	source := ReplicaAnnotations{ReadDSN: readDSN, Role: role, Probe: probe}
	awaitCatalog := func(source ReplicaAnnotations) *policy.Catalog {
		t.Helper()
		for ctx.Err() == nil {
			if err := source.Probe.Refresh(ctx, pol); err == nil {
				if catalog, err := source.Load(ctx); err == nil {
					return catalog
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("standby did not reach the replay floor")
		return nil
	}
	catalog := awaitCatalog(source)
	missing := ReplicaAnnotations{Role: "missing_reader", Probe: probe}
	if _, err := missing.Load(ctx); err == nil {
		t.Fatal("published a policy for a missing login")
	}
	if err := source.Verify(ctx, pol.WithCatalog(catalog)); err != nil {
		t.Fatal(err)
	}

	reader, err := pgx.Connect(ctx, readDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer closePG(reader)
	if err := source.CheckReplica(ctx, reader); err != nil {
		t.Fatal(err)
	}
	var value string
	if err := reader.QueryRow(ctx, "SELECT allowed FROM replica_test.records").Scan(&value); err != nil || value != "a" {
		t.Fatalf("permitted column result: %q, %v", value, err)
	}
	if err := reader.QueryRow(ctx, "SELECT hidden FROM replica_test.records").Scan(&value); err == nil {
		t.Fatal("unclassified column was readable")
	}

	primaryVerifyDSN, _ := RewriteDSN(primary, probe.VerifierRole, "verify-password")
	wrongEndpoint := &ReplicaProbe{VerifierDSN: primaryVerifyDSN, VerifierRole: probe.VerifierRole, ExpectedLSN: lsn}
	if err := wrongEndpoint.Refresh(ctx, pol); err == nil {
		t.Fatal("serving verifier accepted the primary")
	}
	stale := &ReplicaProbe{VerifierDSN: verifyDSN, VerifierRole: probe.VerifierRole, ExpectedLSN: "FFFFFFFF/FFFFFFFF"}
	if err := stale.Refresh(ctx, pol); err == nil {
		t.Fatal("serving verifier accepted stale WAL replay")
	}
	standbyGrants, _ := RewriteDSN(replica, "restricted_sql_grants", "grant-password")
	if _, err := ReconcileReplicaGrants(ctx, standbyGrants, []string{role}, pol); err == nil || !strings.Contains(err.Error(), "requires the primary") {
		t.Fatalf("reconciliation on standby returned %v", err)
	}

	if _, err := admin.Exec(ctx, "COMMENT ON COLUMN replica_test.records.allowed IS '@access: restricted'"); err != nil {
		t.Fatal(err)
	}
	probe.ExpectedLSN = reconcile()
	catalog = awaitCatalog(source)
	if err := source.Verify(ctx, pol.WithCatalog(catalog)); err != nil {
		t.Fatal(err)
	}
	if err := reader.QueryRow(ctx, "SELECT allowed FROM replica_test.records").Scan(&value); err == nil {
		t.Fatal("reclassified column was still readable")
	}
}
