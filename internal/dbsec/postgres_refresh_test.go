package dbsec

import (
	"context"
	"errors"
	"testing"
)

func TestPostgresGrantRefreshWithoutPendingTables(t *testing.T) {
	p := &PostgresProvisioner{DSN: "invalid"}
	if err := p.RefreshGrants(context.Background()); err != nil {
		t.Fatalf("refresh with no pending tables must not connect: %v", err)
	}
}

func TestPostgresGrantRefreshWaitHonorsContext(t *testing.T) {
	p := &PostgresProvisioner{}
	if err := p.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { <-p.sem }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.RefreshGrants(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("refresh waiting for the in-flight attempt = %v, want canceled", err)
	}
}
