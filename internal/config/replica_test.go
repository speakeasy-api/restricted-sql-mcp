package config

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestReplicaModesUseConfiguredRoster(t *testing.T) {
	principals := make([]ReplicaPrincipal, 6)
	for i := range principals {
		principals[i] = ReplicaPrincipal{
			GramUserID:    fmt.Sprintf("caller.%d", i),
			DatabaseLogin: fmt.Sprintf("reader_%d", i),
		}
	}
	roster, err := json.Marshal(principals)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"RESTRICTED_SQL_ROSTER": string(roster)}
	parse := func(mode string, flags ...string) (*Config, error) {
		t.Helper()
		args := []string{"--dialect=postgres", "--columns-from-annotations=confidential", "--replica-mode=" + mode}
		return ParseFlags(append(args, flags...), func(key string) string { return env[key] }, "test")
	}

	env["DATABASE_URL"] = "postgres://grants:secret@127.0.0.1:5432/example?sslmode=disable"
	reconcile, err := parse("reconcile")
	if err != nil {
		t.Fatal(err)
	}

	env["DATABASE_URL"] = "postgres://127.0.0.1:5432/example?sslmode=disable"
	env["RESTRICTED_SQL_PASSWORDS"] = "{}"
	env["RESTRICTED_SQL_AUDIENCE"] = "test-resource"
	env["RESTRICTED_SQL_ORGANIZATION"] = "test-org"
	env["RESTRICTED_SQL_REPLAY_LSN"] = "0/A"
	env["RESTRICTED_SQL_VERIFIER_LOGIN"] = "verify"
	env["RESTRICTED_SQL_VERIFIER_PASSWORD"] = "verify-password"
	env["TUNNEL_GATEWAY_URL"] = "wss://example.test/connect"
	env["TUNNEL_KEY"] = "test-key"
	serve, err := parse("serve", "--tunnel", "--tunnel-only", "--max-rows=200", "--statement-timeout=7s", "--replica-max-concurrent-queries=3")
	if err != nil {
		t.Fatal(err)
	}
	if len(serve.ReplicaPrincipals) != 6 || serve.ReplicaMaxConcurrentQueries != 3 || serve.MaxRows != 200 {
		t.Fatalf("unexpected roster size or limits: %d callers, %d queries, %d rows", len(serve.ReplicaPrincipals), serve.ReplicaMaxConcurrentQueries, serve.MaxRows)
	}
	for i, entry := range serve.ReplicaPrincipals {
		if entry != reconcile.ReplicaPrincipals[i] {
			t.Fatal("reconciliation and serving parsed different callers")
		}
	}
	if got := serve.ReplicaPrincipals[0].RoutingKey(); got != "user:caller.0" {
		t.Fatalf("subject = %q", got)
	}

	env["RESTRICTED_SQL_REPLAY_LSN"] = "00000000/00000000"
	if _, err := parse("serve", "--tunnel", "--tunnel-only"); err == nil {
		t.Fatal("accepted a padded zero replay floor")
	}
	env["RESTRICTED_SQL_REPLAY_LSN"] = "0/A"

	env["RESTRICTED_SQL_ROSTER"] = `[{"email":"one@example.com","databaseLogin":"reader_1"},{"email":"ONE@EXAMPLE.COM","databaseLogin":"reader_2"}]`
	if _, err := parse("serve", "--tunnel", "--tunnel-only"); err == nil {
		t.Fatal("accepted duplicate email addresses with different casing")
	}

	env["RESTRICTED_SQL_ROSTER"] = `[{"gramUserID":"alice","databaseLogin":"reader"},{"gramUserID":"bob","databaseLogin":"reader"}]`
	if _, err := parse("serve", "--tunnel", "--tunnel-only"); err == nil {
		t.Fatal("accepted two callers sharing an audit login")
	}
}
