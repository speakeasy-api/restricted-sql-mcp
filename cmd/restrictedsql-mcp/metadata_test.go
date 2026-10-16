package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
)

// The gateway rejects a session whose metadata serializes to more than 1024
// bytes, so a server allowlisting a whole schema must still fit.
func TestTunnelMetadataFitsGatewayLimit(t *testing.T) {
	pol := &policy.Policy{Dialect: policy.Postgres, WritesEnabled: true,
		ReadTables: map[policy.TableRef]struct{}{}, WriteTables: map[policy.TableRef]struct{}{}}
	for i := 0; i < 5000; i++ {
		ref := policy.TableRef{Schema: "app", Name: fmt.Sprintf("a_rather_long_table_name_%04d", i)}
		pol.ReadTables[ref] = struct{}{}
		pol.WriteTables[ref] = struct{}{}
	}
	meta := tunnelMetadata(pol, "^app_preview_pr_[0-9]+$"+strings.Repeat("x", 2000))
	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > maxTunnelMetadataBytes {
		t.Fatalf("metadata is %d bytes, over %d: %s", len(raw), maxTunnelMetadataBytes, raw)
	}
	if meta["dialect"] != "postgres" || meta["write_tools"] != "true" || meta["read_tables"] != "5000" || meta["write_tables"] != "5000" {
		t.Fatalf("metadata = %v", meta)
	}
}
