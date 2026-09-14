package e2e

import (
	"fmt"
	"testing"
)

// objectsByName indexes a list_objects / get_object_details array by "name".
func objectsByName(t *testing.T, out map[string]any, key string) map[string]map[string]any {
	t.Helper()
	raw, ok := out[key].([]any)
	if !ok {
		t.Fatalf("result has no %q array: %v", key, out)
	}
	res := map[string]map[string]any{}
	for _, o := range raw {
		m, ok := o.(map[string]any)
		if !ok {
			t.Fatalf("%s entry is not an object: %v", key, o)
		}
		res[fmt.Sprint(m["name"])] = m
	}
	return res
}

func TestPostgresListSchemas(t *testing.T) {
	s := bootServer(t, ServerOpts{})
	out := s.mustCall(t, "list_schemas", nil)
	schemas := objectsByName(t, out, "schemas")
	if _, ok := schemas["public"]; !ok {
		t.Fatalf("list_schemas missing public: %v", out)
	}
	if _, ok := schemas["pg_catalog"]; !ok {
		t.Fatalf("list_schemas missing pg_catalog (full catalog visibility is intended): %v", out)
	}
	if _, ok := schemas["pg_toast"]; ok {
		t.Fatalf("list_schemas should hide pg_toast: %v", out)
	}
	if schemas["public"]["owner"] == nil || schemas["public"]["owner"] == "" {
		t.Fatalf("public schema has no owner: %v", schemas["public"])
	}
}

func TestPostgresListObjects(t *testing.T) {
	s := bootServer(t, ServerOpts{})

	tables := objectsByName(t, s.mustCall(t, "list_objects", map[string]any{"schema": "public", "object_type": "table"}), "objects")
	for _, name := range []string{"allowed_orders", "allowed_customers", "allowed_audit", "forbidden_secrets"} {
		o, ok := tables[name]
		if !ok {
			t.Fatalf("list_objects table missing %s: %v", name, tables)
		}
		if o["type"] != "table" {
			t.Fatalf("%s type = %v, want table", name, o["type"])
		}
		if size, _ := o["size_bytes"].(float64); size <= 0 {
			t.Fatalf("%s size_bytes = %v, want > 0", name, o["size_bytes"])
		}
	}
	if _, ok := tables["allowed_orders_v"]; ok {
		t.Fatalf("view listed under object_type table")
	}

	views := objectsByName(t, s.mustCall(t, "list_objects", map[string]any{"schema": "public", "object_type": "view"}), "objects")
	if v, ok := views["allowed_orders_v"]; !ok || v["type"] != "view" {
		t.Fatalf("list_objects view missing allowed_orders_v: %v", views)
	}

	seqs := objectsByName(t, s.mustCall(t, "list_objects", map[string]any{"schema": "public", "object_type": "sequence"}), "objects")
	if q, ok := seqs["allowed_seq"]; !ok || q["type"] != "sequence" {
		t.Fatalf("list_objects sequence missing allowed_seq: %v", seqs)
	}

	exts := objectsByName(t, s.mustCall(t, "list_objects", map[string]any{"schema": "public", "object_type": "extension"}), "objects")
	if e, ok := exts["hypopg"]; !ok || e["type"] != "extension" {
		t.Fatalf("list_objects extension missing hypopg: %v", exts)
	}

	all := objectsByName(t, s.mustCall(t, "list_objects", map[string]any{"schema": "public"}), "objects")
	for _, name := range []string{"allowed_orders", "allowed_orders_v", "allowed_seq", "hypopg"} {
		if _, ok := all[name]; !ok {
			t.Fatalf("list_objects without object_type missing %s: %v", name, all)
		}
	}

	empty := s.mustCall(t, "list_objects", map[string]any{"schema": "no_such_schema", "object_type": "table"})
	if objs := objectsByName(t, empty, "objects"); len(objs) != 0 {
		t.Fatalf("unknown schema should list nothing: %v", objs)
	}
	s.mustReject(t, "list_objects", map[string]any{"schema": "public", "object_type": "trigger"}, "object_type")
}

func TestPostgresGetObjectDetails(t *testing.T) {
	s := bootServer(t, ServerOpts{})
	out := s.mustCall(t, "get_object_details", map[string]any{"schema": "public", "name": "allowed_orders"})
	if out["type"] != "table" || out["description"] != "Orders" {
		t.Fatalf("type/description = %v/%v", out["type"], out["description"])
	}
	cols := objectsByName(t, out, "columns")
	for _, name := range []string{"id", "customer_id", "amount", "status", "created_at"} {
		if _, ok := cols[name]; !ok {
			t.Fatalf("missing column %s: %v", name, cols)
		}
	}
	if len(cols) != 5 {
		t.Fatalf("columns = %d, want 5", len(cols))
	}
	if cols["amount"]["type"] != "numeric(10,2)" || cols["amount"]["nullable"] != false {
		t.Fatalf("amount column = %v", cols["amount"])
	}
	if cols["created_at"]["default"] != "now()" {
		t.Fatalf("created_at default = %v", cols["created_at"]["default"])
	}
	conTypes := map[string]bool{}
	for _, c := range objectsByName(t, out, "constraints") {
		conTypes[fmt.Sprint(c["type"])] = true
	}
	if !conTypes["primary_key"] || !conTypes["foreign_key"] {
		t.Fatalf("constraint types = %v, want primary_key and foreign_key", conTypes)
	}
	idx := objectsByName(t, out, "indexes")
	if i, ok := idx["allowed_orders_customer_idx"]; !ok {
		t.Fatalf("missing index allowed_orders_customer_idx: %v", idx)
	} else if size, _ := i["size_bytes"].(float64); size <= 0 {
		t.Fatalf("index size_bytes = %v", i["size_bytes"])
	}
	if size, _ := out["size_bytes"].(float64); size <= 0 {
		t.Fatalf("size_bytes = %v", out["size_bytes"])
	}

	view := s.mustCall(t, "get_object_details", map[string]any{"schema": "public", "name": "allowed_orders_v"})
	if view["type"] != "view" || len(objectsByName(t, view, "columns")) != 2 {
		t.Fatalf("view details = %v", view)
	}

	s.mustReject(t, "get_object_details", map[string]any{"schema": "public", "name": "nope"}, "not found")
	s.mustReject(t, "get_object_details", map[string]any{"schema": "nope", "name": "allowed_orders"}, "not found")
}
