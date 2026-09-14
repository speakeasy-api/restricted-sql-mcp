package e2e

import (
	"fmt"
	"testing"
)

// chItems returns out[key] as a list of objects.
func chItems(t *testing.T, out map[string]any, key string) []map[string]any {
	t.Helper()
	raw, ok := out[key].([]any)
	if !ok {
		t.Fatalf("result has no %s array: %v", key, out)
	}
	var items []map[string]any
	for _, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			t.Fatalf("%s entry is not an object: %v", key, r)
		}
		items = append(items, m)
	}
	return items
}

func chFind(items []map[string]any, name string) map[string]any {
	for _, it := range items {
		if fmt.Sprint(it["name"]) == name {
			return it
		}
	}
	return nil
}

func TestClickHouseListSchemas(t *testing.T) {
	s := chServer(t, ServerOpts{})
	out := s.mustCall(t, "list_schemas", nil)
	schemas := chItems(t, out, "schemas")
	for _, want := range []string{"app", "system"} {
		if chFind(schemas, want) == nil {
			t.Fatalf("schema %q missing from %v", want, schemas)
		}
	}
}

func TestClickHouseListObjects(t *testing.T) {
	s := chServer(t, ServerOpts{})
	out := s.mustCall(t, "list_objects", map[string]any{"schema": "app", "object_type": "table"})
	tables := chItems(t, out, "objects")
	for _, want := range []string{"allowed_orders", "allowed_customers", "allowed_audit", "forbidden_secrets"} {
		obj := chFind(tables, want)
		if obj == nil {
			t.Fatalf("table %q missing from %v", want, tables)
		}
		if obj["type"] != "table" || obj["engine"] != "MergeTree" {
			t.Fatalf("table %q = %v", want, obj)
		}
	}
	if o := chFind(tables, "allowed_orders"); num(t, o, "row_estimate") != 5 || num(t, o, "size_bytes") <= 0 {
		t.Fatalf("allowed_orders estimates = %v", o)
	}
	if chFind(tables, "allowed_orders_v") != nil {
		t.Fatalf("view listed as table: %v", tables)
	}

	out = s.mustCall(t, "list_objects", map[string]any{"schema": "app", "object_type": "view"})
	views := chItems(t, out, "objects")
	if v := chFind(views, "allowed_orders_v"); v == nil || v["type"] != "view" {
		t.Fatalf("views = %v", views)
	}

	out = s.mustCall(t, "list_objects", map[string]any{"schema": "app"})
	if all := chItems(t, out, "objects"); len(all) != 5 {
		t.Fatalf("all objects = %v", all)
	}

	for _, typ := range []string{"sequence", "extension"} {
		out = s.mustCall(t, "list_objects", map[string]any{"schema": "app", "object_type": typ})
		if raw, ok := out["objects"].([]any); !ok || len(raw) != 0 {
			t.Fatalf("%s objects = %v", typ, out["objects"])
		}
	}
}

func TestClickHouseObjectDetails(t *testing.T) {
	s := chServer(t, ServerOpts{})
	out := s.mustCall(t, "get_object_details", map[string]any{"schema": "app", "name": "allowed_orders"})
	cols := chItems(t, out, "columns")
	if len(cols) != 5 {
		t.Fatalf("columns = %v", cols)
	}
	wantTypes := map[string]string{"id": "Int32", "customer_id": "Int32", "amount": "Decimal(10, 2)", "status": "String", "created_at": "DateTime"}
	for name, typ := range wantTypes {
		c := chFind(cols, name)
		if c == nil || c["type"] != typ || c["nullable"] != false {
			t.Fatalf("column %s = %v", name, c)
		}
	}
	if out["type"] != "table" || out["engine"] != "MergeTree" || out["sorting_key"] != "id" {
		t.Fatalf("details = %v", out)
	}
	if num(t, out, "row_estimate") != 5 || num(t, out, "size_bytes") <= 0 {
		t.Fatalf("estimates = %v", out)
	}

	out = s.mustCall(t, "get_object_details", map[string]any{"schema": "app", "name": "allowed_orders_v"})
	if out["type"] != "view" || out["engine"] != "View" || len(chItems(t, out, "columns")) != 2 {
		t.Fatalf("view details = %v", out)
	}

	s.mustReject(t, "get_object_details", map[string]any{"schema": "app", "name": "nope"}, "not found")
}
