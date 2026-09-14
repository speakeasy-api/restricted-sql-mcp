// Package stub is a placeholder backend used until a dialect backend is wired
// in. Every operation fails and Ping reports the server as not ready.
package stub

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/db"
	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/policy"
)

var errNotImplemented = errors.New("backend not implemented")

// Backend fails every call.
type Backend struct{ dialect policy.Dialect }

// New returns a failing backend for the dialect.
func New(d policy.Dialect) *Backend { return &Backend{dialect: d} }

func (b *Backend) Dialect() policy.Dialect { return b.dialect }

func (b *Backend) Ping(context.Context) error { return errNotImplemented }

func (b *Backend) TablesExist(context.Context, []policy.TableRef) ([]policy.TableRef, error) {
	return nil, errNotImplemented
}

func (b *Backend) Query(context.Context, string, int) (*db.Result, error) {
	return nil, errNotImplemented
}

func (b *Backend) Explain(context.Context, string, db.ExplainOptions) (json.RawMessage, string, error) {
	return nil, "", errNotImplemented
}

func (b *Backend) ListSchemas(context.Context) ([]db.Schema, error) { return nil, errNotImplemented }

func (b *Backend) ListObjects(context.Context, string, string) ([]db.Object, error) {
	return nil, errNotImplemented
}

func (b *Backend) ObjectDetails(context.Context, policy.TableRef) (*db.ObjectDetails, error) {
	return nil, errNotImplemented
}

func (b *Backend) Close() error { return nil }
