package dbsec

import (
	"context"
	"strings"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
)

// AnnotationSource is the privileged control plane. It only accepts a catalog
// policy, never caller SQL. Every process uses an exclusive randomly named role.
type AnnotationSource interface {
	Load(context.Context) (*policy.Catalog, error)
	Reconcile(context.Context, *policy.Policy) (Creds, error)
	Verify(context.Context, *policy.Policy) error
	Close(context.Context) error
}

func AnnotationRolePrefix(prefix string) (string, error) {
	suffix, err := NewPassword()
	if err != nil {
		return "", err
	}
	if len(prefix) > 40 {
		prefix = prefix[:40]
	}
	return prefix + "_a" + suffix[:16], nil
}

func columnIdents(names []string, quote func(string) string) string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = quote(n)
	}
	return strings.Join(out, ",")
}
