// Package stub is a placeholder guard used until a dialect guard is wired in.
// It rejects every statement so the server fails closed.
package stub

import (
	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/policy"
	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/sqlguard"
)

// Guard rejects everything.
type Guard struct{}

// New returns the rejecting guard.
func New() sqlguard.Guard { return Guard{} }

// Check always rejects.
func (Guard) Check(_ string, _ sqlguard.Mode, pol *policy.Policy) (*sqlguard.Checked, error) {
	return nil, sqlguard.Reject("no guard for dialect", string(pol.Dialect))
}
