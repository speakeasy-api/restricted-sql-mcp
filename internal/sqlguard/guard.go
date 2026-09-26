// Package sqlguard defines the contract every dialect guard implements: parse
// raw SQL into an AST, validate it against a policy with a fail-closed
// allowlist, and return canonical SQL deparsed from that AST.
package sqlguard

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/policy"
)

// Mode selects which statement kinds and table sets apply.
type Mode int

const (
	// ModeRead allows SELECT-like statements over policy.ReadTables only.
	ModeRead Mode = iota
	// ModeWrite allows INSERT/UPDATE/DELETE targeting policy.WriteTables and
	// SELECT over ReadTables ∪ WriteTables. Source relations of mutations must
	// also be in ReadTables ∪ WriteTables.
	ModeWrite
)

func (m Mode) String() string {
	if m == ModeWrite {
		return "write"
	}
	return "read"
}

// StmtKind classifies the single validated statement.
type StmtKind string

const (
	KindSelect StmtKind = "select"
	KindInsert StmtKind = "insert"
	KindUpdate StmtKind = "update"
	KindDelete StmtKind = "delete"
)

// Checked is the result of a successful validation.
type Checked struct {
	Generation string
	Columns    map[policy.TableRef][]string

	// SQL is the canonical statement deparsed from the AST, with every table
	// reference fully qualified as schema.table. This, never the raw input, is
	// what gets sent to the database.
	SQL string
	// Kind is the statement classification.
	Kind StmtKind
	// Tables lists every relation referenced (targets and sources), deduplicated
	// and sorted by String().
	Tables []policy.TableRef
}

// RejectError is returned when the statement violates the policy. Reason is a
// stable human-readable explanation; Node names the offending AST node, table,
// function, or type so the agent can self-correct.
type RejectError struct {
	Reason string
	Node   string
}

func (e *RejectError) Error() string {
	if e.Node == "" {
		return "sql rejected: " + e.Reason
	}
	return fmt.Sprintf("sql rejected: %s (%s)", e.Reason, e.Node)
}

// Reject is a helper to build a RejectError.
func Reject(reason, node string) error { return &RejectError{Reason: reason, Node: node} }

// Guard validates SQL for one dialect.
type Guard interface {
	// Check parses raw, validates it for mode against pol, and returns the
	// canonical form. Exactly one statement is allowed. Any error other than a
	// *RejectError indicates a parse failure or internal error.
	Check(raw string, mode Mode, pol *policy.Policy) (*Checked, error)
}

// HypotheticalIndex is the structured input for explain_query on Postgres.
type HypotheticalIndex struct {
	Table   policy.TableRef
	Columns []string
	Method  string // btree (default), hash, gin, gist, brin
}

var identRe = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// BuildIndexDDL validates the index description and returns the CREATE INDEX
// statement to hand to hypopg_create_hypothetical_index. Columns must be plain
// lowercase identifiers; the table must already have been checked against the
// policy by the caller.
func BuildIndexDDL(h HypotheticalIndex) (string, error) {
	if len(h.Columns) == 0 {
		return "", Reject("hypothetical index needs at least one column", "")
	}
	for _, c := range h.Columns {
		if !identRe.MatchString(c) {
			return "", Reject("hypothetical index column must be a plain identifier", c)
		}
	}
	if !identRe.MatchString(h.Table.Schema) || !identRe.MatchString(h.Table.Name) {
		return "", Reject("hypothetical index table must be a plain identifier", h.Table.String())
	}
	method := strings.ToLower(h.Method)
	if method == "" {
		method = "btree"
	}
	switch method {
	case "btree", "hash", "gin", "gist", "brin":
	default:
		return "", Reject("hypothetical index method not allowed", h.Method)
	}
	return fmt.Sprintf("CREATE INDEX ON %s.%s USING %s (%s)",
		h.Table.Schema, h.Table.Name, method, strings.Join(h.Columns, ", ")), nil
}
