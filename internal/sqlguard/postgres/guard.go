// Package pgguard validates Postgres SQL with a fail-closed allowlist over the
// real Postgres grammar (libpg_query via pg_query_go) and returns the canonical
// deparsed statement with every table reference fully qualified.
package pgguard

import (
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"strings"
	"time"

	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/policy"
	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/sqlguard"
)

const logSQLLimit = 2000

// maxStatementBytes bounds the raw input. libpg_query's deparser is
// superlinear in statement size (256 KiB takes seconds), so oversized input is
// refused before it is parsed.
const maxStatementBytes = 64 << 10

type guard struct {
	log *slog.Logger
}

// New returns the Postgres guard logging through slog.Default().
func New() sqlguard.Guard { return NewWithLogger(nil) }

// NewWithLogger returns the Postgres guard logging through the given logger.
func NewWithLogger(logger *slog.Logger) sqlguard.Guard {
	if logger == nil {
		logger = slog.Default()
	}
	return guard{log: logger.With("guard", "postgres")}
}

func (g guard) Check(raw string, mode sqlguard.Mode, pol *policy.Policy) (*sqlguard.Checked, error) {
	start := time.Now()
	log := g.log.With("mode", mode.String())
	log.Debug("guard.check", "raw_sql", truncate(raw))

	if len(raw) > maxStatementBytes {
		err := sqlguard.Reject("statement is too long", fmt.Sprintf("%d bytes, limit %d", len(raw), maxStatementBytes))
		log.Debug("guard.rejected", "reason", err.Error(), "duration", time.Since(start))
		return nil, err
	}
	checked, err := check(raw, mode, pol)
	if err != nil {
		if rej, ok := err.(*sqlguard.RejectError); ok {
			log.Debug("guard.rejected", "reason", rej.Reason, "node", rej.Node, "duration", time.Since(start))
		} else {
			log.Debug("guard.error", "error", err.Error(), "duration", time.Since(start))
		}
		return nil, err
	}

	// Defense in depth: the canonical form must itself pass validation and
	// reference exactly the same tables, so no deparse quirk can widen access.
	again, err := check(checked.SQL, mode, pol)
	if err != nil {
		log.Debug("guard.revalidation_failed", "canonical_sql", checked.SQL, "error", err.Error())
		return nil, sqlguard.Reject("canonical form failed re-validation", err.Error())
	}
	if !sameTables(checked.Tables, again.Tables) || again.Kind != checked.Kind || !reflect.DeepEqual(checked.Columns, again.Columns) {
		log.Debug("guard.revalidation_mismatch", "canonical_sql", checked.SQL, "tables", checked.Tables, "tables_again", again.Tables)
		return nil, sqlguard.Reject("canonical form re-validation mismatch", "")
	}

	log.Debug("guard.ok", "kind", checked.Kind, "tables", refStrings(checked.Tables), "canonical_sql", checked.SQL, "duration", time.Since(start))
	return checked, nil
}

func check(raw string, mode sqlguard.Mode, pol *policy.Policy) (*sqlguard.Checked, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, sqlguard.Reject("empty statement", "")
	}
	// The C parser stops at the first NUL, so everything after it would be
	// silently dropped from what gets validated and executed.
	if strings.IndexByte(raw, 0) >= 0 {
		return nil, sqlguard.Reject("statement contains a NUL byte", "")
	}
	tree, err := pg_query.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}
	switch len(tree.Stmts) {
	case 0:
		return nil, sqlguard.Reject("empty statement", "")
	case 1:
	default:
		return nil, sqlguard.Reject("exactly one statement is required", fmt.Sprintf("%d statements", len(tree.Stmts)))
	}
	if err := rejectTrailingContent(raw, tree.Stmts[0]); err != nil {
		return nil, err
	}
	stmt := tree.Stmts[0].Stmt
	if stmt == nil || stmt.Node == nil {
		return nil, sqlguard.Reject("empty statement", "")
	}

	var columns map[policy.TableRef][]string
	if pol.AnnotationMode() {
		if mode != sqlguard.ModeRead {
			return nil, sqlguard.Reject("annotation mode is read-only", "")
		}
		columns, err = bindAnnotationColumns(stmt, pol)
		if err != nil {
			return nil, err
		}
	}
	v := newVisitCtx(mode, pol)
	kind, err := v.walkTop(stmt)
	if err != nil {
		return nil, err
	}

	canonical, err := pg_query.Deparse(tree)
	if err != nil {
		return nil, fmt.Errorf("deparse error: %w", err)
	}

	tables := make([]policy.TableRef, 0, len(v.tables))
	for t := range v.tables {
		tables = append(tables, t)
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].String() < tables[j].String() })
	generation := ""
	if pol.Catalog != nil {
		generation = pol.Catalog.Digest
	}
	return &sqlguard.Checked{SQL: canonical, Kind: kind, Tables: tables, Columns: columns, Generation: generation}, nil
}

// rejectTrailingContent rejects anything after the statement terminator other
// than whitespace: a second (even empty) statement or a trailing comment.
// StmtLen is zero when the statement runs to the end of the input.
func rejectTrailingContent(raw string, rs *pg_query.RawStmt) error {
	if rs.StmtLen == 0 {
		return nil
	}
	end := int(rs.StmtLocation + rs.StmtLen)
	if end < 0 || end > len(raw) {
		return sqlguard.Reject("could not determine statement boundary", "")
	}
	rest := strings.TrimSpace(raw[end:])
	rest = strings.TrimPrefix(rest, ";")
	if strings.TrimSpace(rest) != "" {
		return sqlguard.Reject("trailing content after statement terminator", truncate(rest))
	}
	return nil
}

func sameTables(a, b []policy.TableRef) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func refStrings(refs []policy.TableRef) []string {
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = r.String()
	}
	return out
}

func truncate(s string) string {
	if len(s) > logSQLLimit {
		return s[:logSQLLimit] + "…"
	}
	return s
}
