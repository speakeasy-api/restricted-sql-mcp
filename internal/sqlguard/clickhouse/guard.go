// Package chguard validates ClickHouse SQL with a fail-closed AST allowlist and
// returns the canonical, fully qualified form deparsed from the AST.
package chguard

import (
	"fmt"
	"log/slog"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/AfterShip/clickhouse-sql-parser/parser"

	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/policy"
	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/sqlguard"
)

type guard struct{}

// New returns the ClickHouse guard.
func New() sqlguard.Guard { return guard{} }

func (guard) Check(raw string, mode sqlguard.Mode, pol *policy.Policy) (checked *sqlguard.Checked, err error) {
	log := slog.Default().With("guard", "clickhouse", "mode", mode.String())
	defer func() {
		// The parser and walker are not trusted to be panic-free on adversarial
		// input; a panic must never let a statement through.
		if r := recover(); r != nil {
			log.Error("guard panicked", "panic", fmt.Sprint(r))
			checked, err = nil, sqlguard.Reject("internal guard failure", fmt.Sprint(r))
		}
	}()
	if mode != sqlguard.ModeRead {
		return nil, sqlguard.Reject("write mode is not supported on clickhouse", "")
	}
	if pol.AnnotationMode() && (len(raw) > 64<<10 || strings.IndexByte(raw, 0) >= 0) {
		return nil, sqlguard.Reject("statement is too long or contains a NUL byte", "")
	}
	if strings.TrimSpace(raw) == "" {
		return nil, sqlguard.Reject("empty statement", "")
	}
	stmts, err := parser.NewParser(raw).ParseStmts()
	if err != nil {
		log.Debug("parse failed", "error", err.Error())
		return nil, sqlguard.Reject("could not parse statement", firstLine(err.Error()))
	}
	if len(stmts) != 1 {
		return nil, sqlguard.Reject("exactly one statement is required", fmt.Sprintf("%d statements", len(stmts)))
	}
	if err := trailingContent(raw); err != nil {
		return nil, err
	}
	sel, ok := stmts[0].(*parser.SelectQuery)
	if !ok {
		return nil, sqlguard.Reject("only SELECT statements are allowed", nodeName(stmts[0]))
	}
	var columns map[policy.TableRef][]string
	if pol.AnnotationMode() {
		columns, err = bindCHAnnotations(sel, pol)
		if err != nil {
			return nil, err
		}
	}
	v := &visitor{pol: pol, tables: map[policy.TableRef]struct{}{}}
	if err := v.selectQuery(sel); err != nil {
		log.Debug("rejected", "error", err.Error())
		return nil, err
	}
	checked = &sqlguard.Checked{
		SQL:     parser.Format(sel),
		Columns: columns,
		Kind:    sqlguard.KindSelect,
		Tables:  v.sortedTables(),
	}
	if pol.Catalog != nil {
		checked.Generation = pol.Catalog.Digest
		canonical, parseErr := parser.NewParser(checked.SQL).ParseStmts()
		if parseErr != nil || len(canonical) != 1 {
			return nil, sqlguard.Reject("canonical form failed re-validation", "")
		}
		selectAgain, ok := canonical[0].(*parser.SelectQuery)
		if !ok {
			return nil, sqlguard.Reject("canonical statement changed kind", "")
		}
		columnsAgain, bindErr := bindCHAnnotations(selectAgain, pol)
		if bindErr != nil {
			return nil, sqlguard.Reject("canonical form failed re-validation", bindErr.Error())
		}
		again := &visitor{pol: pol, tables: map[policy.TableRef]struct{}{}}
		if err := again.selectQuery(selectAgain); err != nil {
			return nil, sqlguard.Reject("canonical form failed re-validation", err.Error())
		}
		if !reflect.DeepEqual(checked.Columns, columnsAgain) || !reflect.DeepEqual(checked.Tables, again.sortedTables()) {
			return nil, sqlguard.Reject("canonical permission references changed", "")
		}
	}
	log.Debug("accepted", "canonical_sql", checked.SQL, "tables", refStrings(checked.Tables))
	return checked, nil
}

// trailingContent rejects anything after the first top-level semicolon,
// including comments, so "SELECT 1; --" style inputs never pass.
func trailingContent(raw string) error {
	tail, found := afterFirstSemicolon(raw)
	if !found {
		return nil
	}
	if rest := strings.TrimSpace(tail); rest != "" {
		return sqlguard.Reject("trailing content after statement", firstLine(rest))
	}
	return nil
}

// afterFirstSemicolon scans raw the way the parser's lexer does (string
// literals with backslash escapes, quoted identifiers, -- and /* */ comments)
// and returns the text after the first semicolon outside those constructs.
func afterFirstSemicolon(raw string) (string, bool) {
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '\'' || c == '"' || c == '`':
			for i++; i < len(raw) && raw[i] != c; i++ {
				if raw[i] == '\\' {
					i++
				}
			}
		case c == '-' && i+1 < len(raw) && raw[i+1] == '-':
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(raw) && raw[i+1] == '*':
			end := strings.Index(raw[i+2:], "*/")
			if end < 0 {
				return "", false
			}
			i += 2 + end + 1
		case c == ';':
			return raw[i+1:], true
		}
	}
	return "", false
}

// visitor carries the policy, the CTE name scopes, and the referenced tables
// while a single statement is walked.
type visitor struct {
	pol     *policy.Policy
	scopes  [][]string
	scalars [][]string
	tables  map[policy.TableRef]struct{}
}

func (v *visitor) pushScope() {
	v.scopes = append(v.scopes, nil)
	v.scalars = append(v.scalars, nil)
}
func (v *visitor) popScope() {
	v.scopes = v.scopes[:len(v.scopes)-1]
	v.scalars = v.scalars[:len(v.scalars)-1]
}
func (v *visitor) addCTE(name string) {
	v.scopes[len(v.scopes)-1] = append(v.scopes[len(v.scopes)-1], name)
}
func (v *visitor) cteInScope(name string) bool {
	return nameInScopes(v.scopes, name)
}

// addScalar records a WITH scalar-alias name (WITH <expr> AS <name>). These
// are tracked separately from relation CTEs: a scalar alias resolves to a
// value, so it is a valid operand of IN, but it must never satisfy a table
// reference (that would let `WITH 5 AS forbidden SELECT * FROM forbidden`
// reach the real table).
func (v *visitor) addScalar(name string) {
	v.scalars[len(v.scalars)-1] = append(v.scalars[len(v.scalars)-1], name)
}
func (v *visitor) scalarInScope(name string) bool {
	return nameInScopes(v.scalars, name)
}

func nameInScopes(scopes [][]string, name string) bool {
	for _, scope := range scopes {
		for _, n := range scope {
			if n == name {
				return true
			}
		}
	}
	return false
}

func (v *visitor) sortedTables() []policy.TableRef {
	out := make([]policy.TableRef, 0, len(v.tables))
	for t := range v.tables {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

var plainIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// tableIdentifier resolves a relation reference against the CTE scopes and the
// read allowlist, and rewrites it to database.table on success.
func (v *visitor) tableIdentifier(t *parser.TableIdentifier) error {
	if t.Table == nil || t.Table.Name == "" {
		return sqlguard.Reject("table reference without a name", "TableIdentifier")
	}
	if strings.ContainsAny(t.Table.Name, "`\"'\\") {
		return sqlguard.Reject("table name contains quote characters", t.Table.Name)
	}
	ref := policy.TableRef{Schema: v.pol.DefaultSchema, Name: t.Table.Name}
	if t.Database != nil {
		if strings.ContainsAny(t.Database.Name, "`\"'\\") {
			return sqlguard.Reject("database name contains quote characters", t.Database.Name)
		}
		ref.Schema = t.Database.Name
	} else if v.cteInScope(t.Table.Name) {
		slog.Default().Debug("cte reference", "guard", "clickhouse", "name", t.Table.Name)
		return nil
	}
	if !v.pol.CanRead(ref) {
		return sqlguard.Reject("table is not in the read allowlist", ref.String())
	}
	quote := parser.Unquoted
	if !plainIdent.MatchString(ref.Schema) {
		quote = parser.BackTicks
	}
	t.Database = &parser.Ident{Name: ref.Schema, QuoteType: quote}
	v.tables[ref] = struct{}{}
	return nil
}

func nodeName(e parser.Expr) string {
	return strings.TrimPrefix(fmt.Sprintf("%T", e), "*parser.")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func refStrings(refs []policy.TableRef) []string {
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = r.String()
	}
	return out
}
