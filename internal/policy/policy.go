// Package policy defines the table allowlist and per-dialect function and type
// allowlists that the SQL guards enforce.
package policy

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// Dialect identifies the database flavor the server is connected to.
type Dialect string

const (
	Postgres   Dialect = "postgres"
	ClickHouse Dialect = "clickhouse"
)

// TableRef is a fully qualified relation name. For Postgres, Schema is the
// schema and Name the table. For ClickHouse, Schema is the database.
type TableRef struct {
	Schema string
	Name   string
}

func (t TableRef) String() string { return t.Schema + "." + t.Name }

// ParseTableRef parses "schema.table" or "table" (resolved against
// defaultSchema). Postgres identifiers are normalized the way Postgres does
// (unquoted -> lowercase, double-quoted -> verbatim). ClickHouse identifiers are
// kept verbatim; backtick or double-quote quoting is stripped.
func ParseTableRef(s, defaultSchema string, d Dialect) (TableRef, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return TableRef{}, fmt.Errorf("empty table name")
	}
	parts, err := splitIdent(s)
	if err != nil {
		return TableRef{}, err
	}
	var ref TableRef
	switch len(parts) {
	case 1:
		ref = TableRef{Schema: defaultSchema, Name: parts[0].normalize(d)}
	case 2:
		ref = TableRef{Schema: parts[0].normalize(d), Name: parts[1].normalize(d)}
	default:
		return TableRef{}, fmt.Errorf("table name %q must be table or schema.table", s)
	}
	if ref.Schema == "" || ref.Name == "" {
		return TableRef{}, fmt.Errorf("table name %q has an empty part", s)
	}
	return ref, nil
}

type identPart struct {
	text   string
	quoted bool
}

func (p identPart) normalize(d Dialect) string {
	if d == Postgres && !p.quoted {
		return strings.ToLower(p.text)
	}
	return p.text
}

// splitIdent splits on unquoted dots, honouring "..." and `...` quoting.
func splitIdent(s string) ([]identPart, error) {
	var parts []identPart
	var cur strings.Builder
	quoted := false
	var quote rune
	inQuote := false
	for i, r := range s {
		switch {
		case inQuote && r == quote:
			// doubled quote inside quoted identifier
			if i+1 < len(s) && rune(s[i+1]) == quote {
				cur.WriteRune(r)
				continue
			}
			inQuote = false
		case !inQuote && (r == '"' || r == '`'):
			if cur.Len() > 0 {
				return nil, fmt.Errorf("unexpected quote in %q", s)
			}
			inQuote = true
			quote = r
			quoted = true
		case !inQuote && r == '.':
			parts = append(parts, identPart{cur.String(), quoted})
			cur.Reset()
			quoted = false
		default:
			cur.WriteRune(r)
		}
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated quote in %q", s)
	}
	parts = append(parts, identPart{cur.String(), quoted})
	return parts, nil
}

// Policy is the boot-time configuration the guards enforce. Everything is
// immutable except the catalog column snapshot, which the backend refreshes
// from the database (see SetColumns).
type Policy struct {
	Dialect          Dialect
	DefaultSchema    string
	ReadTables       map[TableRef]struct{}
	WriteTables      map[TableRef]struct{}
	WritesEnabled    bool
	MaxRows          int
	StatementTimeout time.Duration

	AnnotationTiers map[Tier]bool
	Catalog         *Catalog
	relations       map[TableRef]*Relation

	columns atomic.Pointer[map[TableRef][]string]
}

// SetColumns replaces the catalog column snapshot: the ordered column names of
// each allowlisted relation. Guards use it to resolve qualified column
// references, so a relation missing from the snapshot has no resolvable
// columns (fail closed).
func (p *Policy) SetColumns(cols map[TableRef][]string) {
	copied := make(map[TableRef][]string, len(cols))
	for ref, names := range cols {
		copied[ref] = append([]string(nil), names...)
	}
	p.columns.Store(&copied)
}

// Columns returns the ordered column names of t from the current snapshot, or
// false when t is unknown or no snapshot has been loaded.
func (p *Policy) Columns(t TableRef) ([]string, bool) {
	if p.AnnotationMode() {
		r, ok := p.Relation(t)
		if !ok {
			return nil, false
		}
		names := make([]string, len(r.Columns))
		for i, c := range r.Columns {
			names[i] = c.Name
		}
		return names, true
	}
	m := p.columns.Load()
	if m == nil {
		return nil, false
	}
	names, ok := (*m)[t]
	return names, ok
}

// CanRead reports whether t may be read by the read-only tool (t ∈ R).
func (p *Policy) CanRead(t TableRef) bool {
	_, ok := p.ReadTables[t]
	return ok
}

// CanSelectInWrite reports whether t may be read inside a write transaction
// (t ∈ R ∪ W).
func (p *Policy) CanSelectInWrite(t TableRef) bool {
	if p.CanRead(t) {
		return true
	}
	_, ok := p.WriteTables[t]
	return ok
}

// CanMutate reports whether t may be the target of INSERT/UPDATE/DELETE (t ∈ W).
func (p *Policy) CanMutate(t TableRef) bool {
	_, ok := p.WriteTables[t]
	return ok
}

// AllTables returns R ∪ W, sorted deterministically by String().
func (p *Policy) AllTables() []TableRef {
	seen := map[TableRef]struct{}{}
	var out []TableRef
	for t := range p.ReadTables {
		seen[t] = struct{}{}
	}
	for t := range p.WriteTables {
		seen[t] = struct{}{}
	}
	for t := range seen {
		out = append(out, t)
	}
	sortRefs(out)
	return out
}

func sortRefs(refs []TableRef) {
	for i := 1; i < len(refs); i++ {
		for j := i; j > 0 && refs[j].String() < refs[j-1].String(); j-- {
			refs[j], refs[j-1] = refs[j-1], refs[j]
		}
	}
}

// AllowedFunction reports whether the (lowercased, unqualified) function name is
// in the dialect allowlist.
func AllowedFunction(d Dialect, name string) bool {
	name = strings.ToLower(name)
	switch d {
	case Postgres:
		_, ok := postgresFunctions[name]
		return ok
	case ClickHouse:
		_, ok := clickhouseFunctions[name]
		return ok
	}
	return false
}

// AllowedCastType reports whether the (lowercased, unqualified) type name may be
// used as a cast target.
func AllowedCastType(d Dialect, typeName string) bool {
	typeName = strings.ToLower(strings.TrimSpace(typeName))
	switch d {
	case Postgres:
		_, ok := postgresCastTypes[typeName]
		return ok
	case ClickHouse:
		_, ok := clickhouseCastTypes[typeName]
		return ok
	}
	return false
}
