package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"sort"
	"strings"
)

// Tier is the data classification recorded on an entire column. The
// vocabulary belongs to the database owner, not to this server: the server
// only knows which classes a deployment allows. Every other class, and any
// missing or malformed annotation, is denied. No tier is inherited.
type Tier string

var (
	tierName = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	tierLine = regexp.MustCompile(`^[\t ]*@access:[\t ]*([^\t ]+)[\t ]*$`)
)

// ValidTierName reports whether s is a well-formed class name: lowercase
// words joined by single hyphens, at most 63 characters.
func ValidTierName(s string) bool { return len(s) <= 63 && tierName.MatchString(s) }

// ParseAccessTier counts malformed markers too, so a valid line cannot hide a
// second, invalid decision. The marker must be the last nonempty comment line.
func ParseAccessTier(comment string) (Tier, error) {
	lines := strings.Split(strings.ReplaceAll(comment, "\r\n", "\n"), "\n")
	count, index, last := 0, -1, -1
	for i, line := range lines {
		if strings.TrimSpace(line) != "" {
			last = i
		}
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "@access:") {
			count++
			index = i
		}
	}
	if count == 0 {
		return "", fmt.Errorf("not annotated")
	}
	if count != 1 {
		return "", fmt.Errorf("duplicate access annotations")
	}
	match := tierLine.FindStringSubmatch(lines[index])
	if len(match) != 2 || index != last || !ValidTierName(match[1]) {
		return "", fmt.Errorf("invalid access annotation")
	}
	return Tier(match[1]), nil
}

// Catalog is built privately by a loader, then owned by one immutable Policy.
// Columns includes denied columns: they must still participate in SQL binding.
type Catalog struct {
	BuiltinFunctions         map[string]string `json:"builtin_functions,omitempty"`
	CaseInsensitiveFunctions map[string]string `json:"case_insensitive_functions,omitempty"`
	Schemas                  []string          `json:"schemas"`
	Relations                []Relation        `json:"relations"`
	Digest                   string            `json:"-"`
}
type CatalogConstraint struct {
	Name              string    `json:"name"`
	Kind              string    `json:"kind"`
	Columns           []string  `json:"columns"`
	ReferencedTable   *TableRef `json:"referenced_table,omitempty"`
	ReferencedColumns []string  `json:"referenced_columns,omitempty"`
}

type Relation struct {
	Constraints []CatalogConstraint `json:"constraints,omitempty"`
	Ref         TableRef            `json:"ref"`
	Identity    string              `json:"identity"`
	Kind        string              `json:"kind"`
	Engine      string              `json:"engine,omitempty"`
	Definition  string              `json:"definition,omitempty"` // hashed, never exposed by metadata tools
	Denial      string              `json:"denial,omitempty"`
	Columns     []CatalogColumn     `json:"columns"`
}
type CatalogColumn struct {
	Name             string `json:"name"`
	Identity         string `json:"identity"`
	Position         int    `json:"position"`
	Type             string `json:"type"`
	Nullable         bool   `json:"nullable"`
	Tier             Tier   `json:"tier"`
	AnnotationStatus string `json:"annotation_status"`
	Denial           string `json:"denial,omitempty"`
	Definition       string `json:"definition,omitempty"`
}

func Annotate(c *CatalogColumn, comment string) {
	tier, err := ParseAccessTier(comment)
	c.Tier = tier
	c.AnnotationStatus = "valid"
	if err != nil {
		c.AnnotationStatus = err.Error()
	}
}

func (c *Catalog) Seal() error {
	sort.Strings(c.Schemas)
	sort.Slice(c.Relations, func(i, j int) bool { return c.Relations[i].Ref.String() < c.Relations[j].Ref.String() })
	seen := map[TableRef]bool{}
	for i := range c.Relations {
		r := &c.Relations[i]
		if seen[r.Ref] {
			return fmt.Errorf("duplicate catalog relation %s", r.Ref)
		}
		seen[r.Ref] = true
		sort.Slice(r.Columns, func(i, j int) bool { return r.Columns[i].Position < r.Columns[j].Position })
		names := map[string]bool{}
		for _, col := range r.Columns {
			if names[col.Name] {
				return fmt.Errorf("duplicate catalog column %s.%s", r.Ref, col.Name)
			}
			names[col.Name] = true
		}
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(encoded)
	c.Digest = hex.EncodeToString(hash[:])
	return nil
}

// WithCatalog constructs a request policy without copying atomic state. The
// coordinator owns the snapshot and never mutates it after publication.
func (p *Policy) WithCatalog(c *Catalog) *Policy {
	q := &Policy{Dialect: p.Dialect, DefaultSchema: p.DefaultSchema, ReadTables: map[TableRef]struct{}{}, WriteTables: map[TableRef]struct{}{}, MaxRows: p.MaxRows, StatementTimeout: p.StatementTimeout, AnnotationTiers: maps.Clone(p.AnnotationTiers), Catalog: c}
	q.relations = make(map[TableRef]*Relation, len(c.Relations))
	for i := range c.Relations {
		r := &c.Relations[i]
		q.relations[r.Ref] = r
		if r.Denial == "" && len(q.ReadableColumns(r.Ref)) > 0 {
			q.ReadTables[r.Ref] = struct{}{}
		}
	}
	return q
}
func (p *Policy) AnnotationMode() bool                  { return len(p.AnnotationTiers) > 0 }
func (p *Policy) Relation(t TableRef) (*Relation, bool) { r, ok := p.relations[t]; return r, ok }
func (p *Policy) Column(t TableRef, name string) (*CatalogColumn, bool) {
	r, ok := p.Relation(t)
	if !ok {
		return nil, false
	}
	for i := range r.Columns {
		if r.Columns[i].Name == name {
			return &r.Columns[i], true
		}
	}
	return nil, false
}
func (p *Policy) ColumnDenial(t TableRef, name string) string {
	if !p.AnnotationMode() {
		if p.CanRead(t) {
			return ""
		}
		return "table is not in the read allowlist"
	}
	r, ok := p.Relation(t)
	if !ok {
		return "relation is not in the catalog"
	}
	if r.Denial != "" {
		return r.Denial
	}
	c, ok := p.Column(t, name)
	if !ok {
		return "unknown column"
	}
	if c.AnnotationStatus != "valid" {
		if c.AnnotationStatus == "" {
			return "not annotated"
		}
		return c.AnnotationStatus
	}
	if c.Denial != "" {
		return c.Denial
	}
	if !p.AnnotationTiers[c.Tier] {
		return fmt.Sprintf("tier %q is not selected", c.Tier)
	}
	return ""
}
func (p *Policy) CanReadColumn(t TableRef, name string) bool { return p.ColumnDenial(t, name) == "" }
func (p *Policy) ReadableColumns(t TableRef) []string {
	var cols []string
	r, ok := p.Relation(t)
	if !ok {
		return cols
	}
	for _, c := range r.Columns {
		if p.CanReadColumn(t, c.Name) {
			cols = append(cols, c.Name)
		}
	}
	return cols
}
