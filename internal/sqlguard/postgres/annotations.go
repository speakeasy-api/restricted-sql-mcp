package pgguard

import (
	"fmt"
	"strings"

	pg "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/sqlguard"
)

// The annotation binder runs before the syntax allowlist. Slots retain their
// original column identities even when SQL renames them positionally.
type pgColumnUse struct {
	table policy.TableRef
	name  string
}
type pgSlot struct {
	name string
	expr *pg.Node
	uses []pgColumnUse
	// bound is the bound target expression of an output slot. It is used only
	// to compare duplicate output labels, never substituted into SQL.
	bound *pg.Node
}
type pgRelationBinding struct {
	qualifiers [][]string
	slots      []pgSlot
}
type pgFromBinding struct {
	slots     []pgSlot
	relations []pgRelationBinding
}
type pgBindingScope struct {
	from    pgFromBinding
	outer   *pgBindingScope
	outputs []pgSlot
	clause  string
}
type pgColumnBinder struct {
	pol              *policy.Policy
	uses             map[policy.TableRef]map[string]bool
	depth            int
	steps, exprDepth int
}

func pgString(s string) *pg.Node {
	return &pg.Node{Node: &pg.Node_String_{String_: &pg.String{Sval: s}}}
}
func pgRef(parts ...string) *pg.Node {
	f := make([]*pg.Node, len(parts))
	for i, p := range parts {
		f[i] = pgString(p)
	}
	return &pg.Node{Node: &pg.Node_ColumnRef{ColumnRef: &pg.ColumnRef{Fields: f}}}
}
func clonePG(n *pg.Node) *pg.Node { return proto.Clone(n).(*pg.Node) }
func (b *pgColumnBinder) use(slot pgSlot) error {
	for _, u := range slot.uses {
		if reason := b.pol.ColumnDenial(u.table, u.name); reason != "" {
			return sqlguard.Reject(reason, u.table.String()+"."+u.name)
		}
		if b.uses[u.table] == nil {
			b.uses[u.table] = map[string]bool{}
		}
		b.uses[u.table][u.name] = true
	}
	return nil
}
func slotMatches(slots []pgSlot, name string) []pgSlot {
	var out []pgSlot
	for _, s := range slots {
		if s.name == name {
			out = append(out, s)
		}
	}
	return out
}
func onePGSlot(slots []pgSlot, name string) (pgSlot, error) {
	m := slotMatches(slots, name)
	if len(m) != 1 {
		return pgSlot{}, sqlguard.Reject("unknown or ambiguous column", name)
	}
	return m[0], nil
}

// oneOutput resolves an output label. Several outputs with the same label are
// accepted only when their bound expressions are identical, as in PostgreSQL.
func oneOutput(outputs []pgSlot, name string) (pgSlot, bool, error) {
	m := slotMatches(outputs, name)
	if len(m) == 0 {
		return pgSlot{}, false, nil
	}
	for _, other := range m[1:] {
		if m[0].bound == nil || other.bound == nil || !proto.Equal(withoutLocations(m[0].bound), withoutLocations(other.bound)) {
			return pgSlot{}, false, sqlguard.Reject("ambiguous output column", name)
		}
	}
	return m[0], true, nil
}

// withoutLocations clones a parse tree and clears source offsets, so equal
// expressions written at different positions compare equal.
func withoutLocations(n *pg.Node) *pg.Node {
	c := clonePG(n)
	clearLocations(c.ProtoReflect())
	return c
}
func clearLocations(m protoreflect.Message) {
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.Name() == "location" && fd.Kind() == protoreflect.Int32Kind:
			m.Clear(fd)
		case fd.Kind() == protoreflect.MessageKind && fd.IsList():
			for i := 0; i < v.List().Len(); i++ {
				clearLocations(v.List().Get(i).Message())
			}
		case fd.Kind() == protoreflect.MessageKind && !fd.IsMap():
			clearLocations(v.Message())
		}
		return true
	})
}
func joinPGFrom(a, c pgFromBinding) pgFromBinding {
	return pgFromBinding{slots: append(append([]pgSlot{}, a.slots...), c.slots...), relations: append(append([]pgRelationBinding{}, a.relations...), c.relations...)}
}
func sameParts(a, c []string) bool {
	if len(a) != len(c) {
		return false
	}
	for i := range a {
		if a[i] != c[i] {
			return false
		}
	}
	return true
}
func (b *pgColumnBinder) bindRef(node *pg.Node, c *pg.ColumnRef, scope *pgBindingScope) error {
	if endsWithStar(c.Fields) {
		return sqlguard.Reject("projection wildcards are not allowed in annotation mode", "ColumnRef")
	}
	parts := stringFields(c.Fields)
	if len(parts) == 0 {
		return sqlguard.Reject("empty column reference", "")
	}
	name := parts[len(parts)-1]
	// ORDER BY chooses output labels; GROUP BY chooses this level's input
	// names first, then output labels, then outer levels (PostgreSQL's
	// findTargetlistEntrySQL92 and colNameToVar(localonly) order).
	if len(parts) == 1 && scope != nil && scope.clause == "order" {
		if slot, ok, err := oneOutput(scope.outputs, name); err != nil || ok {
			if err != nil {
				return err
			}
			return b.use(slot)
		}
	}
	for s := scope; s != nil; s = s.outer {
		if s != scope && len(parts) == 1 && scope.clause == "group" {
			if slot, ok, err := oneOutput(scope.outputs, name); err != nil || ok {
				if err != nil {
					return err
				}
				return b.use(slot)
			}
		}
		var matches []pgSlot
		if len(parts) == 1 {
			matches = slotMatches(s.from.slots, name)
		} else {
			var relations []pgRelationBinding
			for _, r := range s.from.relations {
				for _, q := range r.qualifiers {
					if sameParts(q, parts[:len(parts)-1]) {
						relations = append(relations, r)
						break
					}
				}
			}
			if len(relations) > 1 {
				return sqlguard.Reject("ambiguous relation qualifier", strings.Join(parts, "."))
			}
			if len(relations) == 1 {
				matches = slotMatches(relations[0].slots, name)
				if len(matches) == 0 {
					return sqlguard.Reject("unknown column (functional column notation is forbidden)", strings.Join(parts, "."))
				}
			}
		}
		if len(matches) > 1 {
			return sqlguard.Reject("ambiguous column", name)
		}
		if len(matches) == 1 {
			slot := matches[0]
			if err := b.use(slot); err != nil {
				return err
			}
			node.Node = clonePG(slot.expr).Node
			return nil
		}
	}
	if len(parts) == 1 && scope != nil && scope.clause == "group" && scope.outer == nil {
		if slot, ok, err := oneOutput(scope.outputs, name); err != nil || ok {
			if err != nil {
				return err
			}
			return b.use(slot)
		}
	}
	return sqlguard.Reject("unknown column or forbidden whole-row reference", strings.Join(parts, "."))
}

func (b *pgColumnBinder) query(s *pg.SelectStmt, outer *pgBindingScope, parentCTEs map[string][]pgSlot) ([]pgSlot, error) {
	b.depth++
	defer func() { b.depth-- }()
	if b.depth > 64 {
		return nil, sqlguard.Reject("query nesting limit exceeded", "")
	}
	ctes := map[string][]pgSlot{}
	for name, slots := range parentCTEs {
		ctes[name] = slots
	}
	if s.WithClause != nil {
		if s.WithClause.Recursive {
			return nil, sqlguard.Reject("recursive CTEs are not supported in annotation mode", "")
		}
		local := map[string]bool{}
		for _, n := range s.WithClause.Ctes {
			c := n.GetCommonTableExpr()
			if c == nil || c.Ctequery.GetSelectStmt() == nil {
				return nil, sqlguard.Reject("annotation mode is read-only", "CTE")
			}
			if local[c.Ctename] {
				return nil, sqlguard.Reject("duplicate CTE name", c.Ctename)
			}
			local[c.Ctename] = true
			slots, err := b.query(c.Ctequery.GetSelectStmt(), outer, ctes)
			if err != nil {
				return nil, err
			}
			slots, err = renamePGSlots(slots, c.Aliascolnames)
			if err != nil {
				return nil, err
			}
			ctes[c.Ctename] = slots
		}
	}
	scope := &pgBindingScope{outer: outer}
	if s.Op != pg.SetOperation_SETOP_NONE {
		if s.Larg == nil || s.Rarg == nil {
			return nil, sqlguard.Reject("invalid set operation", "")
		}
		left, err := b.query(s.Larg, outer, ctes)
		if err != nil {
			return nil, err
		}
		right, err := b.query(s.Rarg, outer, ctes)
		if err != nil {
			return nil, err
		}
		if len(left) != len(right) {
			return nil, sqlguard.Reject("set operation column counts differ", "")
		}
		scope.outputs = left
		scope.clause = "order"
		if err := b.nodes(s.SortClause, scope, ctes); err != nil {
			return nil, err
		}
		if err := b.node(s.LimitCount, scope, ctes); err != nil {
			return nil, err
		}
		if err := b.node(s.LimitOffset, scope, ctes); err != nil {
			return nil, err
		}
		return left, nil
	}
	for _, n := range s.FromClause {
		from, err := b.from(n, scope, ctes)
		if err != nil {
			return nil, err
		}
		scope.from = joinPGFrom(scope.from, from)
	}
	if len(s.ValuesLists) > 0 {
		if err := b.nodes(s.ValuesLists, scope, ctes); err != nil {
			return nil, err
		}
		var out []pgSlot
		for i := range s.ValuesLists[0].GetList().Items {
			out = append(out, pgSlot{name: fmt.Sprintf("column%d", i+1)})
		}
		scope.outputs = out
	} else {
		if len(s.TargetList) == 0 {
			return nil, sqlguard.Reject("implicit projection is not allowed", "")
		}
		for _, n := range s.TargetList {
			rt := n.GetResTarget()
			if rt == nil {
				return nil, unsupported(n)
			}
			name := rt.Name
			if name == "" {
				name, _ = figureColname(rt.Val)
				if name == "" {
					name = "?column?"
				}
			}
			if err := b.node(rt.Val, scope, ctes); err != nil {
				return nil, err
			}
			// Preserve the database's original output name when qualification or a
			// merged USING expression changes the deparser's inferred label.
			rt.Name = name
			scope.outputs = append(scope.outputs, pgSlot{name: name, bound: clonePG(rt.Val)})
		}
	}
	for _, n := range []*pg.Node{s.WhereClause, s.HavingClause, s.LimitOffset, s.LimitCount} {
		if err := b.node(n, scope, ctes); err != nil {
			return nil, err
		}
	}
	if err := b.nodes(s.WindowClause, scope, ctes); err != nil {
		return nil, err
	}
	// DISTINCT ON follows ORDER BY name resolution; ordinary DISTINCT is nil.
	scope.clause = "order"
	if err := b.nodes(s.DistinctClause, scope, ctes); err != nil {
		return nil, err
	}
	if err := b.nodes(s.SortClause, scope, ctes); err != nil {
		return nil, err
	}
	scope.clause = "group"
	if err := b.nodes(s.GroupClause, scope, ctes); err != nil {
		return nil, err
	}
	return scope.outputs, nil
}
func renamePGSlots(slots []pgSlot, names []*pg.Node) ([]pgSlot, error) {
	if len(names) > len(slots) {
		return nil, sqlguard.Reject("too many column aliases", "")
	}
	out := append([]pgSlot{}, slots...)
	for i, n := range names {
		out[i].name = stringValue(n)
	}
	return out, nil
}
func qualifyPGSlots(slots []pgSlot, qualifier []string) []pgSlot {
	out := append([]pgSlot{}, slots...)
	for i := range out {
		out[i].expr = pgRef(append(append([]string{}, qualifier...), out[i].name)...)
	}
	return out
}
func (b *pgColumnBinder) from(n *pg.Node, current *pgBindingScope, ctes map[string][]pgSlot) (pgFromBinding, error) {
	switch x := n.Node.(type) {
	case *pg.Node_RangeVar:
		rv := x.RangeVar
		var slots []pgSlot
		var qualifiers [][]string
		if output, ok := ctes[rv.Relname]; ok && rv.Schemaname == "" {
			slots = append([]pgSlot{}, output...)
			qualifiers = [][]string{{rv.Relname}}
		} else {
			ref := policy.TableRef{Schema: rv.Schemaname, Name: rv.Relname}
			if ref.Schema == "" {
				ref.Schema = b.pol.DefaultSchema
			}
			r, ok := b.pol.Relation(ref)
			if !ok {
				return pgFromBinding{}, sqlguard.Reject("relation is not in the catalog", ref.String())
			}
			if !b.pol.CanRead(ref) {
				reason := r.Denial
				if reason == "" {
					reason = "no selectable columns"
				}
				return pgFromBinding{}, sqlguard.Reject(reason, ref.String())
			}
			for _, c := range r.Columns {
				slots = append(slots, pgSlot{name: c.Name, uses: []pgColumnUse{{ref, c.Name}}})
			}
			qualifiers = [][]string{{ref.Schema, ref.Name}, {ref.Name}}
		}
		if rv.Alias != nil {
			var err error
			slots, err = renamePGSlots(slots, rv.Alias.Colnames)
			if err != nil {
				return pgFromBinding{}, err
			}
			qualifiers = [][]string{{rv.Alias.Aliasname}}
		}
		slots = qualifyPGSlots(slots, qualifiers[0])
		return pgFromBinding{slots: slots, relations: []pgRelationBinding{{qualifiers: qualifiers, slots: slots}}}, nil
	case *pg.Node_RangeSubselect:
		r := x.RangeSubselect
		if r.Alias == nil {
			return pgFromBinding{}, sqlguard.Reject("derived relations require an alias", "")
		}
		if r.Subquery.GetSelectStmt() == nil {
			return pgFromBinding{}, unsupported(n)
		}
		// Non-LATERAL derived tables cannot see same-level FROM items, but
		// may still reference enclosing query levels.
		outer := current.outer
		if r.Lateral {
			outer = current
		}
		slots, err := b.query(r.Subquery.GetSelectStmt(), outer, ctes)
		if err != nil {
			return pgFromBinding{}, err
		}
		slots, err = renamePGSlots(slots, r.Alias.Colnames)
		if err != nil {
			return pgFromBinding{}, err
		}
		q := []string{r.Alias.Aliasname}
		slots = qualifyPGSlots(slots, q)
		return pgFromBinding{slots: slots, relations: []pgRelationBinding{{qualifiers: [][]string{q}, slots: slots}}}, nil
	case *pg.Node_JoinExpr:
		j := x.JoinExpr
		if j.IsNatural {
			return pgFromBinding{}, sqlguard.Reject("NATURAL JOIN is not allowed", "")
		}
		left, err := b.from(j.Larg, current, ctes)
		if err != nil {
			return pgFromBinding{}, err
		}
		rightScope := &pgBindingScope{from: joinPGFrom(current.from, left), outer: current.outer}
		right, err := b.from(j.Rarg, rightScope, ctes)
		if err != nil {
			return pgFromBinding{}, err
		}
		joined := joinPGFrom(left, right)
		onScope := &pgBindingScope{from: joined, outer: current.outer}
		if err := b.node(j.Quals, onScope, ctes); err != nil {
			return pgFromBinding{}, err
		}
		var merged []pgSlot
		used := map[string]bool{}
		for _, u := range j.UsingClause {
			name := stringValue(u)
			if used[name] {
				return pgFromBinding{}, sqlguard.Reject("duplicate USING column", name)
			}
			used[name] = true
			a, err := onePGSlot(left.slots, name)
			if err != nil {
				return pgFromBinding{}, err
			}
			c, err := onePGSlot(right.slots, name)
			if err != nil {
				return pgFromBinding{}, err
			}
			if err := b.use(a); err != nil {
				return pgFromBinding{}, err
			}
			if err := b.use(c); err != nil {
				return pgFromBinding{}, err
			}
			// A merged USING column is only reachable by its bare name, and
			// PostgreSQL gives it the inputs' common type (with COALESCE for
			// FULL joins). Keep the bare reference so PostgreSQL resolves the
			// merged column itself; substituting either input would change the
			// type. Permission uses still cover both inputs.
			merged = append(merged, pgSlot{name: name, expr: pgRef(name), uses: append(append([]pgColumnUse{}, a.uses...), c.uses...)})
		}
		if j.JoinUsingAlias != nil {
			joined.relations = append(joined.relations, pgRelationBinding{qualifiers: [][]string{{j.JoinUsingAlias.Aliasname}}, slots: qualifyPGSlots(merged, []string{j.JoinUsingAlias.Aliasname})})
		}
		if len(used) > 0 {
			for _, slot := range joined.slots {
				if !used[slot.name] {
					merged = append(merged, slot)
				}
			}
			joined.slots = merged
		}
		if j.Alias != nil {
			slots, err := renamePGSlots(joined.slots, j.Alias.Colnames)
			if err != nil {
				return pgFromBinding{}, err
			}
			q := []string{j.Alias.Aliasname}
			slots = qualifyPGSlots(slots, q)
			joined = pgFromBinding{slots: slots, relations: []pgRelationBinding{{qualifiers: [][]string{q}, slots: slots}}}
		}
		return joined, nil
	}
	return pgFromBinding{}, sqlguard.Reject("unsupported FROM shape in annotation mode", nodeName(n))
}
func (b *pgColumnBinder) nodes(nodes []*pg.Node, s *pgBindingScope, ctes map[string][]pgSlot) error {
	for _, n := range nodes {
		if err := b.node(n, s, ctes); err != nil {
			return err
		}
	}
	return nil
}
func (b *pgColumnBinder) node(n *pg.Node, s *pgBindingScope, ctes map[string][]pgSlot) error {
	if n == nil || n.Node == nil {
		return nil
	}
	b.steps++
	b.exprDepth++
	defer func() { b.exprDepth-- }()
	if b.steps > 20000 || b.exprDepth > 256 {
		return sqlguard.Reject("expression complexity limit exceeded", "")
	}
	switch x := n.Node.(type) {
	case *pg.Node_ColumnRef:
		return b.bindRef(n, x.ColumnRef, s)
	case *pg.Node_AStar:
		return sqlguard.Reject("wildcards are not allowed in annotation mode", "")
	case *pg.Node_SelectStmt:
		_, err := b.query(x.SelectStmt, s, ctes)
		return err
	case *pg.Node_FuncCall:
		f := x.FuncCall
		name := stringValue(f.Funcname[len(f.Funcname)-1])
		if f.AggStar && name != "count" {
			return sqlguard.Reject("only count(*) may use an aggregate star", name)
		}
		if len(f.Funcname) == 1 {
			f.Funcname = append([]*pg.Node{pgString("pg_catalog")}, f.Funcname...)
		}
	case *pg.Node_TypeName:
		t := x.TypeName
		if len(t.Names) == 1 {
			t.Names = append([]*pg.Node{pgString("pg_catalog")}, t.Names...)
		}
	case *pg.Node_AIndirection:
		for _, field := range x.AIndirection.Indirection {
			if field.GetAStar() != nil {
				return sqlguard.Reject("composite wildcards are not allowed", "")
			}
		}
	}
	// Output labels are legal only as the complete ORDER/GROUP expression, not
	// inside expressions such as ORDER BY label + 1 or aggregate ORDER BY.
	childScope := s
	if s != nil && s.clause != "" {
		copy := *s
		copy.clause = ""
		childScope = &copy
	}
	switch x := n.Node.(type) {
	case *pg.Node_SortBy, *pg.Node_GroupingSet:
		childScope = s
	case *pg.Node_RowExpr:
		// PostgreSQL flattens implicit rows in GROUP BY into grouping items.
		if s != nil && s.clause == "group" && x.RowExpr.RowFormat == pg.CoercionForm_COERCE_IMPLICIT_CAST {
			childScope = s
		}
	}
	return b.message(n.ProtoReflect(), childScope, ctes)
}
func (b *pgColumnBinder) message(m protoreflect.Message, s *pgBindingScope, ctes map[string][]pgSlot) error {
	var result error
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Kind() != protoreflect.MessageKind {
			return true
		}
		visit := func(child protoreflect.Message) error {
			if n, ok := child.Interface().(*pg.Node); ok {
				return b.node(n, s, ctes)
			}
			return b.message(child, s, ctes)
		}
		if fd.IsList() {
			list := v.List()
			for i := 0; i < list.Len(); i++ {
				if err := visit(list.Get(i).Message()); err != nil {
					result = err
					return false
				}
			}
		} else {
			result = visit(v.Message())
		}
		return result == nil
	})
	return result
}
func bindAnnotationColumns(stmt *pg.Node, pol *policy.Policy) (map[policy.TableRef][]string, error) {
	if stmt.GetSelectStmt() == nil {
		return nil, sqlguard.Reject("annotation mode is read-only", "")
	}
	b := &pgColumnBinder{pol: pol, uses: map[policy.TableRef]map[string]bool{}}
	if _, err := b.query(stmt.GetSelectStmt(), nil, nil); err != nil {
		return nil, err
	}
	out := map[policy.TableRef][]string{}
	for ref, cols := range b.uses {
		for _, c := range pol.ReadableColumns(ref) {
			if cols[c] {
				out[ref] = append(out[ref], c)
			}
		}
	}
	return out, nil
}
