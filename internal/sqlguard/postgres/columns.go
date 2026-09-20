package pgguard

import (
	"strconv"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/policy"
	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/sqlguard"
)

// Postgres resolves "rel.name" as a column of rel when one exists and
// otherwise as the function call name(rel), which would bypass the function
// allowlist (any function taking the row type, "record" or "anyelement" is
// reachable that way). The guard therefore resolves every qualified column
// reference itself: base-table columns come from the policy's catalog
// snapshot, derived-table columns are inferred from the subquery the same
// way Postgres names them, and anything that does not resolve is rejected.

// colset is the ordered output column names of a relation, or unknown when
// they cannot be determined (missing catalog snapshot, unsupported shape).
type colset struct {
	names []string
	known bool
}

func (c colset) has(name string) bool {
	for _, n := range c.names {
		if n == name {
			return true
		}
	}
	return false
}

// override applies an alias column list: the first len(colnames) columns are
// renamed, the rest keep their names.
func (c colset) override(colnames []*pg_query.Node) colset {
	if len(colnames) == 0 || !c.known {
		return c
	}
	if len(colnames) > len(c.names) {
		return colset{}
	}
	out := colset{known: true, names: append([]string(nil), c.names...)}
	for i, n := range colnames {
		out.names[i] = stringValue(n)
	}
	return out
}

// relItem is one relation visible to qualified column references: a FROM
// entry, a data-modifying statement's target, or INSERT's "excluded".
type relItem struct {
	// name is the alias, or the bare relation/CTE name when unaliased.
	name    string
	aliased bool
	// schema and rel are set for unaliased base tables so schema.table.col
	// resolves.
	schema, rel string
	cols        colset
}

type relScope struct{ items []relItem }

func (v *visitCtx) pushRelScope() *relScope {
	s := &relScope{}
	v.relScopes = append(v.relScopes, s)
	return s
}

func (v *visitCtx) popRelScope() { v.relScopes = v.relScopes[:len(v.relScopes)-1] }

func (v *visitCtx) pushCTEScope() { v.cteScopes = append(v.cteScopes, map[string]colset{}) }
func (v *visitCtx) popCTEScope()  { v.cteScopes = v.cteScopes[:len(v.cteScopes)-1] }

func (v *visitCtx) addCTE(name string, cols colset) { v.cteScopes[len(v.cteScopes)-1][name] = cols }

func (v *visitCtx) cteInScope(name string) (colset, bool) {
	for i := len(v.cteScopes) - 1; i >= 0; i-- {
		if c, ok := v.cteScopes[i][name]; ok {
			return c, true
		}
	}
	return colset{}, false
}

// lookupRel resolves a one-part (alias or name) or two-part (schema.table)
// qualifier against the enclosing scopes, innermost first.
func (v *visitCtx) lookupRel(qualifier []string) (*relItem, bool) {
	for i := len(v.relScopes) - 1; i >= 0; i-- {
		for j := range v.relScopes[i].items {
			it := &v.relScopes[i].items[j]
			switch len(qualifier) {
			case 1:
				if it.name != "" && it.name == qualifier[0] {
					return it, true
				}
			case 2:
				if !it.aliased && it.schema == qualifier[0] && it.rel == qualifier[1] {
					return it, true
				}
			}
		}
	}
	return nil, false
}

// isColumnAnywhere reports whether name is a column of some relation in scope,
// which is how Postgres resolves a bare name before trying it as a relation.
// Unknown column sets make the answer unknowable, reported as true.
func (v *visitCtx) isColumnAnywhere(name string) bool {
	for _, s := range v.relScopes {
		for _, it := range s.items {
			if !it.cols.known || it.cols.has(name) {
				return true
			}
		}
	}
	return false
}

// baseTableItem builds the scope entry for a real relation.
func (v *visitCtx) baseTableItem(rv *pg_query.RangeVar) relItem {
	ref := policy.TableRef{Schema: rv.Schemaname, Name: rv.Relname}
	if ref.Schema == "" {
		ref.Schema = v.pol.DefaultSchema
	}
	cols := colset{}
	if names, ok := v.pol.Columns(ref); ok {
		cols = colset{known: true, names: append([]string(nil), names...)}
	}
	it := relItem{name: rv.Relname, schema: ref.Schema, rel: ref.Name}
	if rv.Alias != nil {
		it.name, it.aliased = rv.Alias.Aliasname, true
		cols = cols.override(rv.Alias.Colnames)
	}
	it.cols = cols
	return it
}

// rangeVarItem builds the scope entry for a FROM-clause relation, which may
// be a CTE reference.
func (v *visitCtx) rangeVarItem(rv *pg_query.RangeVar) relItem {
	if rv.Schemaname == "" {
		if cols, ok := v.cteInScope(rv.Relname); ok {
			it := relItem{name: rv.Relname, cols: cols}
			if rv.Alias != nil {
				it.name, it.aliased = rv.Alias.Aliasname, true
				it.cols = cols.override(rv.Alias.Colnames)
			}
			return it
		}
	}
	return v.baseTableItem(rv)
}

// addFromItems appends the scope entries for one FROM-clause node. Entries are
// appended as they are computed so LATERAL items can see their predecessors.
func (v *visitCtx) addFromItems(scope *relScope, n *pg_query.Node) {
	if n == nil || n.Node == nil {
		return
	}
	switch x := n.Node.(type) {
	case *pg_query.Node_RangeVar:
		scope.items = append(scope.items, v.rangeVarItem(x.RangeVar))
	case *pg_query.Node_RangeSubselect:
		r := x.RangeSubselect
		it := relItem{}
		if sel, ok := r.Subquery.GetNode().(*pg_query.Node_SelectStmt); ok {
			it.cols = v.outputCols(sel.SelectStmt)
		}
		if r.Alias != nil {
			it.name, it.aliased = r.Alias.Aliasname, true
			it.cols = it.cols.override(r.Alias.Colnames)
		}
		scope.items = append(scope.items, it)
	case *pg_query.Node_JoinExpr:
		j := x.JoinExpr
		start := len(scope.items)
		v.addFromItems(scope, j.Larg)
		mid := len(scope.items)
		v.addFromItems(scope, j.Rarg)
		if j.JoinUsingAlias != nil {
			using := colset{known: true}
			for _, u := range j.UsingClause {
				using.names = append(using.names, stringValue(u))
			}
			scope.items = append(scope.items, relItem{name: j.JoinUsingAlias.Aliasname, aliased: true, cols: using})
		}
		if j.Alias != nil {
			merged := joinColumns(j, mergeItems(scope.items[start:mid]), mergeItems(scope.items[mid:]))
			scope.items = append(scope.items[:start], relItem{name: j.Alias.Aliasname, aliased: true, cols: merged.override(j.Alias.Colnames)})
		}
	}
}

func mergeItems(items []relItem) colset {
	out := colset{known: true}
	for _, it := range items {
		if !it.cols.known {
			return colset{}
		}
		out.names = append(out.names, it.cols.names...)
	}
	return out
}

// joinColumns orders a join's output the way Postgres does: the USING (or
// NATURAL) columns first, then the remaining left and right columns.
func joinColumns(j *pg_query.JoinExpr, left, right colset) colset {
	if !left.known || !right.known {
		return colset{}
	}
	var using []string
	switch {
	case j.IsNatural:
		for _, l := range left.names {
			if right.has(l) {
				using = append(using, l)
			}
		}
	case len(j.UsingClause) > 0:
		using = stringFields(j.UsingClause)
	default:
		return colset{known: true, names: append(append([]string(nil), left.names...), right.names...)}
	}
	merged := colset{known: true, names: append([]string(nil), using...)}
	for _, side := range []colset{left, right} {
		for _, n := range side.names {
			if !merged.has(n) {
				merged.names = append(merged.names, n)
			}
		}
	}
	return merged
}

// outputCols infers the output column names of a SELECT the way Postgres
// does, so references to derived tables and CTEs can be checked.
func (v *visitCtx) outputCols(s *pg_query.SelectStmt) colset {
	if s == nil {
		return colset{}
	}
	if c, ok := v.outCache[s]; ok {
		return c
	}
	c := v.computeOutputCols(s)
	v.outCache[s] = c
	return c
}

func (v *visitCtx) computeOutputCols(s *pg_query.SelectStmt) colset {
	if s.WithClause != nil {
		v.pushCTEScope()
		defer v.popCTEScope()
		v.analyzeWith(s.WithClause)
	}
	if s.Op != pg_query.SetOperation_SETOP_NONE {
		return v.outputCols(s.Larg)
	}
	if len(s.ValuesLists) > 0 {
		row, ok := s.ValuesLists[0].GetNode().(*pg_query.Node_List)
		if !ok {
			return colset{}
		}
		c := colset{known: true}
		for i := range row.List.Items {
			c.names = append(c.names, "column"+strconv.Itoa(i+1))
		}
		return c
	}
	scope := v.pushRelScope()
	defer v.popRelScope()
	for _, f := range s.FromClause {
		v.addFromItems(scope, f)
	}
	return v.targetNames(s.TargetList)
}

// analyzeWith registers the column sets of a WITH clause's CTEs in the
// current CTE scope without validating them. RECURSIVE makes every name
// visible everywhere; a forward reference resolves to an unknown column set,
// so qualified references to such a CTE are rejected.
func (v *visitCtx) analyzeWith(w *pg_query.WithClause) {
	if w.Recursive {
		for _, n := range w.Ctes {
			if cte, ok := n.Node.(*pg_query.Node_CommonTableExpr); ok {
				v.addCTE(cte.CommonTableExpr.Ctename, colset{})
			}
		}
	}
	for _, n := range w.Ctes {
		if cte, ok := n.Node.(*pg_query.Node_CommonTableExpr); ok {
			v.addCTE(cte.CommonTableExpr.Ctename, v.cteCols(cte.CommonTableExpr))
		}
	}
}

// cteCols infers a CTE's output columns: the body's output for a SELECT, the
// RETURNING list for a data-modifying CTE.
func (v *visitCtx) cteCols(c *pg_query.CommonTableExpr) colset {
	var cols colset
	switch q := c.Ctequery.GetNode().(type) {
	case *pg_query.Node_SelectStmt:
		cols = v.outputCols(q.SelectStmt)
	case *pg_query.Node_InsertStmt:
		cols = v.returningCols(q.InsertStmt.WithClause, q.InsertStmt.Relation, nil, q.InsertStmt.ReturningList)
	case *pg_query.Node_UpdateStmt:
		cols = v.returningCols(q.UpdateStmt.WithClause, q.UpdateStmt.Relation, q.UpdateStmt.FromClause, q.UpdateStmt.ReturningList)
	case *pg_query.Node_DeleteStmt:
		cols = v.returningCols(q.DeleteStmt.WithClause, q.DeleteStmt.Relation, q.DeleteStmt.UsingClause, q.DeleteStmt.ReturningList)
	}
	return cols.override(c.Aliascolnames)
}

func (v *visitCtx) returningCols(with *pg_query.WithClause, target *pg_query.RangeVar, from []*pg_query.Node, returning []*pg_query.Node) colset {
	if target == nil {
		return colset{}
	}
	if with != nil {
		v.pushCTEScope()
		defer v.popCTEScope()
		v.analyzeWith(with)
	}
	scope := v.pushRelScope()
	defer v.popRelScope()
	scope.items = append(scope.items, v.baseTableItem(target))
	for _, f := range from {
		v.addFromItems(scope, f)
	}
	return v.targetNames(returning)
}

// targetNames names each output column of a target list, expanding "*" and
// "rel.*" against the current scope.
func (v *visitCtx) targetNames(targets []*pg_query.Node) colset {
	out := colset{known: true}
	for _, n := range targets {
		rt, ok := n.Node.(*pg_query.Node_ResTarget)
		if !ok {
			return colset{}
		}
		if rt.ResTarget.Name != "" {
			out.names = append(out.names, rt.ResTarget.Name)
			continue
		}
		if cref, ok := rt.ResTarget.Val.GetNode().(*pg_query.Node_ColumnRef); ok && endsWithStar(cref.ColumnRef.Fields) {
			expanded := v.expandStar(cref.ColumnRef.Fields)
			if !expanded.known {
				return colset{}
			}
			out.names = append(out.names, expanded.names...)
			continue
		}
		name, strength := figureColname(rt.ResTarget.Val)
		if strength == 0 {
			name = "?column?"
		}
		out.names = append(out.names, name)
	}
	return out
}

func endsWithStar(fields []*pg_query.Node) bool {
	if len(fields) == 0 {
		return false
	}
	_, ok := fields[len(fields)-1].GetNode().(*pg_query.Node_AStar)
	return ok
}

// expandStar expands "*" (every relation of the innermost scope, in order) or
// "rel.*".
func (v *visitCtx) expandStar(fields []*pg_query.Node) colset {
	if len(fields) == 1 {
		out := colset{known: true}
		if len(v.relScopes) == 0 {
			return out
		}
		for _, it := range v.relScopes[len(v.relScopes)-1].items {
			if !it.cols.known {
				return colset{}
			}
			out.names = append(out.names, it.cols.names...)
		}
		return out
	}
	it, ok := v.lookupRel(stringFields(fields[:len(fields)-1]))
	if !ok {
		return colset{}
	}
	return it.cols
}

func stringFields(fields []*pg_query.Node) []string {
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, stringValue(f))
	}
	return out
}

// figureColname mirrors Postgres's FigureColnameInternal: the name an
// unaliased target list entry gets, with its strength (0 = "?column?").
func figureColname(n *pg_query.Node) (string, int) {
	if n == nil || n.Node == nil {
		return "", 0
	}
	switch x := n.Node.(type) {
	case *pg_query.Node_ColumnRef:
		for i := len(x.ColumnRef.Fields) - 1; i >= 0; i-- {
			if s := stringValue(x.ColumnRef.Fields[i]); s != "" {
				return s, 2
			}
		}
	case *pg_query.Node_AIndirection:
		for i := len(x.AIndirection.Indirection) - 1; i >= 0; i-- {
			if s := stringValue(x.AIndirection.Indirection[i]); s != "" {
				return s, 2
			}
		}
		return figureColname(x.AIndirection.Arg)
	case *pg_query.Node_FuncCall:
		if l := len(x.FuncCall.Funcname); l > 0 {
			return stringValue(x.FuncCall.Funcname[l-1]), 2
		}
	case *pg_query.Node_AExpr:
		if x.AExpr.Kind == pg_query.A_Expr_Kind_AEXPR_NULLIF {
			return "nullif", 2
		}
	case *pg_query.Node_TypeCast:
		name, strength := figureColname(x.TypeCast.Arg)
		if strength <= 1 && x.TypeCast.TypeName != nil {
			if l := len(x.TypeCast.TypeName.Names); l > 0 {
				return stringValue(x.TypeCast.TypeName.Names[l-1]), 1
			}
		}
		return name, strength
	case *pg_query.Node_CollateClause:
		return figureColname(x.CollateClause.Arg)
	case *pg_query.Node_GroupingFunc:
		return "grouping", 2
	case *pg_query.Node_SubLink:
		switch x.SubLink.SubLinkType {
		case pg_query.SubLinkType_EXISTS_SUBLINK:
			return "exists", 2
		case pg_query.SubLinkType_ARRAY_SUBLINK:
			return "array", 2
		case pg_query.SubLinkType_EXPR_SUBLINK:
			if sel, ok := x.SubLink.Subselect.GetNode().(*pg_query.Node_SelectStmt); ok && len(sel.SelectStmt.TargetList) > 0 {
				if rt, ok := sel.SelectStmt.TargetList[0].Node.(*pg_query.Node_ResTarget); ok {
					if rt.ResTarget.Name != "" {
						return rt.ResTarget.Name, 2
					}
					return figureColname(rt.ResTarget.Val)
				}
			}
		}
	case *pg_query.Node_CaseExpr:
		if x.CaseExpr.Defresult != nil {
			if name, strength := figureColname(x.CaseExpr.Defresult); strength > 1 {
				return name, strength
			}
		}
		return "case", 1
	case *pg_query.Node_AArrayExpr:
		return "array", 2
	case *pg_query.Node_RowExpr:
		return "row", 2
	case *pg_query.Node_CoalesceExpr:
		return "coalesce", 2
	case *pg_query.Node_MinMaxExpr:
		if x.MinMaxExpr.Op == pg_query.MinMaxOp_IS_GREATEST {
			return "greatest", 2
		}
		return "least", 2
	case *pg_query.Node_SqlvalueFunction:
		op := strings.ToLower(strings.TrimPrefix(x.SqlvalueFunction.Op.String(), "SVFOP_"))
		return strings.TrimSuffix(op, "_n"), 2
	}
	return "", 0
}

// walkColumnRef validates a column reference. Unqualified names are always
// columns (or errors) in Postgres; qualified ones must resolve to a known
// column of a relation in scope.
func (v *visitCtx) walkColumnRef(c *pg_query.ColumnRef) error {
	if err := v.walkAll(c.Fields); err != nil {
		return err
	}
	if len(c.Fields) < 2 {
		return nil
	}
	fields := stringFields(c.Fields)
	star := endsWithStar(c.Fields)
	qualifier := fields[:len(fields)-1]
	display := strings.Join(fields, ".")
	if star {
		display = strings.Join(qualifier, ".") + ".*"
	}
	if len(qualifier) > 2 {
		return sqlguard.Reject("catalog-qualified column references are not allowed", display)
	}
	it, ok := v.lookupRel(qualifier)
	if !ok {
		return sqlguard.Reject("column reference does not name a relation in scope", display)
	}
	if star {
		return nil
	}
	return v.checkColumn(it, fields[len(fields)-1], display)
}

func (v *visitCtx) checkColumn(it *relItem, column, display string) error {
	if !it.cols.known {
		return sqlguard.Reject("columns of the relation are not known; reference the column without a qualifier", display)
	}
	if !it.cols.has(column) {
		return sqlguard.Reject("not a column of the relation (functional column notation is not allowed)", display)
	}
	return nil
}

// walkIndirection validates "(expr).field" and subscripts. Field access is
// only allowed on the whole row of a relation in scope, where it is checked
// like rel.field; on any other expression it could invoke a function.
func (v *visitCtx) walkIndirection(a *pg_query.A_Indirection) error {
	if err := v.walk(a.Arg); err != nil {
		return err
	}
	var fields []string
	for _, ind := range a.Indirection {
		switch x := ind.Node.(type) {
		case *pg_query.Node_AIndices:
			if err := v.walk(ind); err != nil {
				return err
			}
		case *pg_query.Node_AStar:
		case *pg_query.Node_String_:
			fields = append(fields, x.String_.Sval)
		default:
			return unsupported(ind)
		}
	}
	if len(fields) == 0 {
		return nil
	}
	cref, ok := a.Arg.GetNode().(*pg_query.Node_ColumnRef)
	if !ok || len(cref.ColumnRef.Fields) != 1 || len(fields) != 1 {
		return sqlguard.Reject("field access on an expression is not allowed", "A_Indirection")
	}
	rel := stringValue(cref.ColumnRef.Fields[0])
	display := "(" + rel + ")." + fields[0]
	if rel == "" || v.isColumnAnywhere(rel) {
		return sqlguard.Reject("field access on a column is not allowed", display)
	}
	it, ok := v.lookupRel([]string{rel})
	if !ok {
		return sqlguard.Reject("column reference does not name a relation in scope", display)
	}
	return v.checkColumn(it, fields[0], display)
}
