package chguard

import (
	"reflect"
	"strings"

	"github.com/AfterShip/clickhouse-sql-parser/parser"
	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/policy"
	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/sqlguard"
)

type chSlot struct {
	name   string
	expr   parser.Expr
	table  policy.TableRef
	column string
}
type chRelation struct {
	qualifiers [][]string
	slots      []chSlot
}
type chBindScope struct {
	relations []chRelation
	aliases   map[string]parser.Expr
	resolving map[string]bool
	locals    map[string]bool
	ctes      map[string][]string
}
type chColumnBinder struct {
	pol              *policy.Policy
	uses             map[policy.TableRef]map[string]bool
	depth            int
	steps, exprDepth int
}

func chBindIdent(name string) *parser.Ident {
	return &parser.Ident{Name: name, QuoteType: parser.BackTicks}
}
func chBindPath(parts ...string) parser.Expr {
	fields := make([]*parser.Ident, len(parts))
	for i, p := range parts {
		fields[i] = chBindIdent(p)
	}
	if len(fields) == 1 {
		return fields[0]
	}
	return &parser.Path{Fields: fields}
}
func chParts(e parser.Expr) ([]string, bool) {
	switch n := e.(type) {
	case *parser.Ident:
		return []string{n.Name}, true
	case *parser.NestedIdentifier:
		if n.DotIdent == nil {
			return []string{n.Ident.Name}, true
		}
		return []string{n.Ident.Name, n.DotIdent.Name}, true
	case *parser.Path:
		var out []string
		for _, f := range n.Fields {
			out = append(out, f.Name)
		}
		return out, true
	}
	return nil, false
}
func sameCHParts(a, b []string) bool {
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
func cloneCHValue(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(cloneCHValue(v.Elem()))
		return out
	case reflect.Pointer:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(cloneCHValue(v.Elem()))
		return out
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		for i := 0; i < v.NumField(); i++ {
			out.Field(i).Set(cloneCHValue(v.Field(i)))
		}
		return out
	case reflect.Slice:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(cloneCHValue(v.Index(i)))
		}
		return out
	default:
		return v
	}
}
func cloneCH(e parser.Expr) parser.Expr {
	return cloneCHValue(reflect.ValueOf(e)).Interface().(parser.Expr)
}
func (b *chColumnBinder) use(slot chSlot) error {
	if slot.column == "" {
		return nil
	}
	if reason := b.pol.ColumnDenial(slot.table, slot.column); reason != "" {
		return sqlguard.Reject(reason, slot.table.String()+"."+slot.column)
	}
	if b.uses[slot.table] == nil {
		b.uses[slot.table] = map[string]bool{}
	}
	b.uses[slot.table][slot.column] = true
	return nil
}
func (b *chColumnBinder) resolve(e parser.Expr, s *chBindScope) (parser.Expr, error) {
	parts, _ := chParts(e)
	if len(parts) == 0 {
		return nil, sqlguard.Reject("empty column reference", "")
	}
	for _, p := range parts {
		if p == "*" {
			return nil, sqlguard.Reject("wildcards are not allowed in annotation mode", "")
		}
		if strings.ContainsAny(p, "`\\\x00") {
			return nil, sqlguard.Reject("unsupported identifier characters", "")
		}
	}
	if len(parts) == 1 && s.locals[parts[0]] {
		return e, nil
	}
	var matches []chSlot
	for _, r := range s.relations {
		if len(parts) > 1 {
			matched := false
			for _, q := range r.qualifiers {
				if sameCHParts(q, parts[:len(parts)-1]) {
					matched = true
				}
			}
			if !matched {
				continue
			}
		}
		for _, slot := range r.slots {
			if slot.name == parts[len(parts)-1] {
				matches = append(matches, slot)
			}
		}
	}
	if len(matches) > 1 {
		return nil, sqlguard.Reject("ambiguous column; qualify the source explicitly", parser.Format(e))
	}
	if len(matches) == 1 {
		if err := b.use(matches[0]); err != nil {
			return nil, err
		}
		return cloneCH(matches[0].expr), nil
	}
	if len(parts) == 1 {
		name := parts[0]
		if a, ok := s.aliases[name]; ok {
			if s.resolving[name] {
				return nil, sqlguard.Reject("cyclic expression alias", name)
			}
			s.resolving[name] = true
			defer delete(s.resolving, name)
			// Bind the alias as written in its defining scope: lambda
			// parameters at the use site must not capture its names.
			defining := *s
			defining.locals = map[string]bool{}
			out, err := b.expr(cloneCH(a), &defining)
			if err != nil {
				return nil, err
			}
			if captured := chCapturedIdent(out, s.locals); captured != "" {
				return nil, sqlguard.Reject("expression alias would be captured by a lambda parameter", captured)
			}
			return chParenthesize(out), nil
		}
	}
	return nil, sqlguard.Reject("unknown column, subcolumn or whole-row reference", parser.Format(e))
}

// chParenthesize keeps the operator precedence of an inlined alias. Atoms
// (identifiers, literals, calls, subqueries, existing parentheses) need none.
func chParenthesize(e parser.Expr) parser.Expr {
	if _, ok := chParts(e); ok {
		return e
	}
	switch e.(type) {
	case *parser.NumberLiteral, *parser.StringLiteral, *parser.NullLiteral, *parser.FunctionExpr, *parser.ParamExprList, *parser.SubQuery, *parser.ArrayParamList:
		return e
	}
	return &parser.ParamExprList{Items: &parser.ColumnExprList{Items: []parser.Expr{&parser.ColumnExpr{Expr: e}}}}
}

// chUnparen removes one layer of parentheses added by chParenthesize.
func chUnparen(e parser.Expr) parser.Expr {
	if p, ok := e.(*parser.ParamExprList); ok && p.ColumnArgList == nil && p.Items != nil && len(p.Items.Items) == 1 {
		if c, ok := p.Items.Items[0].(*parser.ColumnExpr); ok && c.Alias == nil {
			return c.Expr
		}
	}
	return e
}

// chCapturedIdent reports an unqualified identifier in e that a lambda
// parameter in locals would capture.
func chCapturedIdent(e parser.Expr, locals map[string]bool) string {
	if len(locals) == 0 {
		return ""
	}
	found := ""
	var walk func(v reflect.Value)
	walk = func(v reflect.Value) {
		if found != "" || !v.IsValid() {
			return
		}
		switch v.Kind() {
		case reflect.Interface, reflect.Pointer:
			if v.IsNil() {
				return
			}
			switch n := v.Interface().(type) {
			case *parser.Ident:
				if locals[n.Name] {
					found = n.Name
				}
				return
			case *parser.Path:
				// Only the leading segment of a qualified path can bind to a
				// lambda parameter.
				if len(n.Fields) > 0 && locals[n.Fields[0].Name] {
					found = n.Fields[0].Name
				}
				return
			case *parser.FunctionExpr:
				// Function names are not variables; check arguments only.
				walk(reflect.ValueOf(n.Params))
				return
			}
			walk(v.Elem())
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).IsExported() {
					walk(v.Field(i))
				}
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i))
			}
		}
	}
	walk(reflect.ValueOf(e))
	return found
}
func (b *chColumnBinder) query(q *parser.SelectQuery, parent map[string][]string) ([]string, error) {
	b.depth++
	defer func() { b.depth-- }()
	if b.depth > 64 {
		return nil, sqlguard.Reject("query nesting limit exceeded", "")
	}
	s := &chBindScope{aliases: map[string]parser.Expr{}, resolving: map[string]bool{}, locals: map[string]bool{}, ctes: map[string][]string{}}
	for name, cols := range parent {
		s.ctes[name] = cols
	}
	if q.InnerQuery != nil {
		names, err := b.query(q.InnerQuery, parent)
		if err != nil {
			return nil, err
		}
		return names, b.branches(q, parent)
	}
	if q.With != nil {
		for _, c := range q.With.CTEs {
			if sub, ok := c.Alias.(*parser.SelectQuery); ok {
				id, ok := c.Expr.(*parser.Ident)
				if !ok {
					return nil, sqlguard.Reject("unsupported CTE name", "")
				}
				names, err := b.query(sub, s.ctes)
				if err != nil {
					return nil, err
				}
				if _, exists := s.ctes[id.Name]; exists {
					return nil, sqlguard.Reject("duplicate or shadowed CTE", id.Name)
				}
				s.ctes[id.Name] = names
			} else {
				alias, ok := c.Alias.(*parser.Ident)
				if !ok {
					return nil, sqlguard.Reject("unsupported WITH alias", "")
				}
				if _, exists := s.aliases[alias.Name]; exists {
					return nil, sqlguard.Reject("duplicate alias", alias.Name)
				}
				s.aliases[alias.Name] = c.Expr
			}
		}
	}
	var constraints []parser.Expr
	var arrays []*parser.ColumnExprList
	if q.From != nil {
		if err := b.from(q.From.Expr, s, &constraints, &arrays); err != nil {
			return nil, err
		}
	}
	for _, a := range arrays {
		for _, item := range a.Items {
			ce, ok := item.(*parser.ColumnExpr)
			if !ok {
				return nil, sqlguard.Reject("unsupported ARRAY JOIN expression", "")
			}
			e, err := b.expr(ce.Expr, s)
			if err != nil {
				return nil, err
			}
			ce.Expr = e
			if ce.Alias != nil {
				s.relations = append(s.relations, chRelation{slots: []chSlot{{name: ce.Alias.Name, expr: chBindPath(ce.Alias.Name)}}})
			}
		}
	}
	// ClickHouse reads `alias.x` as subcolumn x of a column named alias when
	// one exists, before the relation alias. A relation alias that equals a
	// column name (or a flattened Nested prefix) in scope is therefore
	// ambiguous between a checked column and an unchecked subcolumn.
	columnNames := map[string]bool{}
	for _, r := range s.relations {
		for _, slot := range r.slots {
			columnNames[slot.name] = true
			if i := strings.IndexByte(slot.name, '.'); i > 0 {
				columnNames[slot.name[:i]] = true
			}
		}
	}
	for _, r := range s.relations {
		for _, q := range r.qualifiers {
			if len(q) == 1 && columnNames[q[0]] {
				return nil, sqlguard.Reject("relation alias shadows a column or subcolumn path; choose a different alias", q[0])
			}
		}
	}
	// A colliding alias could be substituted into even qualified expressions.
	// Reject collisions except a plain identity projection, then pin column-first
	// resolution at the database role and inline all other expression aliases.
	for _, item := range q.SelectItems {
		if item.Alias != nil {
			name := item.Alias.Name
			if previous, exists := s.aliases[name]; exists && parser.Format(chUnparen(previous)) != parser.Format(chUnparen(item.Expr)) {
				return nil, sqlguard.Reject("duplicate expression alias", name)
			}
			collision := false
			for _, r := range s.relations {
				for _, slot := range r.slots {
					if slot.name == name {
						collision = true
					}
				}
			}
			if collision {
				parts, ok := chParts(item.Expr)
				if !ok || parts[len(parts)-1] != name {
					return nil, sqlguard.Reject("expression alias collides with a source column", name)
				}
			}
			s.aliases[name] = item.Expr
		}
	}
	for _, e := range constraints {
		if err := b.constraint(e, s); err != nil {
			return nil, err
		}
	}
	if q.With != nil {
		for _, c := range q.With.CTEs {
			if _, ok := c.Alias.(*parser.SelectQuery); !ok {
				e, err := b.expr(c.Expr, s)
				if err != nil {
					return nil, err
				}
				c.Expr = e
			}
		}
	}
	var names []string
	for _, item := range q.SelectItems {
		if len(item.Modifiers) > 0 {
			return nil, sqlguard.Reject("wildcard modifiers are not allowed", "")
		}
		name := ""
		if item.Alias != nil {
			name = item.Alias.Name
		} else if parts, ok := chParts(item.Expr); ok {
			name = parts[len(parts)-1]
		} else {
			name = parser.Format(item.Expr)
		}
		if strings.ContainsAny(name, "`\\\x00\n") {
			return nil, sqlguard.Reject("expression needs an explicit simple alias", "")
		}
		e, err := b.expr(item.Expr, s)
		if err != nil {
			return nil, err
		}
		item.Expr = e
		item.Alias = chBindIdent(name)
		names = append(names, name)
	}
	// Names in the WINDOW declaration are syntactic; only its expressions bind.
	if q.Window != nil {
		for _, w := range q.Window.Windows {
			if _, err := b.expr(w.Expr, s); err != nil {
				return nil, err
			}
		}
	}
	for _, e := range []parser.Expr{q.DistinctOn, q.Prewhere, q.Where, q.GroupBy, q.Having, q.OrderBy, q.LimitBy, q.Limit} {
		if !isNil(e) {
			if _, err := b.expr(e, s); err != nil {
				return nil, err
			}
		}
	}
	return names, b.branches(q, parent)
}
func (b *chColumnBinder) branches(q *parser.SelectQuery, ctes map[string][]string) error {
	for _, sub := range []*parser.SelectQuery{q.UnionAll, q.UnionDistinct, q.Except, q.Intersect} {
		if sub != nil {
			if _, err := b.query(sub, ctes); err != nil {
				return err
			}
		}
	}
	return nil
}
func (b *chColumnBinder) from(e parser.Expr, s *chBindScope, constraints *[]parser.Expr, arrays *[]*parser.ColumnExprList) error {
	switch n := e.(type) {
	case *parser.JoinExpr:
		if err := b.from(n.Left, s, constraints, arrays); err != nil {
			return err
		}
		if !isNil(n.Right) {
			if err := b.from(n.Right, s, constraints, arrays); err != nil {
				return err
			}
		}
		if !isNil(n.Constraints) {
			*constraints = append(*constraints, n.Constraints)
		}
		return nil
	case *parser.JoinTableExpr:
		if n.HasFinal || n.SampleRatio != nil {
			return sqlguard.Reject("FINAL/SAMPLE require additional dependency validation", "")
		}
		return b.from(n.Table, s, constraints, arrays)
	case *parser.TableExpr:
		if n.HasFinal || n.Alias != nil {
			return sqlguard.Reject("unsupported table modifiers", "")
		}
		return b.from(n.Expr, s, constraints, arrays)
	case *parser.ColumnExprList:
		*arrays = append(*arrays, n)
		return nil
	}
	alias := ""
	if a, ok := e.(*parser.AliasExpr); ok {
		id, ok := a.Alias.(*parser.Ident)
		if !ok {
			return sqlguard.Reject("unsupported relation alias", "")
		}
		alias = id.Name
		e = a.Expr
	}
	var names []string
	var ref policy.TableRef
	var qualifiers [][]string
	var base bool
	switch n := e.(type) {
	case *parser.TableIdentifier:
		if n.Table == nil {
			return sqlguard.Reject("missing table name", "")
		}
		if cte, ok := s.ctes[n.Table.Name]; ok && n.Database == nil {
			names = cte
			qualifiers = [][]string{{n.Table.Name}}
		} else {
			ref = policy.TableRef{Schema: b.pol.DefaultSchema, Name: n.Table.Name}
			if n.Database != nil {
				ref.Schema = n.Database.Name
			}
			r, ok := b.pol.Relation(ref)
			if !ok {
				return sqlguard.Reject("relation is not in the catalog", ref.String())
			}
			if !b.pol.CanRead(ref) {
				reason := r.Denial
				if reason == "" {
					reason = "no selectable columns"
				}
				return sqlguard.Reject(reason, ref.String())
			}
			for _, c := range r.Columns {
				names = append(names, c.Name)
			}
			base = true
			qualifiers = [][]string{{ref.Schema, ref.Name}, {ref.Name}}
		}
	case *parser.SubQuery:
		var err error
		names, err = b.query(n.Select, s.ctes)
		if err != nil {
			return err
		}
	case *parser.SelectQuery:
		var err error
		names, err = b.query(n, s.ctes)
		if err != nil {
			return err
		}
	default:
		return sqlguard.Reject("unsupported relation in annotation mode", nodeName(e))
	}
	if alias != "" {
		qualifiers = [][]string{{alias}}
	}
	if len(qualifiers) == 0 {
		return sqlguard.Reject("derived relations require an alias", "")
	}
	var slots []chSlot
	for _, name := range names {
		slot := chSlot{name: name, expr: chBindPath(append(append([]string{}, qualifiers[0]...), name)...)}
		if base {
			slot.table = ref
			slot.column = name
		}
		slots = append(slots, slot)
	}
	s.relations = append(s.relations, chRelation{qualifiers: qualifiers, slots: slots})
	return nil
}
func (b *chColumnBinder) constraint(e parser.Expr, s *chBindScope) error {
	var using parser.Expr
	switch n := e.(type) {
	case *parser.OnClause:
		out, err := b.expr(n.On, s)
		if err == nil {
			n.On = out.(*parser.ColumnExprList)
		}
		return err
	case *parser.UsingClause:
		using = n.Using
	case *parser.JoinConstraintClause:
		if !isNil(n.On) {
			out, err := b.expr(n.On, s)
			if err != nil {
				return err
			}
			if err == nil {
				n.On = out.(*parser.ColumnExprList)
			}
		}
		using = n.Using
	default:
		return sqlguard.Reject("unsupported join constraint", nodeName(e))
	}
	if isNil(using) {
		return nil
	}
	list, ok := using.(*parser.ColumnExprList)
	if !ok {
		return sqlguard.Reject("unsupported USING list", "")
	}
	for _, e := range list.Items {
		ce, ok := e.(*parser.ColumnExpr)
		if !ok {
			return sqlguard.Reject("unsupported USING column", "")
		}
		parts, ok := chParts(ce.Expr)
		if !ok || len(parts) != 1 {
			return sqlguard.Reject("USING requires plain columns", "")
		}
		count := 0
		for _, r := range s.relations {
			for _, slot := range r.slots {
				if slot.name == parts[0] {
					count++
					if err := b.use(slot); err != nil {
						return err
					}
				}
			}
		}
		if count != 2 {
			return sqlguard.Reject("ambiguous USING scope; use an explicit ON clause", parts[0])
		}
	}
	return nil
}

var chExprInterface = reflect.TypeFor[parser.Expr]()

func (b *chColumnBinder) children(e parser.Expr, s *chBindScope, skip ...string) error {
	value := reflect.ValueOf(e)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return nil
	}
	value = value.Elem()
	if value.Kind() != reflect.Struct {
		return nil
	}
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		name := value.Type().Field(i).Name
		ignored := false
		for _, key := range skip {
			if name == key {
				ignored = true
			}
		}
		if ignored {
			continue
		}
		update := func(f reflect.Value) error {
			if !f.Type().Implements(chExprInterface) || f.IsNil() {
				return nil
			}
			out, err := b.expr(f.Interface().(parser.Expr), s)
			if err != nil {
				return err
			}
			v := reflect.ValueOf(out)
			if !v.Type().AssignableTo(f.Type()) {
				return sqlguard.Reject("unsupported binding in typed expression", name)
			}
			f.Set(v)
			return nil
		}
		if field.Kind() == reflect.Slice {
			for j := 0; j < field.Len(); j++ {
				if err := update(field.Index(j)); err != nil {
					return err
				}
			}
		} else if field.Kind() == reflect.Pointer || field.Kind() == reflect.Interface {
			if err := update(field); err != nil {
				return err
			}
		}
	}
	return nil
}
func (b *chColumnBinder) expr(e parser.Expr, s *chBindScope) (parser.Expr, error) {
	if isNil(e) {
		return e, nil
	}
	b.steps++
	b.exprDepth++
	defer func() { b.exprDepth-- }()
	if b.steps > 20000 || b.exprDepth > 256 {
		return nil, sqlguard.Reject("expression expansion limit exceeded", "")
	}
	if _, ok := chParts(e); ok {
		return b.resolve(e, s)
	}
	switch n := e.(type) {
	case *parser.SelectQuery:
		_, err := b.query(n, s.ctes)
		return e, err
	case *parser.SubQuery:
		_, err := b.query(n.Select, s.ctes)
		return e, err
	case *parser.AliasExpr:
		return nil, sqlguard.Reject("nested expression aliases are not supported", "")
	case *parser.MapLiteral:
		return nil, sqlguard.Reject("map literals are not supported in annotation mode; use map()", "")
	case *parser.ColumnExpr:
		if n.Alias != nil {
			return nil, sqlguard.Reject("nested expression aliases are not supported", "")
		}
		return e, b.children(e, s, "Alias")
	case *parser.FunctionExpr:
		if n.Name == nil {
			return nil, sqlguard.Reject("malformed function", "")
		}
		name := n.Name.Name
		if b.pol.Catalog == nil {
			return nil, sqlguard.Reject("function catalog is unavailable", name)
		}
		canonical, ok := b.pol.Catalog.BuiltinFunctions[name]
		if !ok {
			canonical, ok = b.pol.Catalog.CaseInsensitiveFunctions[strings.ToLower(name)]
		}
		if !ok && !strings.EqualFold(name, "columns") {
			return nil, sqlguard.Reject("function is not an approved built-in", name)
		}
		if ok {
			n.Name.Name = canonical
		}
		if strings.EqualFold(n.Name.Name, "columns") {
			return nil, sqlguard.Reject("wildcard column matchers are not allowed", "")
		}
		if strings.EqualFold(n.Name.Name, "count") && n.Params != nil && n.Params.Items != nil && !n.Params.Items.HasDistinct && len(n.Params.Items.Items) == 1 && n.Params.ColumnArgList == nil {
			if ce, ok := n.Params.Items.Items[0].(*parser.ColumnExpr); ok && ce.Alias == nil {
				if id, ok := ce.Expr.(*parser.Ident); ok && id.Name == "*" {
					n.Name.Name = "count"
					n.Params.Items.Items = nil
					return e, nil
				}
			}
		}
		return e, b.children(e, s, "Name")
	case *parser.BinaryOperation:
		if n.Operation == parser.TokenKindArrow {
			local := *s
			local.locals = map[string]bool{}
			for name, value := range s.locals {
				local.locals[name] = value
			}
			var params []string
			var collect func(parser.Expr) bool
			collect = func(e parser.Expr) bool {
				switch p := e.(type) {
				case *parser.Ident:
					params = append(params, p.Name)
					return true
				case *parser.ColumnExpr:
					return collect(p.Expr)
				case *parser.ParamExprList:
					if p.Items == nil {
						return false
					}
					return collect(p.Items)
				case *parser.ColumnExprList:
					for _, item := range p.Items {
						if !collect(item) {
							return false
						}
					}
					return true
				}
				return false
			}
			if !collect(n.LeftExpr) || len(params) == 0 {
				return nil, sqlguard.Reject("unsupported lambda parameters", "")
			}
			for _, name := range params {
				local.locals[name] = true
			}
			out, err := b.expr(n.RightExpr, &local)
			n.RightExpr = out
			return e, err
		}
		if n.Operation == parser.TokenKindDash {
			return e, b.children(e, s, "RightExpr")
		}
	case *parser.CastExpr:
		return e, b.children(e, s, "AsType")
	case *parser.WindowFunctionExpr:
		if _, ok := n.OverExpr.(*parser.Ident); ok {
			return e, b.children(e, s, "OverExpr")
		}
	case *parser.IntervalExpr:
		return e, b.children(e, s, "Unit")
	}
	return e, b.children(e, s)
}
func bindCHAnnotations(q *parser.SelectQuery, p *policy.Policy) (map[policy.TableRef][]string, error) {
	b := &chColumnBinder{pol: p, uses: map[policy.TableRef]map[string]bool{}}
	if _, err := b.query(q, nil); err != nil {
		return nil, err
	}
	out := map[policy.TableRef][]string{}
	for ref, cols := range b.uses {
		for _, name := range p.ReadableColumns(ref) {
			if cols[name] {
				out[ref] = append(out[ref], name)
			}
		}
	}
	return out, nil
}
