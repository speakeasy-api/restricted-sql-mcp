package chguard

import (
	"reflect"
	"strings"

	"github.com/AfterShip/clickhouse-sql-parser/parser"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/sqlguard"
)

func unsupported(e parser.Expr) error {
	return sqlguard.Reject("unsupported syntax", nodeName(e))
}

// isNil is true for a nil interface and for a typed nil pointer stored in the
// interface, which the parser produces for absent optional children.
func isNil(e parser.Expr) bool {
	if e == nil {
		return true
	}
	rv := reflect.ValueOf(e)
	return rv.Kind() == reflect.Ptr && rv.IsNil()
}

// selectQuery walks one SELECT (or a parenthesised group) including its
// set-operation branches. CTE names are visible inside the query's own clauses
// and subqueries, but not in set-operation branches, matching ClickHouse.
func (v *visitor) selectQuery(s *parser.SelectQuery) error {
	if s == nil {
		return sqlguard.Reject("empty SELECT", "SelectQuery")
	}
	if s.Settings != nil {
		return sqlguard.Reject("SETTINGS clause is not allowed", "SettingsClause")
	}
	if s.Format != nil {
		return sqlguard.Reject("FORMAT clause is not allowed", "FormatClause")
	}
	if s.InnerQuery != nil {
		if err := v.selectQuery(s.InnerQuery); err != nil {
			return err
		}
		return v.setOperations(s)
	}
	v.pushScope()
	defer v.popScope()
	if s.With != nil {
		for _, cte := range s.With.CTEs {
			if err := v.cte(cte); err != nil {
				return err
			}
		}
	}
	if s.Top != nil && s.Top.Number == nil {
		return unsupported(s.Top)
	}
	if s.DistinctOn != nil {
		for _, id := range s.DistinctOn.Idents {
			if err := v.expr(id); err != nil {
				return err
			}
		}
	}
	if len(s.SelectItems) == 0 {
		return sqlguard.Reject("SELECT without select items", "SelectQuery")
	}
	for _, item := range s.SelectItems {
		if err := v.selectItem(item); err != nil {
			return err
		}
	}
	if s.From != nil {
		if err := v.tableSource(s.From.Expr); err != nil {
			return err
		}
	}
	if s.Window != nil {
		for _, w := range s.Window.Windows {
			if err := v.windowExpr(w.Expr); err != nil {
				return err
			}
		}
	}
	if s.Prewhere != nil {
		if err := v.expr(s.Prewhere.Expr); err != nil {
			return err
		}
	}
	if s.Where != nil {
		if err := v.expr(s.Where.Expr); err != nil {
			return err
		}
	}
	if s.GroupBy != nil {
		if err := v.expr(s.GroupBy.Expr); err != nil {
			return err
		}
	}
	if s.Having != nil {
		if err := v.expr(s.Having.Expr); err != nil {
			return err
		}
	}
	if s.OrderBy != nil {
		if err := v.orderBy(s.OrderBy); err != nil {
			return err
		}
	}
	if s.LimitBy != nil {
		if err := v.limit(s.LimitBy.Limit); err != nil {
			return err
		}
		if err := v.expr(s.LimitBy.ByExpr); err != nil {
			return err
		}
	}
	if err := v.limit(s.Limit); err != nil {
		return err
	}
	v.popScope()
	v.pushScope()
	return v.setOperations(s)
}

func (v *visitor) setOperations(s *parser.SelectQuery) error {
	for _, branch := range []*parser.SelectQuery{s.UnionAll, s.UnionDistinct, s.Except, s.Intersect} {
		if branch == nil {
			continue
		}
		if err := v.selectQuery(branch); err != nil {
			return err
		}
	}
	return nil
}

// cte handles both `name AS (SELECT ...)` (a relation, added to scope) and
// `expr AS name` (a scalar alias, not a relation).
func (v *visitor) cte(c *parser.CTEStmt) error {
	if sub, ok := c.Alias.(*parser.SelectQuery); ok {
		name, ok := c.Expr.(*parser.Ident)
		if !ok {
			return sqlguard.Reject("CTE name must be an identifier", nodeName(c.Expr))
		}
		if err := v.selectQuery(sub); err != nil {
			return err
		}
		v.addCTE(name.Name)
		return nil
	}
	alias, ok := c.Alias.(*parser.Ident)
	if !ok {
		return sqlguard.Reject("WITH expression alias must be an identifier", nodeName(c.Alias))
	}
	v.addScalar(alias.Name)
	return v.expr(c.Expr)
}

func (v *visitor) selectItem(item *parser.SelectItem) error {
	if err := v.expr(item.Expr); err != nil {
		return err
	}
	for _, m := range item.Modifiers {
		if err := v.starModifier(m); err != nil {
			return err
		}
	}
	return nil
}

// starModifier validates `* EXCEPT (...)`, `* REPLACE (...)` and `* APPLY (f)`.
func (v *visitor) starModifier(m *parser.FunctionExpr) error {
	if m == nil || m.Name == nil {
		return sqlguard.Reject("malformed select modifier", "FunctionExpr")
	}
	switch strings.ToUpper(m.Name.Name) {
	case "EXCEPT", "REPLACE":
		return v.expr(m.Params)
	case "APPLY":
		if m.Params == nil || m.Params.Items == nil {
			return sqlguard.Reject("APPLY without a function", "APPLY")
		}
		for _, arg := range m.Params.Items.Items {
			ce, ok := arg.(*parser.ColumnExpr)
			if !ok {
				return unsupported(arg)
			}
			switch a := ce.Expr.(type) {
			case *parser.Ident:
				if !policy.AllowedFunction(policy.ClickHouse, a.Name) {
					return sqlguard.Reject("function is not allowed", a.Name)
				}
			case *parser.BinaryOperation:
				if a.Operation != parser.TokenKindArrow {
					return unsupported(a)
				}
				if err := v.expr(a); err != nil {
					return err
				}
			default:
				return unsupported(ce.Expr)
			}
		}
		return nil
	}
	return sqlguard.Reject("unsupported select modifier", m.Name.Name)
}

// tableSource walks the FROM tree: joins, relations, subqueries.
func (v *visitor) tableSource(e parser.Expr) error {
	if isNil(e) {
		return sqlguard.Reject("empty FROM clause", "FromClause")
	}
	switch n := e.(type) {
	case *parser.JoinExpr:
		if err := v.joinModifiers(n.Modifiers); err != nil {
			return err
		}
		if err := v.tableSource(n.Left); err != nil {
			return err
		}
		if n.Right != nil {
			if err := v.tableSource(n.Right); err != nil {
				return err
			}
		}
		return v.joinConstraint(n.Constraints)
	case *parser.JoinTableExpr:
		if n.SampleRatio != nil {
			return sqlguard.Reject("SAMPLE is not allowed", "SampleClause")
		}
		return v.tableExpr(n.Table)
	case *parser.TableExpr:
		return v.tableExpr(n)
	case *parser.ColumnExprList:
		// ARRAY JOIN items: plain expressions (arrays, subqueries).
		return v.expr(n)
	}
	return unsupported(e)
}

var allowedJoinModifiers = map[string]struct{}{
	"JOIN": {}, "INNER": {}, "LEFT": {}, "RIGHT": {}, "FULL": {}, "OUTER": {}, "CROSS": {},
	"ANY": {}, "ALL": {}, "ASOF": {}, "SEMI": {}, "ANTI": {}, "ARRAY": {}, "GLOBAL": {},
}

func (v *visitor) joinModifiers(mods []string) error {
	for _, m := range mods {
		if _, ok := allowedJoinModifiers[strings.ToUpper(m)]; !ok {
			return sqlguard.Reject("join modifier is not allowed", m)
		}
	}
	return nil
}

func (v *visitor) joinConstraint(e parser.Expr) error {
	if isNil(e) {
		return nil
	}
	switch n := e.(type) {
	case *parser.OnClause:
		return v.expr(n.On)
	case *parser.UsingClause:
		return v.expr(n.Using)
	case *parser.JoinConstraintClause:
		if err := v.expr(n.On); err != nil {
			return err
		}
		return v.expr(n.Using)
	}
	return unsupported(e)
}

func (v *visitor) tableExpr(t *parser.TableExpr) error {
	if t == nil {
		return sqlguard.Reject("empty table expression", "TableExpr")
	}
	return v.relation(t.Expr)
}

// relation is one FROM/JOIN operand: a table, an aliased table, or a subquery.
func (v *visitor) relation(e parser.Expr) error {
	if isNil(e) {
		return sqlguard.Reject("empty relation", "TableExpr")
	}
	switch n := e.(type) {
	case *parser.TableIdentifier:
		return v.tableIdentifier(n)
	case *parser.AliasExpr:
		if _, ok := n.Alias.(*parser.Ident); !ok {
			return sqlguard.Reject("alias must be an identifier", nodeName(n.Alias))
		}
		return v.relation(n.Expr)
	case *parser.SubQuery:
		return v.selectQuery(n.Select)
	case *parser.SelectQuery:
		return v.selectQuery(n)
	case *parser.TableFunctionExpr:
		return sqlguard.Reject("table functions are not allowed", functionName(n.Name))
	case *parser.Ident:
		return sqlguard.Reject("unexpected identifier as a relation", n.Name)
	}
	return unsupported(e)
}

func functionName(e parser.Expr) string {
	if id, ok := e.(*parser.Ident); ok {
		return id.Name
	}
	return nodeName(e)
}

func (v *visitor) orderBy(o *parser.OrderByClause) error {
	if o == nil {
		return nil
	}
	for _, item := range o.Items {
		if err := v.expr(item); err != nil {
			return err
		}
	}
	if o.Interpolate != nil {
		for _, it := range o.Interpolate.Items {
			if err := v.expr(it.Expr); err != nil {
				return err
			}
		}
	}
	return nil
}

func (v *visitor) limit(l *parser.LimitClause) error {
	if l == nil {
		return nil
	}
	if err := v.expr(l.Limit); err != nil {
		return err
	}
	return v.expr(l.Offset)
}

func (v *visitor) windowExpr(w *parser.WindowExpr) error {
	if w == nil {
		return nil
	}
	if w.PartitionBy != nil {
		if err := v.expr(w.PartitionBy.Expr); err != nil {
			return err
		}
	}
	if err := v.orderBy(w.OrderBy); err != nil {
		return err
	}
	if w.Frame != nil {
		return v.frameExtend(w.Frame.Extend)
	}
	return nil
}

func (v *visitor) frameExtend(e parser.Expr) error {
	if isNil(e) {
		return nil
	}
	switch n := e.(type) {
	case *parser.BetweenClause:
		if err := v.frameExtend(n.Between); err != nil {
			return err
		}
		return v.frameExtend(n.And)
	case *parser.WindowFrameExtendExpr:
		return v.frameExtend(n.Expr)
	case *parser.WindowFrameCurrentRow, *parser.WindowFrameUnbounded:
		return nil
	case *parser.WindowFrameNumber:
		return nil
	}
	return unsupported(e)
}

var allowedOperators = map[string]struct{}{
	"=": {}, "==": {}, "!=": {}, "<>": {}, "<": {}, "<=": {}, ">": {}, ">=": {},
	"+": {}, "-": {}, "*": {}, "/": {}, "%": {}, "||": {},
	"AND": {}, "OR": {}, "LIKE": {}, "NOT LIKE": {}, "ILIKE": {}, "NOT ILIKE": {}, "REGEXP": {},
	"IN": {}, "NOT IN": {},
}

// expr walks an expression tree. Every node type must be listed here; anything
// else is rejected by name.
func (v *visitor) expr(e parser.Expr) error {
	if isNil(e) {
		return nil
	}
	switch n := e.(type) {
	case *parser.Ident, *parser.NestedIdentifier, *parser.Path:
		return nil
	case *parser.NumberLiteral, *parser.StringLiteral, *parser.BoolLiteral,
		*parser.NullLiteral, *parser.NotNullLiteral:
		return nil
	case *parser.BinaryOperation:
		return v.binaryOperation(n)
	case *parser.UnaryExpr:
		return v.expr(n.Expr)
	case *parser.NotExpr:
		return v.expr(n.Expr)
	case *parser.NegateExpr:
		return v.expr(n.Expr)
	case *parser.TernaryOperation:
		if err := v.expr(n.Condition); err != nil {
			return err
		}
		if err := v.expr(n.TrueExpr); err != nil {
			return err
		}
		return v.expr(n.FalseExpr)
	case *parser.IndexOperation:
		if err := v.expr(n.Object); err != nil {
			return err
		}
		return v.expr(n.Index)
	case *parser.ObjectParams:
		if err := v.expr(n.Object); err != nil {
			return err
		}
		return v.expr(n.Params)
	case *parser.ArrayParamList:
		return v.expr(n.Items)
	case *parser.ParamExprList:
		if err := v.expr(n.Items); err != nil {
			return err
		}
		return v.expr(n.ColumnArgList)
	case *parser.ColumnExprList:
		for _, item := range n.Items {
			if err := v.expr(item); err != nil {
				return err
			}
		}
		return nil
	case *parser.ColumnArgList:
		for _, item := range n.Items {
			if err := v.expr(item); err != nil {
				return err
			}
		}
		return nil
	case *parser.ColumnExpr:
		if n.Alias != nil {
			if err := v.expr(n.Alias); err != nil {
				return err
			}
		}
		return v.expr(n.Expr)
	case *parser.AliasExpr:
		if _, ok := n.Alias.(*parser.Ident); !ok {
			return sqlguard.Reject("alias must be an identifier", nodeName(n.Alias))
		}
		return v.expr(n.Expr)
	case *parser.MapLiteral:
		for _, kv := range n.KeyValues {
			if err := v.expr(kv.Value); err != nil {
				return err
			}
		}
		return nil
	case *parser.FunctionExpr:
		return v.functionExpr(n)
	case *parser.WindowFunctionExpr:
		if err := v.functionExpr(n.Function); err != nil {
			return err
		}
		switch over := n.OverExpr.(type) {
		case *parser.Ident:
			return nil
		case *parser.WindowExpr:
			return v.windowExpr(over)
		}
		return unsupported(n.OverExpr)
	case *parser.WindowExpr:
		return v.windowExpr(n)
	case *parser.BetweenClause:
		if err := v.expr(n.Expr); err != nil {
			return err
		}
		if err := v.expr(n.Between); err != nil {
			return err
		}
		return v.expr(n.And)
	case *parser.CaseExpr:
		if err := v.expr(n.Expr); err != nil {
			return err
		}
		for _, w := range n.Whens {
			if err := v.expr(w.When); err != nil {
				return err
			}
			if err := v.expr(w.Then); err != nil {
				return err
			}
			if err := v.expr(w.Else); err != nil {
				return err
			}
		}
		return v.expr(n.Else)
	case *parser.CastExpr:
		if err := v.expr(n.Expr); err != nil {
			return err
		}
		return v.castType(n.AsType)
	case *parser.SubQuery:
		return v.selectQuery(n.Select)
	case *parser.SelectQuery:
		return v.selectQuery(n)
	case *parser.IsNullExpr:
		return v.expr(n.Expr)
	case *parser.IsNotNullExpr:
		return v.expr(n.Expr)
	case *parser.IntervalExpr:
		return v.expr(n.Expr)
	case *parser.ExtractExpr:
		for _, p := range n.Parameters {
			if err := v.expr(p); err != nil {
				return err
			}
		}
		return nil
	case *parser.IntervalFrom:
		return v.expr(n.FromExpr)
	case *parser.OrderExpr:
		if err := v.expr(n.Expr); err != nil {
			return err
		}
		if n.Fill != nil {
			for _, f := range []parser.Expr{n.Fill.From, n.Fill.To, n.Fill.Step, n.Fill.Staleness} {
				if err := v.expr(f); err != nil {
					return err
				}
			}
		}
		return nil
	case *parser.OrderByClause:
		return v.orderBy(n)
	case *parser.QueryParam, *parser.PlaceHolder, *parser.TypedPlaceholder:
		return sqlguard.Reject("bind parameters are not supported", nodeName(e))
	case *parser.TableIdentifier:
		return sqlguard.Reject("table reference is not allowed here", nodeName(e))
	case *parser.TableFunctionExpr:
		return sqlguard.Reject("table functions are not allowed", functionName(n.Name))
	}
	return unsupported(e)
}

func (v *visitor) binaryOperation(n *parser.BinaryOperation) error {
	switch n.Operation {
	case parser.TokenKindArrow:
		return v.lambda(n)
	case parser.TokenKindDash:
		if err := v.expr(n.LeftExpr); err != nil {
			return err
		}
		return v.castType(n.RightExpr)
	}
	op := strings.ToUpper(string(n.Operation))
	if _, ok := allowedOperators[op]; !ok {
		return sqlguard.Reject("operator is not allowed", string(n.Operation))
	}
	if err := v.expr(n.LeftExpr); err != nil {
		return err
	}
	if op == "IN" || op == "NOT IN" {
		// A bare identifier on the right of IN names a table in ClickHouse.
		switch r := n.RightExpr.(type) {
		case *parser.Ident:
			return sqlguard.Reject("IN with a table name is not allowed", r.Name)
		case *parser.NestedIdentifier, *parser.Path:
			return sqlguard.Reject("IN with a table name is not allowed", parser.Format(r))
		}
		// A parenthesised single identifier, e.g. IN (forbidden_secrets) or
		// IN (app.forbidden_secrets), is also resolved as a table.
		if name, ok := v.relationRefInSet(n.RightExpr); ok {
			return sqlguard.Reject("IN with a table name is not allowed", name)
		}
	}
	return v.expr(n.RightExpr)
}

// lambda validates `params -> body`: parameters must be identifiers.
func (v *visitor) lambda(n *parser.BinaryOperation) error {
	switch p := n.LeftExpr.(type) {
	case *parser.Ident:
	case *parser.ParamExprList:
		if p.Items == nil || p.ColumnArgList != nil {
			return sqlguard.Reject("lambda parameters must be identifiers", "ParamExprList")
		}
		for _, item := range p.Items.Items {
			ce, ok := item.(*parser.ColumnExpr)
			if !ok {
				return sqlguard.Reject("lambda parameters must be identifiers", nodeName(item))
			}
			if _, ok := ce.Expr.(*parser.Ident); !ok || ce.Alias != nil {
				return sqlguard.Reject("lambda parameters must be identifiers", nodeName(ce.Expr))
			}
		}
	default:
		return sqlguard.Reject("lambda parameters must be identifiers", nodeName(n.LeftExpr))
	}
	return v.expr(n.RightExpr)
}

// setFunctions are the membership functions whose set argument (everything
// after the first) ClickHouse resolves as a table when it is an identifier,
// e.g. in(x, forbidden_secrets) or globalIn(x, app.forbidden_secrets). These
// are the function-call spellings of the IN operator and need the same guard.
var setFunctions = map[string]struct{}{
	"in": {}, "notin": {}, "globalin": {}, "globalnotin": {},
}

func (v *visitor) functionExpr(f *parser.FunctionExpr) error {
	if f == nil || f.Name == nil {
		return sqlguard.Reject("malformed function call", "FunctionExpr")
	}
	if !policy.AllowedFunction(policy.ClickHouse, f.Name.Name) {
		return sqlguard.Reject("function is not allowed", f.Name.Name)
	}
	if _, ok := setFunctions[strings.ToLower(f.Name.Name)]; ok {
		if err := v.rejectSetTableArgs(f.Params); err != nil {
			return err
		}
	}
	if f.Params == nil {
		return nil
	}
	return v.expr(f.Params)
}

// rejectSetTableArgs rejects a table identifier in the set position (any
// argument after the first) of a membership function.
func (v *visitor) rejectSetTableArgs(params *parser.ParamExprList) error {
	if params == nil || params.Items == nil {
		return nil
	}
	for i, item := range params.Items.Items {
		if i == 0 {
			continue
		}
		arg := item
		if ce, ok := item.(*parser.ColumnExpr); ok {
			arg = ce.Expr
		}
		if name, ok := v.relationRefInSet(arg); ok {
			return sqlguard.Reject("IN with a table name is not allowed", name)
		}
	}
	return nil
}

// relationRefInSet reports whether e, in a set/membership position, denotes a
// table reference rather than a value. It unwraps parentheses and flags a
// qualified name (schema.table) or a bare identifier that is not a CTE or
// scalar alias in scope; ClickHouse resolves such a name as a table.
func (v *visitor) relationRefInSet(e parser.Expr) (string, bool) {
	switch n := unwrapParens(e).(type) {
	case *parser.NestedIdentifier:
		return parser.Format(n), true
	case *parser.Path:
		return parser.Format(n), true
	case *parser.Ident:
		if v.cteInScope(n.Name) || v.scalarInScope(n.Name) {
			return "", false
		}
		return n.Name, true
	}
	return "", false
}

// unwrapParens follows a chain of parenthesised single-element expression
// lists, e.g. (x) or ((x)), returning the innermost expression. Anything with
// an alias, a column-arg list, or more than one element is returned as-is.
func unwrapParens(e parser.Expr) parser.Expr {
	for {
		pl, ok := e.(*parser.ParamExprList)
		if !ok || pl.ColumnArgList != nil || pl.Items == nil || len(pl.Items.Items) != 1 {
			return e
		}
		inner := pl.Items.Items[0]
		if ce, ok := inner.(*parser.ColumnExpr); ok {
			if ce.Alias != nil {
				return e
			}
			e = ce.Expr
			continue
		}
		e = inner
	}
}
