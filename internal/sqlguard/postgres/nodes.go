package pgguard

import (
	"fmt"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/sqlguard"
)

// relRole says how a relation is used, which selects the allowlist to apply.
type relRole int

const (
	roleSource relRole = iota
	roleMutationTarget
)

// visitCtx carries the state of one validation pass.
type visitCtx struct {
	mode   sqlguard.Mode
	pol    *policy.Policy
	tables map[policy.TableRef]struct{}
	// cteScopes is a stack of CTE names (with their output columns)
	// introduced by enclosing WITH clauses. An unqualified relation name that
	// matches one is a local relation.
	cteScopes []map[string]colset
	// relScopes is a stack of the relations visible to qualified column
	// references, one entry per query level.
	relScopes []*relScope
	// outCache memoizes inferred output columns per SELECT node.
	outCache map[*pg_query.SelectStmt]colset
}

func newVisitCtx(mode sqlguard.Mode, pol *policy.Policy) *visitCtx {
	return &visitCtx{mode: mode, pol: pol, tables: map[policy.TableRef]struct{}{}, outCache: map[*pg_query.SelectStmt]colset{}}
}

// allowedOperators is the set of builtin operator spellings accepted in
// A_Expr, SubLink and ORDER BY ... USING positions.
var allowedOperators = map[string]struct{}{
	"=": {}, "<>": {}, "!=": {}, "<": {}, ">": {}, "<=": {}, ">=": {},
	"+": {}, "-": {}, "*": {}, "/": {}, "%": {}, "^": {},
	"||": {}, "~": {}, "~*": {}, "!~": {}, "!~*": {},
	"~~": {}, "!~~": {}, "~~*": {}, "!~~*": {},
	"->": {}, "->>": {}, "#>": {}, "#>>": {}, "#-": {},
	"@>": {}, "<@": {}, "?": {}, "?|": {}, "?&": {}, "&&": {},
	"&": {}, "|": {}, "#": {}, "<<": {}, ">>": {}, "<<=": {}, ">>=": {},
	"@": {}, "|/": {}, "||/": {}, "@@": {}, "@?": {}, "@@@": {}, "-|-": {}, "<->": {}, "~=": {},
}

func nodeName(n *pg_query.Node) string {
	if n == nil || n.Node == nil {
		return "nil"
	}
	return strings.TrimPrefix(fmt.Sprintf("%T", n.Node), "*pg_query.Node_")
}

func unsupported(n *pg_query.Node) error {
	return sqlguard.Reject("unsupported syntax", nodeName(n))
}

// walkTop validates the top-level statement and classifies it.
func (v *visitCtx) walkTop(n *pg_query.Node) (sqlguard.StmtKind, error) {
	switch s := n.Node.(type) {
	case *pg_query.Node_SelectStmt:
		return sqlguard.KindSelect, v.walkSelect(s.SelectStmt)
	case *pg_query.Node_InsertStmt:
		if v.mode != sqlguard.ModeWrite {
			return "", sqlguard.Reject("INSERT is not allowed in read mode", "InsertStmt")
		}
		return sqlguard.KindInsert, v.walkInsert(s.InsertStmt)
	case *pg_query.Node_UpdateStmt:
		if v.mode != sqlguard.ModeWrite {
			return "", sqlguard.Reject("UPDATE is not allowed in read mode", "UpdateStmt")
		}
		return sqlguard.KindUpdate, v.walkUpdate(s.UpdateStmt)
	case *pg_query.Node_DeleteStmt:
		if v.mode != sqlguard.ModeWrite {
			return "", sqlguard.Reject("DELETE is not allowed in read mode", "DeleteStmt")
		}
		return sqlguard.KindDelete, v.walkDelete(s.DeleteStmt)
	}
	return "", v.rejectStatement(n)
}

// rejectStatement gives a stable message for statement kinds the parser
// accepts but the policy never does.
func (v *visitCtx) rejectStatement(n *pg_query.Node) error {
	switch n.Node.(type) {
	case *pg_query.Node_ExplainStmt:
		return sqlguard.Reject("EXPLAIN is not allowed; use the explain_query tool", "ExplainStmt")
	case *pg_query.Node_MergeStmt:
		return sqlguard.Reject("MERGE is not allowed", "MergeStmt")
	case *pg_query.Node_CopyStmt:
		return sqlguard.Reject("COPY is not allowed", "CopyStmt")
	case *pg_query.Node_VariableSetStmt:
		return sqlguard.Reject("SET is not allowed", "VariableSetStmt")
	case *pg_query.Node_VariableShowStmt:
		return sqlguard.Reject("SHOW is not allowed", "VariableShowStmt")
	case *pg_query.Node_TransactionStmt:
		return sqlguard.Reject("transaction control statements are not allowed; use the transaction tools", "TransactionStmt")
	case *pg_query.Node_TruncateStmt:
		return sqlguard.Reject("TRUNCATE is not allowed", "TruncateStmt")
	case *pg_query.Node_LockStmt:
		return sqlguard.Reject("LOCK is not allowed", "LockStmt")
	case *pg_query.Node_CallStmt:
		return sqlguard.Reject("CALL is not allowed", "CallStmt")
	case *pg_query.Node_DoStmt:
		return sqlguard.Reject("DO is not allowed", "DoStmt")
	case *pg_query.Node_PrepareStmt, *pg_query.Node_ExecuteStmt, *pg_query.Node_DeallocateStmt:
		return sqlguard.Reject("PREPARE/EXECUTE are not allowed", nodeName(n))
	case *pg_query.Node_ListenStmt, *pg_query.Node_NotifyStmt, *pg_query.Node_UnlistenStmt:
		return sqlguard.Reject("LISTEN/NOTIFY are not allowed", nodeName(n))
	case *pg_query.Node_GrantStmt, *pg_query.Node_GrantRoleStmt:
		return sqlguard.Reject("GRANT/REVOKE are not allowed", nodeName(n))
	case *pg_query.Node_VacuumStmt:
		return sqlguard.Reject("VACUUM/ANALYZE are not allowed", "VacuumStmt")
	case *pg_query.Node_CreateTableAsStmt:
		return sqlguard.Reject("CREATE TABLE AS / SELECT INTO is not allowed", "CreateTableAsStmt")
	}
	return sqlguard.Reject("statement kind is not allowed", nodeName(n))
}

// walk validates one generic child node. Every allowed case walks every child
// field of its struct explicitly; anything else is rejected by name.
func (v *visitCtx) walk(n *pg_query.Node) error {
	if n == nil || n.Node == nil {
		return nil
	}
	switch x := n.Node.(type) {
	case *pg_query.Node_SelectStmt:
		return v.walkSelect(x.SelectStmt)
	case *pg_query.Node_RangeVar:
		return v.walkRangeVar(x.RangeVar, roleSource)
	case *pg_query.Node_RangeSubselect:
		return v.walkRangeSubselect(x.RangeSubselect)
	case *pg_query.Node_JoinExpr:
		return v.walkJoin(x.JoinExpr)
	case *pg_query.Node_Alias:
		return v.walkAlias(x.Alias)
	case *pg_query.Node_ResTarget:
		return v.walkResTarget(x.ResTarget)
	case *pg_query.Node_ColumnRef:
		return v.walkColumnRef(x.ColumnRef)
	case *pg_query.Node_AStar:
		return nil
	case *pg_query.Node_AConst:
		return nil
	case *pg_query.Node_AExpr:
		return v.walkAExpr(x.AExpr)
	case *pg_query.Node_BoolExpr:
		if err := v.walk(x.BoolExpr.Xpr); err != nil {
			return err
		}
		return v.walkAll(x.BoolExpr.Args)
	case *pg_query.Node_NullTest:
		if err := v.walk(x.NullTest.Xpr); err != nil {
			return err
		}
		return v.walk(x.NullTest.Arg)
	case *pg_query.Node_BooleanTest:
		if err := v.walk(x.BooleanTest.Xpr); err != nil {
			return err
		}
		return v.walk(x.BooleanTest.Arg)
	case *pg_query.Node_CaseExpr:
		c := x.CaseExpr
		if err := v.walk(c.Xpr); err != nil {
			return err
		}
		if err := v.walk(c.Arg); err != nil {
			return err
		}
		if err := v.walkAll(c.Args); err != nil {
			return err
		}
		return v.walk(c.Defresult)
	case *pg_query.Node_CaseWhen:
		if err := v.walk(x.CaseWhen.Xpr); err != nil {
			return err
		}
		if err := v.walk(x.CaseWhen.Expr); err != nil {
			return err
		}
		return v.walk(x.CaseWhen.Result)
	case *pg_query.Node_CoalesceExpr:
		if err := v.walk(x.CoalesceExpr.Xpr); err != nil {
			return err
		}
		return v.walkAll(x.CoalesceExpr.Args)
	case *pg_query.Node_MinMaxExpr:
		if err := v.walk(x.MinMaxExpr.Xpr); err != nil {
			return err
		}
		return v.walkAll(x.MinMaxExpr.Args)
	case *pg_query.Node_SubLink:
		return v.walkSubLink(x.SubLink)
	case *pg_query.Node_AArrayExpr:
		return v.walkAll(x.AArrayExpr.Elements)
	case *pg_query.Node_AIndirection:
		return v.walkIndirection(x.AIndirection)
	case *pg_query.Node_AIndices:
		if err := v.walk(x.AIndices.Lidx); err != nil {
			return err
		}
		return v.walk(x.AIndices.Uidx)
	case *pg_query.Node_RowExpr:
		if err := v.walk(x.RowExpr.Xpr); err != nil {
			return err
		}
		if err := v.walkAll(x.RowExpr.Args); err != nil {
			return err
		}
		return v.walkAll(x.RowExpr.Colnames)
	case *pg_query.Node_SortBy:
		return v.walkSortBy(x.SortBy)
	case *pg_query.Node_WindowDef:
		return v.walkWindowDef(x.WindowDef)
	case *pg_query.Node_GroupingSet:
		return v.walkAll(x.GroupingSet.Content)
	case *pg_query.Node_NamedArgExpr:
		if err := v.walk(x.NamedArgExpr.Xpr); err != nil {
			return err
		}
		return v.walk(x.NamedArgExpr.Arg)
	case *pg_query.Node_SqlvalueFunction:
		return v.walkSQLValueFunction(x.SqlvalueFunction)
	case *pg_query.Node_List:
		return v.walkAll(x.List.Items)
	case *pg_query.Node_String_, *pg_query.Node_Integer, *pg_query.Node_Float, *pg_query.Node_Boolean, *pg_query.Node_BitString:
		return nil
	case *pg_query.Node_FuncCall:
		return v.walkFuncCall(x.FuncCall)
	case *pg_query.Node_TypeCast:
		if err := v.walk(x.TypeCast.Arg); err != nil {
			return err
		}
		return v.walkTypeName(x.TypeCast.TypeName)
	case *pg_query.Node_TypeName:
		return v.walkTypeName(x.TypeName)
	case *pg_query.Node_CommonTableExpr:
		return sqlguard.Reject("CTE outside a WITH clause", "CommonTableExpr")
	case *pg_query.Node_WithClause:
		return sqlguard.Reject("WITH clause in unexpected position", "WithClause")

	// Write-mode-only nodes reachable as generic children.
	case *pg_query.Node_InsertStmt, *pg_query.Node_UpdateStmt, *pg_query.Node_DeleteStmt:
		return sqlguard.Reject("data-modifying statement in unexpected position", nodeName(n))
	case *pg_query.Node_MultiAssignRef:
		if v.mode != sqlguard.ModeWrite {
			return unsupported(n)
		}
		return v.walk(x.MultiAssignRef.Source)
	case *pg_query.Node_SetToDefault:
		if v.mode != sqlguard.ModeWrite {
			return unsupported(n)
		}
		return v.walk(x.SetToDefault.Xpr)
	case *pg_query.Node_IndexElem:
		if v.mode != sqlguard.ModeWrite {
			return unsupported(n)
		}
		return v.walkIndexElem(x.IndexElem)
	case *pg_query.Node_InferClause, *pg_query.Node_OnConflictClause:
		return sqlguard.Reject("ON CONFLICT clause in unexpected position", nodeName(n))

	// Explicit rejections with clearer messages than the generic default.
	case *pg_query.Node_ParamRef:
		return sqlguard.Reject("bind parameters are not supported", "ParamRef")
	case *pg_query.Node_RangeFunction:
		return sqlguard.Reject("table functions are not allowed", rangeFunctionName(x.RangeFunction))
	case *pg_query.Node_RangeTableSample:
		return sqlguard.Reject("TABLESAMPLE is not allowed", "RangeTableSample")
	case *pg_query.Node_RangeTableFunc:
		return sqlguard.Reject("XMLTABLE is not allowed", "RangeTableFunc")
	case *pg_query.Node_XmlExpr, *pg_query.Node_XmlSerialize:
		return sqlguard.Reject("XML expressions are not allowed", nodeName(n))
	case *pg_query.Node_CollateClause:
		return sqlguard.Reject("COLLATE is not allowed", "CollateClause")
	case *pg_query.Node_LockingClause:
		return sqlguard.Reject("FOR UPDATE/SHARE is not allowed", "LockingClause")
	case *pg_query.Node_IntoClause:
		return sqlguard.Reject("SELECT INTO is not allowed", "IntoClause")
	case *pg_query.Node_JsonTable, *pg_query.Node_JsonObjectConstructor, *pg_query.Node_JsonArrayConstructor,
		*pg_query.Node_JsonArrayQueryConstructor, *pg_query.Node_JsonObjectAgg, *pg_query.Node_JsonArrayAgg,
		*pg_query.Node_JsonFuncExpr, *pg_query.Node_JsonParseExpr, *pg_query.Node_JsonScalarExpr,
		*pg_query.Node_JsonSerializeExpr, *pg_query.Node_JsonIsPredicate, *pg_query.Node_JsonValueExpr:
		return sqlguard.Reject("SQL/JSON constructor syntax is not allowed; use the json_* functions", nodeName(n))
	}
	return unsupported(n)
}

func (v *visitCtx) walkAll(nodes []*pg_query.Node) error {
	for _, n := range nodes {
		if err := v.walk(n); err != nil {
			return err
		}
	}
	return nil
}

func (v *visitCtx) walkSelect(s *pg_query.SelectStmt) error {
	if s == nil {
		return nil
	}
	if s.IntoClause != nil {
		return sqlguard.Reject("SELECT INTO is not allowed", "IntoClause")
	}
	if len(s.LockingClause) > 0 {
		return sqlguard.Reject("FOR UPDATE/SHARE is not allowed", "LockingClause")
	}
	if s.WithClause != nil {
		v.pushCTEScope()
		defer v.popCTEScope()
		if err := v.walkWith(s.WithClause); err != nil {
			return err
		}
	}
	scope := v.pushRelScope()
	defer v.popRelScope()
	for _, f := range s.FromClause {
		v.addFromItems(scope, f)
	}
	if err := v.walkAll(s.DistinctClause); err != nil {
		return err
	}
	if err := v.walkAll(s.TargetList); err != nil {
		return err
	}
	if err := v.walkAll(s.FromClause); err != nil {
		return err
	}
	if err := v.walk(s.WhereClause); err != nil {
		return err
	}
	if err := v.walkAll(s.GroupClause); err != nil {
		return err
	}
	if err := v.walk(s.HavingClause); err != nil {
		return err
	}
	if err := v.walkAll(s.WindowClause); err != nil {
		return err
	}
	if err := v.walkAll(s.ValuesLists); err != nil {
		return err
	}
	if err := v.walkAll(s.SortClause); err != nil {
		return err
	}
	if err := v.walk(s.LimitOffset); err != nil {
		return err
	}
	if err := v.walk(s.LimitCount); err != nil {
		return err
	}
	if err := v.walkSelect(s.Larg); err != nil {
		return err
	}
	return v.walkSelect(s.Rarg)
}

// walkWith validates the CTEs of a WITH clause. The caller has pushed a CTE
// scope. Non-recursive CTE names become visible only to later CTEs and the
// main query, as in Postgres; RECURSIVE makes every name visible everywhere,
// so their column sets are registered up front.
func (v *visitCtx) walkWith(w *pg_query.WithClause) error {
	for _, n := range w.Ctes {
		if _, ok := n.Node.(*pg_query.Node_CommonTableExpr); !ok {
			return unsupported(n)
		}
	}
	if w.Recursive {
		v.analyzeWith(w)
	}
	for _, n := range w.Ctes {
		cte := n.Node.(*pg_query.Node_CommonTableExpr).CommonTableExpr
		if err := v.walkCTE(cte); err != nil {
			return err
		}
		if !w.Recursive {
			v.addCTE(cte.Ctename, v.cteCols(cte))
		}
	}
	return nil
}

func (v *visitCtx) walkCTE(c *pg_query.CommonTableExpr) error {
	if c.SearchClause != nil || c.CycleClause != nil {
		return sqlguard.Reject("CTE SEARCH/CYCLE clauses are not allowed", "CommonTableExpr")
	}
	if err := v.walkAll(c.Aliascolnames); err != nil {
		return err
	}
	if c.Ctequery == nil || c.Ctequery.Node == nil {
		return sqlguard.Reject("empty CTE body", c.Ctename)
	}
	switch q := c.Ctequery.Node.(type) {
	case *pg_query.Node_SelectStmt:
		return v.walkSelect(q.SelectStmt)
	case *pg_query.Node_InsertStmt:
		if v.mode != sqlguard.ModeWrite {
			return sqlguard.Reject("data-modifying CTE is not allowed in read mode", "InsertStmt")
		}
		return v.walkInsert(q.InsertStmt)
	case *pg_query.Node_UpdateStmt:
		if v.mode != sqlguard.ModeWrite {
			return sqlguard.Reject("data-modifying CTE is not allowed in read mode", "UpdateStmt")
		}
		return v.walkUpdate(q.UpdateStmt)
	case *pg_query.Node_DeleteStmt:
		if v.mode != sqlguard.ModeWrite {
			return sqlguard.Reject("data-modifying CTE is not allowed in read mode", "DeleteStmt")
		}
		return v.walkDelete(q.DeleteStmt)
	}
	return unsupported(c.Ctequery)
}

// walkRangeVar resolves a relation against the CTE scopes and the policy and
// rewrites it to its fully qualified form.
func (v *visitCtx) walkRangeVar(rv *pg_query.RangeVar, role relRole) error {
	if rv == nil {
		return nil
	}
	if rv.Catalogname != "" {
		return sqlguard.Reject("catalog-qualified table names are not allowed", rv.Catalogname+"."+rv.Schemaname+"."+rv.Relname)
	}
	if rv.Relname == "" {
		return sqlguard.Reject("empty relation name", "RangeVar")
	}
	if err := v.walkAlias(rv.Alias); err != nil {
		return err
	}
	// An unqualified name that matches an enclosing CTE is a local relation.
	// Mutation targets are always real tables in Postgres, never CTEs.
	if _, ok := v.cteInScope(rv.Relname); ok && rv.Schemaname == "" && role == roleSource {
		return nil
	}
	ref := policy.TableRef{Schema: rv.Schemaname, Name: rv.Relname}
	if ref.Schema == "" {
		ref.Schema = v.pol.DefaultSchema
	}
	switch role {
	case roleMutationTarget:
		if !v.pol.CanMutate(ref) {
			return sqlguard.Reject("table is not in the write allowlist", ref.String())
		}
	case roleSource:
		if v.mode == sqlguard.ModeWrite {
			if !v.pol.CanSelectInWrite(ref) {
				return sqlguard.Reject("table is not in the read or write allowlist", ref.String())
			}
		} else if !v.pol.CanRead(ref) {
			return sqlguard.Reject("table is not in the read allowlist", ref.String())
		}
	}
	rv.Schemaname = ref.Schema
	v.tables[ref] = struct{}{}
	return nil
}

func (v *visitCtx) walkRangeSubselect(r *pg_query.RangeSubselect) error {
	if err := v.walkAlias(r.Alias); err != nil {
		return err
	}
	if r.Subquery == nil || r.Subquery.Node == nil {
		return sqlguard.Reject("empty subquery", "RangeSubselect")
	}
	if _, ok := r.Subquery.Node.(*pg_query.Node_SelectStmt); !ok {
		return unsupported(r.Subquery)
	}
	return v.walk(r.Subquery)
}

func (v *visitCtx) walkJoin(j *pg_query.JoinExpr) error {
	if err := v.walk(j.Larg); err != nil {
		return err
	}
	if err := v.walk(j.Rarg); err != nil {
		return err
	}
	if err := v.walkAll(j.UsingClause); err != nil {
		return err
	}
	if err := v.walkAlias(j.JoinUsingAlias); err != nil {
		return err
	}
	if err := v.walk(j.Quals); err != nil {
		return err
	}
	return v.walkAlias(j.Alias)
}

func (v *visitCtx) walkAlias(a *pg_query.Alias) error {
	if a == nil {
		return nil
	}
	return v.walkAll(a.Colnames)
}

func (v *visitCtx) walkResTarget(r *pg_query.ResTarget) error {
	if err := v.walkAll(r.Indirection); err != nil {
		return err
	}
	return v.walk(r.Val)
}

func (v *visitCtx) walkAExpr(a *pg_query.A_Expr) error {
	switch a.Kind {
	case pg_query.A_Expr_Kind_AEXPR_BETWEEN, pg_query.A_Expr_Kind_AEXPR_NOT_BETWEEN,
		pg_query.A_Expr_Kind_AEXPR_BETWEEN_SYM, pg_query.A_Expr_Kind_AEXPR_NOT_BETWEEN_SYM:
		// Name holds the BETWEEN keyword spelling, not an operator.
	case pg_query.A_Expr_Kind_AEXPR_OP, pg_query.A_Expr_Kind_AEXPR_OP_ANY, pg_query.A_Expr_Kind_AEXPR_OP_ALL,
		pg_query.A_Expr_Kind_AEXPR_DISTINCT, pg_query.A_Expr_Kind_AEXPR_NOT_DISTINCT,
		pg_query.A_Expr_Kind_AEXPR_NULLIF, pg_query.A_Expr_Kind_AEXPR_IN,
		pg_query.A_Expr_Kind_AEXPR_LIKE, pg_query.A_Expr_Kind_AEXPR_ILIKE, pg_query.A_Expr_Kind_AEXPR_SIMILAR:
		if err := v.checkOperator(a.Name); err != nil {
			return err
		}
	default:
		return sqlguard.Reject("unsupported expression kind", a.Kind.String())
	}
	if err := v.walk(a.Lexpr); err != nil {
		return err
	}
	return v.walk(a.Rexpr)
}

// checkOperator accepts a single unqualified builtin operator. OPERATOR(schema.op)
// arrives as a two-element name and is rejected.
func (v *visitCtx) checkOperator(name []*pg_query.Node) error {
	if len(name) == 0 {
		return nil
	}
	if len(name) != 1 {
		return sqlguard.Reject("schema-qualified operators are not allowed", stringList(name))
	}
	op, ok := name[0].Node.(*pg_query.Node_String_)
	if !ok {
		return unsupported(name[0])
	}
	if _, allowed := allowedOperators[op.String_.Sval]; !allowed {
		return sqlguard.Reject("operator is not allowed", op.String_.Sval)
	}
	return nil
}

func (v *visitCtx) walkSubLink(s *pg_query.SubLink) error {
	if err := v.walk(s.Xpr); err != nil {
		return err
	}
	if err := v.checkOperator(s.OperName); err != nil {
		return err
	}
	if err := v.walk(s.Testexpr); err != nil {
		return err
	}
	if s.Subselect == nil || s.Subselect.Node == nil {
		return sqlguard.Reject("empty subquery", "SubLink")
	}
	if _, ok := s.Subselect.Node.(*pg_query.Node_SelectStmt); !ok {
		return unsupported(s.Subselect)
	}
	return v.walk(s.Subselect)
}

func (v *visitCtx) walkSortBy(s *pg_query.SortBy) error {
	if err := v.checkOperator(s.UseOp); err != nil {
		return err
	}
	return v.walk(s.Node)
}

func (v *visitCtx) walkWindowDef(w *pg_query.WindowDef) error {
	if w == nil {
		return nil
	}
	if err := v.walkAll(w.PartitionClause); err != nil {
		return err
	}
	if err := v.walkAll(w.OrderClause); err != nil {
		return err
	}
	if err := v.walk(w.StartOffset); err != nil {
		return err
	}
	return v.walk(w.EndOffset)
}

// walkSQLValueFunction allows the date/time keywords and rejects the
// user/role/schema introspection keywords.
func (v *visitCtx) walkSQLValueFunction(f *pg_query.SQLValueFunction) error {
	if err := v.walk(f.Xpr); err != nil {
		return err
	}
	switch f.Op {
	case pg_query.SQLValueFunctionOp_SVFOP_CURRENT_DATE,
		pg_query.SQLValueFunctionOp_SVFOP_CURRENT_TIME,
		pg_query.SQLValueFunctionOp_SVFOP_CURRENT_TIME_N,
		pg_query.SQLValueFunctionOp_SVFOP_CURRENT_TIMESTAMP,
		pg_query.SQLValueFunctionOp_SVFOP_CURRENT_TIMESTAMP_N,
		pg_query.SQLValueFunctionOp_SVFOP_LOCALTIME,
		pg_query.SQLValueFunctionOp_SVFOP_LOCALTIME_N,
		pg_query.SQLValueFunctionOp_SVFOP_LOCALTIMESTAMP,
		pg_query.SQLValueFunctionOp_SVFOP_LOCALTIMESTAMP_N:
		return nil
	}
	return sqlguard.Reject("session introspection keyword is not allowed", strings.TrimPrefix(f.Op.String(), "SVFOP_"))
}

// walkFuncCall accepts an unqualified or pg_catalog-qualified function whose
// exact (already case-folded by the parser) name is in the allowlist.
func (v *visitCtx) walkFuncCall(f *pg_query.FuncCall) error {
	var name string
	switch len(f.Funcname) {
	case 1:
		name = stringValue(f.Funcname[0])
	case 2:
		if stringValue(f.Funcname[0]) != "pg_catalog" {
			return sqlguard.Reject("schema-qualified functions are not allowed", stringList(f.Funcname))
		}
		name = stringValue(f.Funcname[1])
	default:
		return sqlguard.Reject("schema-qualified functions are not allowed", stringList(f.Funcname))
	}
	// A quoted mixed-case name could resolve to a user-defined function whose
	// lowercased spelling happens to be allowlisted; require the exact form.
	if name == "" || name != strings.ToLower(name) || !policy.AllowedFunction(policy.Postgres, name) {
		return sqlguard.Reject("function is not allowed", stringList(f.Funcname))
	}
	if err := v.walkAll(f.Args); err != nil {
		return err
	}
	if err := v.walkAll(f.AggOrder); err != nil {
		return err
	}
	if err := v.walk(f.AggFilter); err != nil {
		return err
	}
	return v.walkWindowDef(f.Over)
}

// walkTypeName accepts an unqualified or pg_catalog-qualified builtin type
// from the cast allowlist, optionally with typmods and array bounds.
func (v *visitCtx) walkTypeName(t *pg_query.TypeName) error {
	if t == nil {
		return nil
	}
	if t.Setof {
		return sqlguard.Reject("SETOF types are not allowed", stringList(t.Names))
	}
	if t.PctType {
		return sqlguard.Reject("%TYPE references are not allowed", stringList(t.Names))
	}
	var name string
	switch len(t.Names) {
	case 1:
		name = stringValue(t.Names[0])
	case 2:
		if stringValue(t.Names[0]) != "pg_catalog" {
			return sqlguard.Reject("schema-qualified types are not allowed", stringList(t.Names))
		}
		name = stringValue(t.Names[1])
	default:
		return sqlguard.Reject("schema-qualified types are not allowed", stringList(t.Names))
	}
	if name == "" || name != strings.ToLower(name) || !policy.AllowedCastType(policy.Postgres, name) {
		return sqlguard.Reject("cast type is not allowed", stringList(t.Names))
	}
	if err := v.walkAll(t.Typmods); err != nil {
		return err
	}
	return v.walkAll(t.ArrayBounds)
}

func (v *visitCtx) walkInsert(s *pg_query.InsertStmt) error {
	if s.WithClause != nil {
		v.pushCTEScope()
		defer v.popCTEScope()
		if err := v.walkWith(s.WithClause); err != nil {
			return err
		}
	}
	if s.Relation == nil {
		return sqlguard.Reject("INSERT without a target table", "InsertStmt")
	}
	if err := v.walkRangeVar(s.Relation, roleMutationTarget); err != nil {
		return err
	}
	scope := v.pushRelScope()
	defer v.popRelScope()
	target := v.baseTableItem(s.Relation)
	scope.items = append(scope.items, target, relItem{name: "excluded", aliased: true, cols: target.cols})
	if err := v.walkAll(s.Cols); err != nil {
		return err
	}
	if s.SelectStmt != nil {
		if _, ok := s.SelectStmt.Node.(*pg_query.Node_SelectStmt); !ok {
			return unsupported(s.SelectStmt)
		}
		if err := v.walk(s.SelectStmt); err != nil {
			return err
		}
	}
	if err := v.walkOnConflict(s.OnConflictClause); err != nil {
		return err
	}
	return v.walkAll(s.ReturningList)
}

func (v *visitCtx) walkOnConflict(c *pg_query.OnConflictClause) error {
	if c == nil {
		return nil
	}
	switch c.Action {
	case pg_query.OnConflictAction_ONCONFLICT_NOTHING, pg_query.OnConflictAction_ONCONFLICT_UPDATE:
	default:
		return sqlguard.Reject("unsupported ON CONFLICT action", c.Action.String())
	}
	if c.Infer != nil {
		if err := v.walkAll(c.Infer.IndexElems); err != nil {
			return err
		}
		if err := v.walk(c.Infer.WhereClause); err != nil {
			return err
		}
	}
	if err := v.walkAll(c.TargetList); err != nil {
		return err
	}
	return v.walk(c.WhereClause)
}

func (v *visitCtx) walkIndexElem(e *pg_query.IndexElem) error {
	if len(e.Collation) > 0 {
		return sqlguard.Reject("COLLATE is not allowed", "IndexElem")
	}
	if len(e.Opclass) > 0 || len(e.Opclassopts) > 0 {
		return sqlguard.Reject("operator classes are not allowed", "IndexElem")
	}
	return v.walk(e.Expr)
}

func (v *visitCtx) walkUpdate(s *pg_query.UpdateStmt) error {
	if s.WithClause != nil {
		v.pushCTEScope()
		defer v.popCTEScope()
		if err := v.walkWith(s.WithClause); err != nil {
			return err
		}
	}
	if s.Relation == nil {
		return sqlguard.Reject("UPDATE without a target table", "UpdateStmt")
	}
	if err := v.walkRangeVar(s.Relation, roleMutationTarget); err != nil {
		return err
	}
	scope := v.pushRelScope()
	defer v.popRelScope()
	scope.items = append(scope.items, v.baseTableItem(s.Relation))
	for _, f := range s.FromClause {
		v.addFromItems(scope, f)
	}
	if err := v.walkAll(s.TargetList); err != nil {
		return err
	}
	if err := v.walk(s.WhereClause); err != nil {
		return err
	}
	if err := v.walkAll(s.FromClause); err != nil {
		return err
	}
	return v.walkAll(s.ReturningList)
}

func (v *visitCtx) walkDelete(s *pg_query.DeleteStmt) error {
	if s.WithClause != nil {
		v.pushCTEScope()
		defer v.popCTEScope()
		if err := v.walkWith(s.WithClause); err != nil {
			return err
		}
	}
	if s.Relation == nil {
		return sqlguard.Reject("DELETE without a target table", "DeleteStmt")
	}
	if err := v.walkRangeVar(s.Relation, roleMutationTarget); err != nil {
		return err
	}
	scope := v.pushRelScope()
	defer v.popRelScope()
	scope.items = append(scope.items, v.baseTableItem(s.Relation))
	for _, u := range s.UsingClause {
		v.addFromItems(scope, u)
	}
	if err := v.walkAll(s.UsingClause); err != nil {
		return err
	}
	if err := v.walk(s.WhereClause); err != nil {
		return err
	}
	return v.walkAll(s.ReturningList)
}

func stringValue(n *pg_query.Node) string {
	if n == nil {
		return ""
	}
	if s, ok := n.Node.(*pg_query.Node_String_); ok {
		return s.String_.Sval
	}
	return ""
}

func stringList(nodes []*pg_query.Node) string {
	parts := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if s := stringValue(n); s != "" {
			parts = append(parts, s)
		} else {
			parts = append(parts, nodeName(n))
		}
	}
	return strings.Join(parts, ".")
}

// rangeFunctionName extracts the first function name from a RangeFunction for
// the rejection message; the structure is a list of [FuncCall, colnames] lists.
func rangeFunctionName(r *pg_query.RangeFunction) string {
	for _, item := range r.Functions {
		l, ok := item.Node.(*pg_query.Node_List)
		if !ok {
			continue
		}
		for _, inner := range l.List.Items {
			if fc, ok := inner.Node.(*pg_query.Node_FuncCall); ok {
				return stringList(fc.FuncCall.Funcname)
			}
		}
	}
	return "RangeFunction"
}
