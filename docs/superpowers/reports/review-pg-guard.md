# Postgres guard adversarial review (branch `review-pg-guard`)

Scope: `internal/sqlguard/postgres/` under the policy R = {allowed_orders,
allowed_customers}, W = {allowed_audit}, default schema `public`, against the
PG17 e2e stack. Probes went through `cmd/sqlguard-check` first and every
accepted-but-suspicious statement was then executed against the live database
inside `BEGIN READ ONLY; SET LOCAL search_path = public` to confirm what
Postgres actually does with the canonical SQL.

Totals: 437 statement probes (327 read mode, 110 write mode) plus 12 byte-level
probes driven from Go. Four findings, all fixed; `make e2e-pg` is green.

## Findings and fixes

### 1. Functional column notation calls non-allowlisted functions (real bypass, fixed)

Postgres resolves `rel.name` as the column `name` of `rel` when one exists and
otherwise as the function call `name(rel)` passing the whole row. The same
fallback applies to `(expr).name`. The guard walked `ColumnRef` fields as plain
strings, so these executed without touching the function allowlist:

| Statement | Live result |
|---|---|
| `SELECT o.pg_column_size FROM allowed_orders o` | `56` |
| `SELECT o.to_json FROM allowed_orders o` | full row as JSON |
| `SELECT o.json_agg FROM allowed_orders o` | every row as a JSON array (an aggregate) |
| `SELECT o.record_out FROM allowed_orders o` | row text |
| `SELECT x.pg_typeof FROM (SELECT 1 AS a) x` | `record` |
| `SELECT (o.customer_id).pg_typeof FROM allowed_orders o` | `integer` |
| `SELECT (ROW(1,2)).pg_typeof` | `record` |
| `SELECT o.leak FROM allowed_orders o` with `CREATE FUNCTION leak(allowed_orders) RETURNS text AS $$ SELECT secret FROM forbidden_secrets LIMIT 1 $$` (created and rolled back in one transaction) | `hunter2` |

Any function whose single parameter is the row type of an allowlisted table,
`record`, `any` or `anyelement` is reachable this way, including user-defined
`SECURITY DEFINER` functions and every aggregate over such a type. Builtins like
`pg_sleep(double precision)` do not match a composite argument, which is the only
reason the existing corpus did not catch it. The same path works in write mode
through `RETURNING`, `SET`, `WHERE`, `USING`, `ON CONFLICT ... excluded.name`
and data-modifying CTEs.

Fix (`internal/sqlguard/postgres/columns.go`, wired in `nodes.go`): the guard
now resolves every qualified column reference itself and rejects anything that
does not resolve to a real column.

- Base-table columns come from a catalog snapshot (`policy.Policy.SetColumns` /
  `Columns`). The Postgres backend loads it at boot and on every `/readyz`
  probe (`RefreshColumns`), so a database that was unreachable at boot or a
  schema change is picked up without a restart. With no snapshot, qualified
  references to base tables are rejected with a message that says to use the
  unqualified name; unqualified names are never function calls in Postgres.
- Derived tables, VALUES lists, set operations, joins (including USING/NATURAL
  merge order and join alias column lists), CTEs (including data-modifying
  CTEs via their RETURNING list) get their output column names inferred the
  same way Postgres's `FigureColname` does, so `sub.amount`, `v.column1`,
  `x."?column?"`, `x.coalesce`, `paid.status` and so on keep working.
- Scopes are tracked per query level, so correlated subqueries, LATERAL items,
  UPDATE/DELETE targets with FROM/USING, INSERT targets and `excluded` resolve
  like they do in Postgres.
- `(expr).field` is allowed only when `expr` is a whole-row reference to a
  relation in scope and `field` is one of its columns; field access on any
  other expression, or on a bare name that is also a column somewhere in
  scope, is rejected.
- Three-part `schema.table.col` resolves only against an unaliased base table
  of that schema and name; four-part references are rejected.
- `cmd/sqlguard-check` takes the snapshot via `--columns 't=c1,c2;t2=c1'`.

Coverage: `TestPostgresColumnNotation` and `TestPostgresColumnNotationWrite`
in `e2e/postgres_adversarial_test.go` install a `leak_via_row(allowed_orders)`
fixture (also added to `e2e/postgres/init.sql`), prove it leaks outside the
guard, then assert 24 rejections and 21 accepted legitimate shapes across both
modes. Eight cases were also added to `bypassCorpusPostgres` and
`bypassCorpusWritePostgres`.

### 2. NUL byte truncates the statement inside the C parser (fixed)

`SELECT * FROM allowed_orders\x00, forbidden_secrets` reached the parser as
`SELECT * FROM allowed_orders`, was accepted, and executed the truncated
canonical form. Because the canonical SQL is what runs, this fails safe, but it
silently drops input. The guard now rejects any statement containing a NUL byte
before parsing. Covered by `TestPostgresReadInputLimits` and a corpus entry.

### 3. Oversized statements spend seconds in the deparser (fixed)

libpg_query's deparser is superlinear in statement size: a 1 MiB target list
took 42 s inside `Check`, 256 KiB took 3.5 s. There was no input bound anywhere
in the server, so a client could pin CPU. The guard now refuses raw input over
64 KiB (which takes about 0.4 s) before parsing. 5,000 nested parentheses and
2,000 nested sub-selects were already rejected by the parser and protobuf depth
limits without crashing. Covered by `TestPostgresReadInputLimits`.

### 4. `pg_typeof` and `txid_current` in the allowlist (fixed)

Spec §5 rule 4 forbids every `pg_*` function. `txid_current()` succeeded inside
`BEGIN READ ONLY` and assigns a transaction id, which is a small state change.
`pg_typeof(1) = 'x'` was checked as a possible type-existence oracle; it is not
(the literal coerces to `oid`, not `regtype`), but the function is still out of
policy. Both removed; corpus entries added.

## Confirmed to hold

- Table reach: every FROM/JOIN/subquery/CTE/LATERAL/VALUES/ANY/ALL/EXISTS/
  ARRAY/LIMIT/OFFSET/ORDER BY/GROUP BY/HAVING/GROUPING SETS/window/FILTER/
  WITHIN GROUP/CASE/COALESCE/NULLIF/ROW/array-subscript position that can hold
  a `forbidden_secrets` reference is rejected in both modes, including CTE
  shadowing an allowlisted name with a forbidden body, RECURSIVE bodies, WITH
  inside subqueries and set-operation arms, `TABLE forbidden_secrets`,
  `IN (TABLE ...)`, aliasing a forbidden table as an allowed name, quoted and
  `U&` spellings, mixed case, over-length identifiers (truncated identically
  by parser and server) and catalog-qualified names.
- Write mode: mutation targets outside W, sources outside R ∪ W in `INSERT ...
  SELECT`, `UPDATE ... FROM`, `DELETE ... USING`, `ON CONFLICT` index
  expressions and WHERE, `DO UPDATE SET`, `RETURNING`, `SET (a, b) = (SELECT
  ...)`, data-modifying CTEs targeting read-only tables, and CTE names that
  shadow a write target (the target is always the real table, as in Postgres)
  are all rejected. `ON CONFLICT (col COLLATE "C")` and opclasses are rejected.
- Functions and types: `pg_catalog."pg_sleep"`, `"PG_SLEEP"`, `public.lower`,
  `system_user`, `current_schemas`, `version`, `to_regclass`, `overlay`,
  `normalize`, `IS NORMALIZED`, `COLLATION FOR`, `generate_series` in a target
  list; casts to `regclass`, `regtype`, `oid`, `xid`, `pg_lsn`, `xml`, `bit`,
  `tsvector`, `tsquery`, `money`, a table's composite type, and quoted
  mixed-case type names.
- Statement kinds: every DDL/utility statement probed (CLUSTER, REINDEX,
  REFRESH, SECURITY LABEL, COMMENT, CHECKPOINT, DISCARD, LOAD, IMPORT FOREIGN
  SCHEMA, CREATE FUNCTION, DECLARE/FETCH, ALTER SYSTEM, MERGE, COPY both ways,
  GRANT, transaction control, EXPLAIN ANALYZE) is rejected by name. `FOR
  UPDATE/SHARE` is rejected at every nesting level; `SELECT INTO`, `CREATE
  TABLE AS`, `CREATE MATERIALIZED VIEW`, `TABLESAMPLE`, `ROWS FROM`, `WITH
  ORDINALITY`, XML and SQL/JSON constructors, `WHERE CURRENT OF`, `$1`, and
  `OPERATOR(schema.op)` are rejected.
- Trailing content: `SELECT 1;;`, `SELECT 1; SELECT 2`, and comments after the
  terminator are rejected; comments elsewhere never survive deparse.
- Deparse round-trips checked live for equality of results: `substring(x
  similar p escape e)` becomes `SUBSTRING(x FROM p FOR e)` (same function),
  `LIKE ... ESCAPE` becomes `pg_catalog.like_escape`, arithmetic and boolean
  precedence, set-operation nesting, `AT TIME ZONE`, interval typmods, dollar
  and Unicode-escaped strings, `E''` strings with backslashes. `(ARRAY[o])[1].f`
  deparses to invalid SQL and is caught by the canonical re-validation.
- Invalid UTF-8 is rejected by the parser; CR/LF comments and form feeds parse
  normally.

## Still risky (not fixed)

- Column snapshot drift. If a column is dropped after the last `/readyz`
  refresh and a function with that name takes the row type, `rel.col` would
  reach it until the next probe. Refreshing on every probe narrows the window;
  refreshing on every `Check` would close it at the cost of a catalog query per
  statement.
- Operators are matched by spelling only. A user-defined operator with a
  builtin spelling (for example `+` on a custom type) in the default schema is
  callable. Same for user-defined functions that overload an allowlisted name
  with a signature `pg_catalog` lacks (for example `public.lower(int)`); the
  session `search_path` puts `pg_catalog` first, so the builtin wins whenever
  both match.
- Read mode still reveals `tableoid`, `xmin`, `ctid` through unqualified
  references, and `ON CONFLICT ON CONSTRAINT name` reveals whether a constraint
  exists on the write target. Both are limited to allowlisted tables.
- The `excluded` pseudo-relation and UPDATE targets are visible to the guard's
  resolver in slightly more positions than Postgres allows; the extra
  positions error in Postgres, so this only affects error messages.
- Composite-typed column field access `(col).field` and `col.field` on a
  composite column is rejected outright, since the guard has no type
  information for columns.
- The 64 KiB input cap is a heuristic against deparser cost; a 60 KiB
  statement still costs ~0.4 s of CPU per call.
- Error text from Postgres is returned to the caller unchanged; nothing in
  this review found it leaking data from non-allowlisted tables, but it is a
  channel worth keeping in mind for the server review.

## Probe ledger

Results are from the final build with the column snapshot for the three
allowlisted tables. "accepted" means the guard produced canonical SQL; each
accepted statement in the first section was executed live and checked.

### Read mode

| Probe | Result |
|---|---|
| `SELECT * FROM allowed_orders, forbidden_secrets AS allowed_customers` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM "Public"."allowed_orders"` | rejected: table is not in the read allowlist (Public.allowed_orders) |
| `SELECT * FROM U&"forbidden_secrets"` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM U&"forbidden\005Fsecrets"` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM "forbidden_secrets" f` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM public."forbidden_secrets"` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM public . forbidden_secrets` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM app.public.forbidden_secrets` | rejected: catalog-qualified table names are not allowed (app.public.forbidden_secrets) |
| `SELECT * FROM FORBIDDEN_SECRETS` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM "FORBIDDEN_SECRETS"` | rejected: table is not in the read allowlist (public.FORBIDDEN_SECRETS) |
| `SELECT * FROM forbidden_secrets_______________________________________________________________________________xx` | rejected: table is not in the read allowlist (public.forbidden_secrets______________________________________________) |
| `SELECT * FROM "allowed_orders___________________________________________________________________xx"` | rejected: table is not in the read allowlist (public.allowed_orders_________________________________________________) |
| `SELECT * FROM allowed_orders TABLESAMPLE BERNOULLI (1) REPEATABLE (1)` | rejected: TABLESAMPLE is not allowed (RangeTableSample) |
| `TABLE forbidden_secrets` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM ROWS FROM (generate_series(1,2), unnest(array[1]))` | rejected: table functions are not allowed (generate_series) |
| `SELECT * FROM unnest(array[1,2])` | rejected: table functions are not allowed (unnest) |
| `SELECT unnest(array[1,2])` | accepted |
| `SELECT * FROM allowed_orders CROSS JOIN LATERAL unnest(array[id])` | rejected: table functions are not allowed (unnest) |
| `SELECT * FROM allowed_orders WHERE id IN (TABLE forbidden_secrets)` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM allowed_orders WHERE EXISTS (TABLE forbidden_secrets)` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT ARRAY(SELECT secret FROM forbidden_secrets)` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT (SELECT secret FROM forbidden_secrets LIMIT 1) = ALL (SELECT 'x')` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM allowed_orders LIMIT (SELECT count(*) FROM forbidden_secrets)` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM allowed_orders OFFSET (SELECT count(*) FROM forbidden_secrets)` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM allowed_orders ORDER BY (SELECT secret FROM forbidden_secrets)` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT count(*) FROM allowed_orders GROUP BY (SELECT secret FROM forbidden_secrets)` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT count(*) FROM allowed_orders HAVING count(*) > (SELECT count(*) FROM forbidden_secrets)` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT count(*) FROM allowed_orders GROUP BY GROUPING SETS ((SELECT secret FROM forbidden_secrets), ())` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT sum(id) OVER (PARTITION BY (SELECT secret FROM forbidden_secrets)) FROM allowed_orders` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT sum(id) OVER (ORDER BY id ROWS BETWEEN (SELECT count(*) FROM forbidden_secrets) PRECEDING AND CURRENT ROW) FROM allowed_orders` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT sum(id) OVER w FROM allowed_orders WINDOW w AS (ORDER BY (SELECT secret FROM forbidden_secrets))` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT array_agg(id ORDER BY (SELECT secret FROM forbidden_secrets)) FROM allowed_orders` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT count(*) FILTER (WHERE EXISTS (SELECT 1 FROM forbidden_secrets)) FROM allowed_orders` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT id FROM allowed_orders ORDER BY id FETCH FIRST (SELECT count(*) FROM forbidden_secrets) ROWS WITH TIES` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT CASE WHEN (SELECT true FROM forbidden_secrets) THEN 1 END` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT coalesce((SELECT secret FROM forbidden_secrets), 'x')` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT greatest((SELECT secret FROM forbidden_secrets), 'x')` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT nullif((SELECT secret FROM forbidden_secrets), 'x')` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT ROW((SELECT secret FROM forbidden_secrets))` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT ARRAY[(SELECT secret FROM forbidden_secrets)]` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT (ARRAY[1])[(SELECT id FROM forbidden_secrets)]` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT 1 WHERE (SELECT secret FROM forbidden_secrets) IS NOT NULL` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT 1 WHERE (SELECT true FROM forbidden_secrets) IS TRUE` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT 1 WHERE (SELECT id FROM forbidden_secrets) BETWEEN 1 AND 2` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT 1 WHERE (SELECT id FROM forbidden_secrets) IS DISTINCT FROM 2` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT 1 WHERE 1 IN ((SELECT id FROM forbidden_secrets), 2)` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT lower((SELECT secret FROM forbidden_secrets))` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT lower(x => (SELECT secret FROM forbidden_secrets))` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT ('x'::text \|\| (SELECT secret FROM forbidden_secrets))::text` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM (SELECT * FROM forbidden_secrets) s` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM allowed_orders o JOIN (SELECT * FROM forbidden_secrets) s ON true` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM allowed_orders o NATURAL JOIN forbidden_secrets` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM allowed_orders o FULL JOIN forbidden_secrets USING (id) AS j` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM (allowed_orders CROSS JOIN forbidden_secrets) AS j` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `WITH x AS (SELECT * FROM forbidden_secrets) SELECT 1` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `WITH x AS (SELECT 1) SELECT * FROM x, forbidden_secrets` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `WITH allowed_orders AS (SELECT * FROM forbidden_secrets) SELECT * FROM allowed_orders` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `WITH x AS (SELECT 1 AS id), y AS (SELECT * FROM x, forbidden_secrets) SELECT * FROM y` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `WITH RECURSIVE x AS (SELECT 1 UNION SELECT * FROM forbidden_secrets) SELECT * FROM x` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `WITH x AS (SELECT 1 AS id) SELECT * FROM (WITH y AS (SELECT * FROM forbidden_secrets) SELECT * FROM y) s` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT (WITH y AS (SELECT * FROM forbidden_secrets) SELECT count(*) FROM y)` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `WITH x AS MATERIALIZED (SELECT * FROM forbidden_secrets) SELECT * FROM x` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `WITH x AS (SELECT 1) SELECT * FROM x UNION SELECT * FROM forbidden_secrets` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `(SELECT 1) UNION (WITH x AS (SELECT * FROM forbidden_secrets) SELECT count(*) FROM x)` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT 1 EXCEPT SELECT id FROM forbidden_secrets` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT 1 INTERSECT ALL (SELECT id FROM forbidden_secrets)` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `VALUES ((SELECT secret FROM forbidden_secrets))` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM (VALUES ((SELECT secret FROM forbidden_secrets))) v` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM allowed_orders WHERE id = ANY (ARRAY(SELECT id FROM forbidden_secrets))` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM allowed_orders WHERE id = SOME (SELECT id FROM forbidden_secrets)` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM allowed_orders WHERE id < ALL (SELECT id FROM forbidden_secrets)` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT * FROM allowed_orders WHERE (id) OPERATOR(pg_catalog.=) ANY (SELECT id FROM forbidden_secrets)` | rejected: schema-qualified operators are not allowed (pg_catalog.=) |
| `SELECT * FROM allowed_orders WHERE ROW(id) = (SELECT id FROM forbidden_secrets)` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT pg_catalog.pg_sleep(1)` | rejected: function is not allowed (pg_catalog.pg_sleep) |
| `SELECT "pg_catalog".pg_sleep(1)` | rejected: function is not allowed (pg_catalog.pg_sleep) |
| `SELECT "PG_CATALOG".lower('x')` | rejected: schema-qualified functions are not allowed (PG_CATALOG.lower) |
| `SELECT PG_SLEEP(1)` | rejected: function is not allowed (pg_sleep) |
| `SELECT "pg_sleep"(1)` | rejected: function is not allowed (pg_sleep) |
| `SELECT pg_typeof(1)` | rejected: function is not allowed (pg_typeof) |
| `SELECT pg_typeof(1) = 'forbidden_type'` | rejected: function is not allowed (pg_typeof) |
| `SELECT txid_current()` | rejected: function is not allowed (txid_current) |
| `SELECT system_user` | rejected: function is not allowed (pg_catalog.system_user) |
| `SELECT current_catalog, current_role, user` | rejected: session introspection keyword is not allowed (CURRENT_CATALOG) |
| `SELECT current_schemas(true)` | rejected: function is not allowed (current_schemas) |
| `SELECT version()` | rejected: function is not allowed (version) |
| `SELECT inet_server_addr()` | rejected: function is not allowed (inet_server_addr) |
| `SELECT pg_backend_pid()` | rejected: function is not allowed (pg_backend_pid) |
| `SELECT to_regclass('forbidden_secrets')` | rejected: function is not allowed (to_regclass) |
| `SELECT 'forbidden_secrets'::regclass::oid` | rejected: cast type is not allowed (regclass) |
| `SELECT CAST('x' AS pg_catalog.regclass)` | rejected: cast type is not allowed (pg_catalog.regclass) |
| `SELECT 'x'::"regclass"` | rejected: cast type is not allowed (regclass) |
| `SELECT 'x'::oid` | rejected: cast type is not allowed (oid) |
| `SELECT 1::xid` | rejected: cast type is not allowed (xid) |
| `SELECT '1'::pg_lsn` | rejected: cast type is not allowed (pg_lsn) |
| `SELECT 'x'::xml` | rejected: cast type is not allowed (xml) |
| `SELECT NULL::forbidden_secrets` | rejected: cast type is not allowed (forbidden_secrets) |
| `SELECT ('(1,x)'::forbidden_secrets).secret` | rejected: cast type is not allowed (forbidden_secrets) |
| `SELECT '1'::int::regtype` | rejected: cast type is not allowed (regtype) |
| `SELECT 'a'::name` | accepted |
| `SELECT 'x'::"TEXT"` | rejected: cast type is not allowed (TEXT) |
| `SELECT '1'::"int4"` | accepted |
| `SELECT '{}'::text[]` | accepted |
| `SELECT '{}'::int[2][3]` | accepted |
| `SELECT 'x'::varchar(2)::"char"` | accepted |
| `SELECT interval '1 day' hour to minute` | accepted |
| `SELECT 1::int8::bit(8)` | rejected: cast type is not allowed (pg_catalog.bit) |
| `SELECT 'x'::tsvector` | rejected: cast type is not allowed (tsvector) |
| `SELECT 'x'::tsquery` | rejected: cast type is not allowed (tsquery) |
| `SELECT 'x'::money` | rejected: cast type is not allowed (money) |
| `SELECT tableoid, xmin, ctid FROM allowed_orders` | accepted |
| `SELECT tableoid::regclass FROM allowed_orders` | rejected: cast type is not allowed (regclass) |
| `SELECT tableoid = 'forbidden_secrets' FROM allowed_orders` | accepted |
| `SELECT o.pg_typeof FROM allowed_orders o` | rejected: not a column of the relation (functional column notation is not allowed) (o.pg_typeof) |
| `SELECT o.pg_column_size FROM allowed_orders o` | rejected: not a column of the relation (functional column notation is not allowed) (o.pg_column_size) |
| `SELECT (o).pg_typeof FROM allowed_orders o` | rejected: not a column of the relation (functional column notation is not allowed) ((o).pg_typeof) |
| `SELECT o.to_json FROM allowed_orders o` | rejected: not a column of the relation (functional column notation is not allowed) (o.to_json) |
| `SELECT x.pg_typeof FROM (SELECT 1 AS a) x` | rejected: not a column of the relation (functional column notation is not allowed) (x.pg_typeof) |
| `SELECT allowed_orders.pg_sleep FROM allowed_orders` | rejected: not a column of the relation (functional column notation is not allowed) (allowed_orders.pg_sleep) |
| `SELECT (allowed_orders).* FROM allowed_orders` | accepted |
| `SELECT o.* FROM allowed_orders o` | accepted |
| `SELECT overlay('abc' placing 'x' from 1)` | rejected: function is not allowed (pg_catalog.overlay) |
| `SELECT position('a' in 'abc')` | accepted |
| `SELECT trim(both 'x' from 'xax')` | accepted |
| `SELECT normalize('x')` | rejected: function is not allowed (pg_catalog.normalize) |
| `SELECT 'x' IS NORMALIZED` | rejected: function is not allowed (pg_catalog.is_normalized) |
| `SELECT collation for ('x')` | rejected: function is not allowed (pg_catalog.pg_collation_for) |
| `SELECT extract(epoch from now())` | accepted |
| `SELECT substring('abc' from 1 for 2)` | accepted |
| `SELECT substring('abc' similar 'a' escape '#')` | accepted |
| `SELECT 'a' SIMILAR TO 'b'` | accepted |
| `SELECT 'a' LIKE 'b' ESCAPE 'c'` | accepted |
| `SELECT 1 OPERATOR(+) 1` | accepted |
| `SELECT 1 OPERATOR(pg_catalog.+) 1` | rejected: schema-qualified operators are not allowed (pg_catalog.+) |
| `SELECT 1 OPERATOR(public.===) 1` | rejected: schema-qualified operators are not allowed (public.===) |
| `SELECT 1 === 1` | rejected: operator is not allowed (===) |
| `SELECT !! 1` | rejected: operator is not allowed (!!) |
| `SELECT 5 !` | rejected: parse error: syntax error at end of input |
| `SELECT \|/ 4, \|\|/ 8, @ -1, ~1, 1 # 2, 1 << 2` | accepted |
| `SELECT 'a' @@ 'b'` | accepted |
| `SELECT '{"a":1}'::jsonb @? '$.a'` | accepted |
| `SELECT '[1]'::jsonb @@ '$[0] == 1'` | accepted |
| `SELECT 'x' <-> 'y'` | accepted |
| `SELECT ARRAY[1] && ARRAY[1]` | accepted |
| `SELECT '1.1.1.1'::inet <<= '1.1.1.0/24'::cidr` | accepted |
| `SELECT $1` | rejected: bind parameters are not supported (ParamRef) |
| `SELECT $$dollar$$, $q$quoted$q$` | accepted |
| `SELECT U&'d\0061ta', U&'d!0061ta' UESCAPE '!'` | accepted |
| `SELECT E'a\'b', E'\\', '\'` | accepted |
| `SELECT 'a' 'b'` | rejected: parse error: syntax error at or near "'b'" |
| `SELECT B'101', X'ff'` | accepted |
| `SELECT 1 /* nested /* comment */ still */ + 1` | accepted |
| `SELECT 1 -- trailing` | accepted |
| `SELECT * FROM allowed_orders /* ; DROP TABLE x */ WHERE id = 1` | accepted |
| `SELECT 1;` | accepted |
| `SELECT 1; ` | accepted |
| `SELECT 1;;` | rejected: trailing content after statement terminator (;) |
| `SELECT 1; SELECT 2` | rejected: exactly one statement is required (2 statements) |
| `;SELECT 1` | accepted |
| `SELECT 1 \g` | rejected: parse error: syntax error at or near "\" |
| `SELECT 1 FOR SHARE` | rejected: FOR UPDATE/SHARE is not allowed (LockingClause) |
| `SELECT 1 FOR KEY SHARE SKIP LOCKED` | rejected: FOR UPDATE/SHARE is not allowed (LockingClause) |
| `SELECT * FROM (SELECT * FROM allowed_orders FOR UPDATE) s` | rejected: FOR UPDATE/SHARE is not allowed (LockingClause) |
| `WITH x AS (SELECT * FROM allowed_orders FOR NO KEY UPDATE) SELECT * FROM x` | rejected: FOR UPDATE/SHARE is not allowed (LockingClause) |
| `SELECT 1 UNION SELECT * FROM allowed_orders FOR UPDATE` | rejected: FOR UPDATE/SHARE is not allowed (LockingClause) |
| `SELECT * INTO TEMP t FROM allowed_orders` | rejected: SELECT INTO is not allowed (IntoClause) |
| `SELECT 1 INTO UNLOGGED t` | rejected: SELECT INTO is not allowed (IntoClause) |
| `CREATE TABLE t AS SELECT * FROM allowed_orders` | rejected: CREATE TABLE AS / SELECT INTO is not allowed (CreateTableAsStmt) |
| `CREATE MATERIALIZED VIEW t AS SELECT 1` | rejected: CREATE TABLE AS / SELECT INTO is not allowed (CreateTableAsStmt) |
| `SELECT * FROM allowed_orders WHERE CURRENT OF c` | rejected: parse error: syntax error at or near "OF" |
| `FETCH ALL FROM c` | rejected: statement kind is not allowed (FetchStmt) |
| `DECLARE c CURSOR FOR SELECT 1` | rejected: statement kind is not allowed (DeclareCursorStmt) |
| `CLUSTER allowed_orders` | rejected: statement kind is not allowed (ClusterStmt) |
| `REINDEX TABLE allowed_orders` | rejected: statement kind is not allowed (ReindexStmt) |
| `REFRESH MATERIALIZED VIEW x` | rejected: statement kind is not allowed (RefreshMatViewStmt) |
| `SECURITY LABEL ON TABLE x IS 'y'` | rejected: statement kind is not allowed (SecLabelStmt) |
| `COMMENT ON TABLE allowed_orders IS 'x'` | rejected: statement kind is not allowed (CommentStmt) |
| `CHECKPOINT` | rejected: statement kind is not allowed (CheckPointStmt) |
| `DISCARD ALL` | rejected: statement kind is not allowed (DiscardStmt) |
| `RESET search_path` | rejected: SET is not allowed (VariableSetStmt) |
| `LOAD 'x'` | rejected: statement kind is not allowed (LoadStmt) |
| `IMPORT FOREIGN SCHEMA x FROM SERVER s INTO public` | rejected: statement kind is not allowed (ImportForeignSchemaStmt) |
| `CREATE FUNCTION f() RETURNS int LANGUAGE sql AS 'SELECT 1'` | rejected: statement kind is not allowed (CreateFunctionStmt) |
| `DO $$ BEGIN END $$` | rejected: DO is not allowed (DoStmt) |
| `CALL p()` | rejected: CALL is not allowed (CallStmt) |
| `EXECUTE p` | rejected: PREPARE/EXECUTE are not allowed (ExecuteStmt) |
| `PREPARE p AS SELECT 1` | rejected: PREPARE/EXECUTE are not allowed (PrepareStmt) |
| `ANALYZE allowed_orders` | rejected: VACUUM/ANALYZE are not allowed (VacuumStmt) |
| `VACUUM` | rejected: VACUUM/ANALYZE are not allowed (VacuumStmt) |
| `LOCK TABLE allowed_orders` | rejected: LOCK is not allowed (LockStmt) |
| `NOTIFY x` | rejected: LISTEN/NOTIFY are not allowed (NotifyStmt) |
| `LISTEN x` | rejected: LISTEN/NOTIFY are not allowed (ListenStmt) |
| `MERGE INTO allowed_audit a USING allowed_orders o ON a.id = o.id WHEN MATCHED THEN DELETE` | rejected: MERGE is not allowed (MergeStmt) |
| `COPY (SELECT 1) TO STDOUT` | rejected: COPY is not allowed (CopyStmt) |
| `COPY allowed_orders FROM '/etc/passwd'` | rejected: COPY is not allowed (CopyStmt) |
| `GRANT SELECT ON forbidden_secrets TO public` | rejected: GRANT/REVOKE are not allowed (GrantStmt) |
| `ALTER SYSTEM SET x = 1` | rejected: statement kind is not allowed (AlterSystemStmt) |
| `SET LOCAL search_path = x` | rejected: SET is not allowed (VariableSetStmt) |
| `SET TRANSACTION READ WRITE` | rejected: SET is not allowed (VariableSetStmt) |
| `START TRANSACTION` | rejected: transaction control statements are not allowed; use the transaction tools (TransactionStmt) |
| `SAVEPOINT s` | rejected: transaction control statements are not allowed; use the transaction tools (TransactionStmt) |
| `ROLLBACK` | rejected: transaction control statements are not allowed; use the transaction tools (TransactionStmt) |
| `ABORT` | rejected: transaction control statements are not allowed; use the transaction tools (TransactionStmt) |
| `END` | rejected: transaction control statements are not allowed; use the transaction tools (TransactionStmt) |
| `SHOW ALL` | rejected: SHOW is not allowed (VariableShowStmt) |
| `EXPLAIN (ANALYZE) DELETE FROM allowed_audit` | rejected: EXPLAIN is not allowed; use the explain_query tool (ExplainStmt) |
| `EXPLAIN ANALYZE SELECT 1` | rejected: EXPLAIN is not allowed; use the explain_query tool (ExplainStmt) |
| `SELECT (ROW(1,2)).pg_typeof` | rejected: field access on an expression is not allowed (A_Indirection) |
| `SELECT ((SELECT o FROM allowed_orders o LIMIT 1)).pg_typeof` | rejected: field access on an expression is not allowed (A_Indirection) |
| `SELECT (ARRAY[o])[1].pg_typeof FROM allowed_orders o` | rejected: field access on an expression is not allowed (A_Indirection) |
| `SELECT ((o)).to_json FROM allowed_orders o` | rejected: not a column of the relation (functional column notation is not allowed) ((o).to_json) |
| `SELECT x.to_json FROM (VALUES (1)) x` | rejected: not a column of the relation (functional column notation is not allowed) (x.to_json) |
| `SELECT c.to_json FROM allowed_orders o JOIN allowed_customers c ON true` | rejected: not a column of the relation (functional column notation is not allowed) (c.to_json) |
| `SELECT j.to_json FROM (allowed_orders o JOIN allowed_customers c ON true) j` | rejected: not a column of the relation (functional column notation is not allowed) (j.to_json) |
| `SELECT allowed_orders.to_json FROM public.allowed_orders` | rejected: not a column of the relation (functional column notation is not allowed) (allowed_orders.to_json) |
| `SELECT public.allowed_orders.to_json FROM public.allowed_orders` | rejected: not a column of the relation (functional column notation is not allowed) (public.allowed_orders.to_json) |
| `SELECT * FROM allowed_orders o ORDER BY o.pg_column_size` | rejected: not a column of the relation (functional column notation is not allowed) (o.pg_column_size) |
| `SELECT o.upper FROM allowed_orders o` | rejected: not a column of the relation (functional column notation is not allowed) (o.upper) |
| `SELECT x.pg_typeof FROM (SELECT 1 AS a) x` | rejected: not a column of the relation (functional column notation is not allowed) (x.pg_typeof) |
| `SELECT o.id, o.pg_typeof FROM allowed_orders o WHERE o.pg_column_size > 1` | rejected: not a column of the relation (functional column notation is not allowed) (o.pg_typeof) |
| `SELECT c.name FROM allowed_customers c` | accepted |
| `SELECT o.customer_id.pg_typeof FROM allowed_orders o` | rejected: column reference does not name a relation in scope (o.customer_id.pg_typeof) |
| `SELECT (o.customer_id).pg_typeof FROM allowed_orders o` | rejected: field access on an expression is not allowed (A_Indirection) |
| `SELECT t.n FROM (SELECT 1 AS n) t` | accepted |
| `SELECT paid.pg_typeof FROM (SELECT 1) paid` | rejected: not a column of the relation (functional column notation is not allowed) (paid.pg_typeof) |
| `WITH paid AS (SELECT id FROM allowed_orders) SELECT paid.to_json FROM paid` | rejected: not a column of the relation (functional column notation is not allowed) (paid.to_json) |
| `SELECT o.* FROM allowed_orders o` | accepted |
| `SELECT (o).* FROM allowed_orders o` | accepted |
| `SELECT o.id FROM allowed_orders AS o(id, cid)` | accepted |
| `SELECT o.customer_id FROM allowed_orders AS o(id, cid)` | rejected: not a column of the relation (functional column notation is not allowed) (o.customer_id) |
| `SELECT o.id, c.name FROM allowed_orders o JOIN allowed_customers c ON c.id = o.customer_id` | accepted |
| `SELECT allowed_orders.id FROM allowed_orders` | accepted |
| `SELECT public.allowed_orders.id FROM allowed_orders` | accepted |
| `SELECT public.allowed_orders.id FROM public.allowed_orders` | accepted |
| `SELECT allowed_orders.id FROM public.allowed_orders` | accepted |
| `SELECT allowed_orders.id FROM allowed_orders o` | rejected: column reference does not name a relation in scope (allowed_orders.id) |
| `SELECT o.tableoid, o.ctid, o.xmin FROM allowed_orders o` | rejected: not a column of the relation (functional column notation is not allowed) (o.tableoid) |
| `SELECT sub.amount FROM (SELECT id, amount FROM allowed_orders) sub WHERE sub.amount > 10` | accepted |
| `SELECT sub.x FROM (SELECT id AS x FROM allowed_orders) sub` | accepted |
| `SELECT sub.id, sub.name FROM (SELECT * FROM allowed_orders o JOIN allowed_customers c ON true) sub` | accepted |
| `SELECT sub.customer_id FROM (SELECT o.* FROM allowed_orders o) sub` | accepted |
| `SELECT v.id, v.name FROM (VALUES (1, 'a')) AS v(id, name)` | accepted |
| `SELECT v.column1 FROM (VALUES (1, 'a')) v` | accepted |
| `SELECT paid.status FROM (SELECT status FROM allowed_orders WHERE status = 'paid' UNION SELECT status FROM allowed_orders) paid` | accepted |
| `WITH paid AS (SELECT * FROM allowed_orders WHERE status = 'paid') SELECT paid.id, paid.amount FROM paid` | accepted |
| `WITH paid(a, b) AS (SELECT id, amount FROM allowed_orders) SELECT paid.a, p.b FROM paid, paid p` | accepted |
| `WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT t.n + 1 FROM t WHERE t.n < 5) SELECT t.n FROM t` | accepted |
| `WITH RECURSIVE t AS (SELECT id AS n FROM allowed_orders UNION ALL SELECT t.n + 1 FROM t WHERE t.n < 5) SELECT t.n FROM t` | accepted |
| `WITH a AS (SELECT * FROM b), b AS (SELECT 1 AS x) SELECT a.x FROM a` | rejected: table is not in the read allowlist (public.b) |
| `WITH RECURSIVE a AS (SELECT * FROM b), b AS (SELECT 1 AS x) SELECT a.x FROM a` | rejected: columns of the relation are not known; reference the column without a qualifier (a.x) |
| `SELECT o.id FROM allowed_orders o WHERE EXISTS (SELECT 1 FROM allowed_customers c WHERE c.id = o.customer_id)` | accepted |
| `SELECT o.id, (SELECT c.name FROM allowed_customers c WHERE c.id = o.customer_id) FROM allowed_orders o` | accepted |
| `SELECT o.id, l.name FROM allowed_orders o, LATERAL (SELECT c.name FROM allowed_customers c WHERE c.id = o.customer_id) l` | accepted |
| `SELECT o.id, l.* FROM allowed_orders o CROSS JOIN LATERAL (SELECT o.amount * 2 AS dbl) l` | accepted |
| `SELECT j.id, j.name FROM (allowed_orders o JOIN allowed_customers c USING (id)) j` | accepted |
| `SELECT u.id FROM allowed_orders o JOIN allowed_customers c USING (id) AS u` | accepted |
| `SELECT (o).id, (o).amount, (o).* FROM allowed_orders o` | accepted |
| `SELECT x.coalesce, x.lower, x.text, x."?column?", x.case, x.exists, x.array, x.row, x.count, x.current_date, x.nullif, x.greatest, x.amount FROM (SELECT coalesce(id, 1), lower(status), 'a'::text, 1 + 1, CASE WHEN true THEN 1 END, EXISTS (SELECT 1), ARRAY[1], ROW(1), count(*), current_date, nullif(1, 2), greatest(1, 2), amount::int FROM allowed_orders GROUP BY 1,2,3,4,5,6,7,8,10,11,12,13) x` | accepted |
| `SELECT x.id FROM (SELECT (SELECT o.id FROM allowed_orders o LIMIT 1)) x` | accepted |
| `SELECT o.id FROM allowed_orders AS o(id, cid)` | accepted |
| `SELECT o.cid FROM allowed_orders AS o(id, cid)` | accepted |
| `SELECT o.amount FROM allowed_orders AS o(id, cid)` | accepted |
| `SELECT * FROM allowed_orders o ORDER BY o.id` | accepted |
| `SELECT customer_id, count(o.id) FROM allowed_orders o GROUP BY o.customer_id HAVING max(o.amount) > 1` | accepted |
| `SELECT sum(o.amount) OVER (PARTITION BY o.customer_id ORDER BY o.id) FROM allowed_orders o` | accepted |
| `SELECT o.id FROM allowed_orders o UNION SELECT c.id FROM allowed_customers c ORDER BY 1` | accepted |
| `SELECT allowed_orders_v.id FROM allowed_orders_v` | rejected: columns of the relation are not known; reference the column without a qualifier (allowed_orders_v.id) |
| `SELECT o.nope FROM allowed_orders o` | rejected: not a column of the relation (functional column notation is not allowed) (o.nope) |
| `SELECT o.pg_typeof FROM allowed_orders o` | rejected: not a column of the relation (functional column notation is not allowed) (o.pg_typeof) |
| `SELECT x.pg_typeof FROM (SELECT 1 AS a) x` | rejected: not a column of the relation (functional column notation is not allowed) (x.pg_typeof) |
| `SELECT paid.to_json FROM (SELECT 1) paid` | rejected: not a column of the relation (functional column notation is not allowed) (paid.to_json) |
| `WITH paid AS (SELECT id FROM allowed_orders) SELECT paid.to_json FROM paid` | rejected: not a column of the relation (functional column notation is not allowed) (paid.to_json) |
| `SELECT c.to_json FROM allowed_orders o JOIN allowed_customers c ON true` | rejected: not a column of the relation (functional column notation is not allowed) (c.to_json) |
| `SELECT j.to_json FROM (allowed_orders o JOIN allowed_customers c ON true) j` | rejected: not a column of the relation (functional column notation is not allowed) (j.to_json) |
| `SELECT public.allowed_orders.to_json FROM public.allowed_orders` | rejected: not a column of the relation (functional column notation is not allowed) (public.allowed_orders.to_json) |
| `SELECT * FROM allowed_orders o ORDER BY o.pg_column_size` | rejected: not a column of the relation (functional column notation is not allowed) (o.pg_column_size) |
| `SELECT (o).pg_typeof FROM allowed_orders o` | rejected: not a column of the relation (functional column notation is not allowed) ((o).pg_typeof) |
| `SELECT (o.customer_id).pg_typeof FROM allowed_orders o` | rejected: field access on an expression is not allowed (A_Indirection) |
| `SELECT (ROW(1,2)).pg_typeof` | rejected: field access on an expression is not allowed (A_Indirection) |
| `SELECT ((SELECT o FROM allowed_orders o LIMIT 1)).pg_typeof` | rejected: field access on an expression is not allowed (A_Indirection) |
| `SELECT x.to_json FROM (VALUES (1)) x` | rejected: not a column of the relation (functional column notation is not allowed) (x.to_json) |
| `SELECT o.customer_id.pg_typeof FROM allowed_orders o` | rejected: column reference does not name a relation in scope (o.customer_id.pg_typeof) |
| `SELECT (id).pg_typeof FROM allowed_orders` | rejected: field access on a column is not allowed ((id).pg_typeof) |
| `SELECT (id).pg_typeof FROM allowed_orders id` | rejected: field access on a column is not allowed ((id).pg_typeof) |
| `SELECT c.x FROM allowed_orders c, (SELECT 1 AS c) s` | rejected: not a column of the relation (functional column notation is not allowed) (c.x) |
| `SELECT app.public.allowed_orders.id FROM allowed_orders` | rejected: catalog-qualified column references are not allowed (app.public.allowed_orders.id) |
| `SELECT o.leak FROM allowed_orders o` | rejected: not a column of the relation (functional column notation is not allowed) (o.leak) |
| `SELECT o.* FROM allowed_orders o, LATERAL (SELECT o.leak) l` | rejected: not a column of the relation (functional column notation is not allowed) (o.leak) |
| `SELECT * FROM allowed_orders o, LATERAL (SELECT 1 AS leak) l WHERE o.leak IS NULL` | rejected: not a column of the relation (functional column notation is not allowed) (o.leak) |
| `SELECT x.leak FROM (SELECT o.* FROM allowed_orders o) x` | rejected: not a column of the relation (functional column notation is not allowed) (x.leak) |
| `SELECT x.leak FROM (SELECT * FROM allowed_orders o JOIN (SELECT 1 AS leak) y ON true) x` | accepted |
| `SELECT "lower"('X'), "count"(*) FROM allowed_orders` | accepted |
| `SELECT string_agg(status, ',' ORDER BY o.leak_via_row) FROM allowed_orders o` | rejected: not a column of the relation (functional column notation is not allowed) (o.leak_via_row) |
| `SELECT * FROM allowed_orders o WHERE (SELECT o.leak_via_row) IS NULL` | rejected: not a column of the relation (functional column notation is not allowed) (o.leak_via_row) |
| `SELECT * FROM (WITH d AS (DELETE FROM allowed_orders RETURNING *) SELECT * FROM d) x` | rejected: data-modifying CTE is not allowed in read mode (DeleteStmt) |
| `SELECT INTERVAL '1' DAY, DATE '2026-01-01', TIMESTAMP WITH TIME ZONE '2026-01-01', 'x'::"char", 1::"int4"` | accepted |
| `SELECT NOT true = false, - 2 ^ 2, 1 + 2 * 3 - 4 / 2, 'a' \|\| 'b' IS NOT NULL, (1, 2) = (1, 2), 1 IN (1, 2) AND NOT 2 IN (3)` | accepted |
| `SELECT o.id FROM allowed_orders o WHERE o.status ~ '^p' AND o.status !~* 'X' AND o.amount BETWEEN SYMMETRIC 50 AND 5` | accepted |
| `SELECT * FROM allowed_orders WHERE created_at > now() - INTERVAL '1 year' AND created_at AT TIME ZONE 'UTC' < '2027-01-01'` | accepted |
| `SELECT array_agg(DISTINCT status), jsonb_agg(o) FROM allowed_orders o` | accepted |
| `SELECT json_build_object('id', o.id)->'id', to_jsonb(o)->>'status', to_jsonb(o) ? 'status', '{"a":[1]}'::jsonb #> '{a,0}' FROM allowed_orders o` | accepted |
| `SELECT jsonb_path_query(to_jsonb(o), '$.status ? (@ like_regex "^p")') FROM allowed_orders o` | accepted |
| `SELECT unnest(ARRAY[1,2]) AS u, generate_series(1, 2)` | rejected: function is not allowed (generate_series) |
| `SELECT format('%I.%I', 'public', 'forbidden_secrets')` | accepted |
| `SELECT quote_literal(secret) FROM forbidden_secrets` | rejected: table is not in the read allowlist (public.forbidden_secrets) |
| `SELECT o.id FROM allowed_orders o WHERE o.id = ANY (ARRAY(SELECT c.id FROM allowed_customers c))` | accepted |
| `SELECT (SELECT max(c.id) FROM allowed_customers c) = ALL (SELECT o.customer_id FROM allowed_orders o)` | accepted |
| `SELECT o.id FROM allowed_orders o GROUP BY GROUPING SETS ((o.id), (o.status), ()) ORDER BY 1 NULLS FIRST` | accepted |
| `SELECT o.id, lag(o.amount) OVER (ORDER BY o.id ROWS BETWEEN UNBOUNDED PRECEDING AND 1 FOLLOWING EXCLUDE CURRENT ROW) FROM allowed_orders o` | accepted |
| `SELECT o.id FROM allowed_orders o ORDER BY o.amount USING > FETCH FIRST 1 ROW ONLY` | accepted |
| `SELECT o.id FROM allowed_orders o ORDER BY o.amount USING ===` | rejected: operator is not allowed (===) |
| `SELECT * FROM allowed_orders WHERE status = $$paid$$ OR status = U&'p\0061id'` | accepted |
| `SELECT E'\\x41', '\x41', decode('QQ==', 'base64'), encode('A'::bytea, 'hex'), md5('x')` | accepted |
| `SELECT o.id FROM allowed_orders o TABLESAMPLE SYSTEM (50)` | rejected: column reference does not name a relation in scope (o.id) |
| `SELECT 1 FROM allowed_orders o WHERE o.id = 1 FOR UPDATE OF o` | rejected: FOR UPDATE/SHARE is not allowed (LockingClause) |
| `SELECT 1 FROM allowed_orders o WHERE o.id = 1 FOR SHARE NOWAIT` | rejected: FOR UPDATE/SHARE is not allowed (LockingClause) |
| `SELECT * FROM allowed_orders o WHERE o.id IN (SELECT id FROM allowed_customers ORDER BY id LIMIT 1 FOR UPDATE)` | rejected: FOR UPDATE/SHARE is not allowed (LockingClause) |
| `SELECT * FROM allowed_orders o, allowed_customers AS o` | accepted |
| `SELECT o.id FROM allowed_orders o, LATERAL (SELECT o.id) o` | accepted |
| `SELECT 1 FROM allowed_orders WHERE allowed_orders.id = 1 AND public.allowed_orders.id = 1` | accepted |
| `SELECT current_timestamp(3), localtimestamp(0), current_time(2)` | accepted |
| `SELECT now()::date, CAST(now() AS time), now()::timestamptz::text::varchar(10)` | accepted |
| `SELECT 'a'::text::name::"char"` | accepted |
| `SELECT ROW(1, 'a')::text, ARRAY[ROW(1)]` | accepted |
| `SELECT (o.*)::text FROM allowed_orders o` | accepted |
| `SELECT o::text FROM allowed_orders o` | accepted |
| `SELECT to_json(o)::text, row_to_json(o.*) FROM allowed_orders o` | accepted |
| `SELECT * FROM allowed_orders o WHERE o.id = 1 LIMIT ALL OFFSET 0 ROWS` | accepted |

327 probes, 101 accepted, 226 rejected

### Write mode (W = {allowed_audit})

| Probe | Result |
|---|---|
| `INSERT INTO allowed_audit (note) SELECT secret FROM forbidden_secrets` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `INSERT INTO allowed_audit (note) TABLE forbidden_secrets` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `INSERT INTO allowed_audit (note) VALUES ((SELECT secret FROM forbidden_secrets))` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `INSERT INTO allowed_audit (note) VALUES ('x') RETURNING (SELECT secret FROM forbidden_secrets)` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `INSERT INTO allowed_audit (note) VALUES ('x') ON CONFLICT (id) WHERE (SELECT true FROM forbidden_secrets) DO NOTHING` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `INSERT INTO allowed_audit (note) VALUES ('x') ON CONFLICT (id) DO UPDATE SET note = (SELECT secret FROM forbidden_secrets)` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `INSERT INTO allowed_audit (note) VALUES ('x') ON CONFLICT (id) DO UPDATE SET note = 'y' WHERE (SELECT true FROM forbidden_secrets)` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `INSERT INTO allowed_audit (note) VALUES ('x') ON CONFLICT (lower(note)) DO NOTHING` | accepted |
| `INSERT INTO allowed_audit (note) VALUES ('x') ON CONFLICT (pg_sleep(1)) DO NOTHING` | rejected: function is not allowed (pg_sleep) |
| `INSERT INTO allowed_audit (note) VALUES ('x') ON CONFLICT ((SELECT id FROM forbidden_secrets)) DO NOTHING` | rejected: parse error: syntax error at or near "SELECT" |
| `INSERT INTO allowed_audit (note) VALUES ('x') ON CONFLICT (note COLLATE "C") DO NOTHING` | rejected: COLLATE is not allowed (IndexElem) |
| `INSERT INTO allowed_audit (note) VALUES ('x') ON CONFLICT (note text_pattern_ops) DO NOTHING` | rejected: operator classes are not allowed (IndexElem) |
| `INSERT INTO allowed_audit (note) VALUES ('x') ON CONFLICT ON CONSTRAINT allowed_audit_pkey DO NOTHING` | accepted |
| `INSERT INTO allowed_audit (note) VALUES ('x') ON CONFLICT (id) DO UPDATE SET note = excluded.note RETURNING excluded.note` | accepted |
| `INSERT INTO allowed_audit (note) VALUES (pg_read_file('/etc/passwd'))` | rejected: function is not allowed (pg_read_file) |
| `INSERT INTO allowed_audit (note) VALUES ('x'::regclass::text)` | rejected: cast type is not allowed (regclass) |
| `INSERT INTO allowed_audit (note) VALUES (DEFAULT)` | accepted |
| `INSERT INTO allowed_audit DEFAULT VALUES` | accepted |
| `INSERT INTO allowed_audit (id) OVERRIDING SYSTEM VALUE VALUES (1)` | accepted |
| `INSERT INTO forbidden_secrets VALUES (1)` | rejected: table is not in the write allowlist (public.forbidden_secrets) |
| `INSERT INTO public.forbidden_secrets VALUES (1)` | rejected: table is not in the write allowlist (public.forbidden_secrets) |
| `INSERT INTO "allowed_audit" (note) VALUES ('x')` | accepted |
| `INSERT INTO allowed_orders (id) VALUES (1)` | rejected: table is not in the write allowlist (public.allowed_orders) |
| `INSERT INTO allowed_audit AS forbidden_secrets (note) VALUES ('x') RETURNING forbidden_secrets.*` | accepted |
| `WITH allowed_audit AS (SELECT 1) INSERT INTO allowed_orders (id) VALUES (1)` | rejected: table is not in the write allowlist (public.allowed_orders) |
| `WITH x AS (INSERT INTO forbidden_secrets VALUES (1) RETURNING *) SELECT * FROM x` | rejected: table is not in the write allowlist (public.forbidden_secrets) |
| `WITH x AS (INSERT INTO allowed_orders (id) VALUES (1) RETURNING *) SELECT * FROM x` | rejected: table is not in the write allowlist (public.allowed_orders) |
| `WITH x AS (DELETE FROM allowed_orders RETURNING *) INSERT INTO allowed_audit (note) SELECT status FROM x` | rejected: table is not in the write allowlist (public.allowed_orders) |
| `WITH x AS (UPDATE allowed_customers SET name = 'x' RETURNING *) SELECT 1` | rejected: table is not in the write allowlist (public.allowed_customers) |
| `WITH x AS (INSERT INTO allowed_audit (note) VALUES ('a') RETURNING id), y AS (DELETE FROM allowed_audit WHERE id IN (SELECT id FROM x)) SELECT 1` | accepted |
| `WITH RECURSIVE x AS (INSERT INTO allowed_audit (note) VALUES ('a') RETURNING id) SELECT * FROM x` | accepted |
| `WITH x AS (SELECT secret FROM forbidden_secrets) INSERT INTO allowed_audit (note) SELECT 'y'` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `INSERT INTO allowed_audit (note) WITH x AS (SELECT secret FROM forbidden_secrets) SELECT secret FROM x` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `INSERT INTO allowed_audit (note) SELECT 'a' UNION SELECT secret FROM forbidden_secrets` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `UPDATE allowed_audit SET note = (SELECT secret FROM forbidden_secrets)` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `UPDATE allowed_audit SET note = 'x' FROM forbidden_secrets` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `UPDATE allowed_audit SET note = 'x' FROM allowed_orders o, forbidden_secrets f` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `UPDATE allowed_audit SET note = 'x' FROM (SELECT * FROM forbidden_secrets) f` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `UPDATE allowed_audit SET note = 'x' FROM allowed_orders o JOIN forbidden_secrets f ON true` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `UPDATE allowed_audit SET note = 'x' FROM LATERAL (SELECT * FROM forbidden_secrets) f` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `UPDATE allowed_audit SET note = 'x' WHERE EXISTS (SELECT 1 FROM forbidden_secrets)` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `UPDATE allowed_audit SET note = 'x' RETURNING (SELECT secret FROM forbidden_secrets)` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `UPDATE allowed_audit SET (note, created_at) = (SELECT secret, now() FROM forbidden_secrets)` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `UPDATE allowed_audit SET (note, created_at) = ROW('x', now())` | accepted |
| `UPDATE allowed_audit SET (note, created_at) = ('x', now())` | accepted |
| `UPDATE allowed_audit SET note = DEFAULT` | accepted |
| `UPDATE allowed_audit SET note[1] = 'x'` | accepted |
| `UPDATE allowed_audit SET note = pg_read_file('/etc/passwd')` | rejected: function is not allowed (pg_read_file) |
| `UPDATE allowed_audit SET note = 'x' WHERE CURRENT OF c` | rejected: unsupported syntax (CurrentOfExpr) |
| `UPDATE forbidden_secrets SET secret = 'x'` | rejected: table is not in the write allowlist (public.forbidden_secrets) |
| `UPDATE allowed_orders SET amount = 0` | rejected: table is not in the write allowlist (public.allowed_orders) |
| `UPDATE ONLY allowed_audit SET note = 'x'` | accepted |
| `UPDATE allowed_audit AS allowed_orders SET note = 'x'` | accepted |
| `UPDATE allowed_audit a SET note = 'x' FROM allowed_audit b` | accepted |
| `UPDATE public.allowed_audit SET note = 'x'` | accepted |
| `UPDATE "Public".allowed_audit SET note = 'x'` | rejected: table is not in the write allowlist (Public.allowed_audit) |
| `WITH allowed_audit AS (SELECT 1) UPDATE allowed_audit SET note = 'x'` | accepted |
| `WITH u AS (UPDATE allowed_audit SET note = 'x' RETURNING *) SELECT * FROM u, forbidden_secrets` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `WITH u AS (UPDATE allowed_audit SET note = 'x' FROM forbidden_secrets RETURNING *) SELECT * FROM u` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `DELETE FROM allowed_audit USING forbidden_secrets` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `DELETE FROM allowed_audit USING allowed_orders o, forbidden_secrets f` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `DELETE FROM allowed_audit USING (SELECT * FROM forbidden_secrets) f` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `DELETE FROM allowed_audit USING LATERAL (SELECT * FROM forbidden_secrets) f` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `DELETE FROM allowed_audit WHERE id IN (SELECT id FROM forbidden_secrets)` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `DELETE FROM allowed_audit RETURNING (SELECT secret FROM forbidden_secrets)` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `DELETE FROM allowed_audit WHERE CURRENT OF c` | rejected: unsupported syntax (CurrentOfExpr) |
| `DELETE FROM forbidden_secrets` | rejected: table is not in the write allowlist (public.forbidden_secrets) |
| `DELETE FROM allowed_orders` | rejected: table is not in the write allowlist (public.allowed_orders) |
| `DELETE FROM ONLY allowed_audit` | accepted |
| `DELETE FROM allowed_audit AS forbidden_secrets USING allowed_orders WHERE forbidden_secrets.id = allowed_orders.id` | accepted |
| `WITH allowed_audit AS (SELECT 1) DELETE FROM allowed_audit` | accepted |
| `WITH d AS (DELETE FROM allowed_audit RETURNING *) DELETE FROM allowed_orders` | rejected: table is not in the write allowlist (public.allowed_orders) |
| `WITH d AS (DELETE FROM allowed_audit RETURNING *) SELECT * FROM d` | accepted |
| `SELECT * FROM allowed_audit` | accepted |
| `SELECT * FROM forbidden_secrets` | rejected: table is not in the read or write allowlist (public.forbidden_secrets) |
| `SELECT * FROM allowed_orders FOR UPDATE` | rejected: FOR UPDATE/SHARE is not allowed (LockingClause) |
| `SELECT * FROM allowed_audit FOR UPDATE` | rejected: FOR UPDATE/SHARE is not allowed (LockingClause) |
| `UPDATE allowed_audit SET note = 'x' FROM allowed_audit_v` | rejected: table is not in the read or write allowlist (public.allowed_audit_v) |
| `INSERT INTO allowed_audit (note) SELECT pg_sleep(1)::text` | rejected: function is not allowed (pg_sleep) |
| `INSERT INTO allowed_audit (note) VALUES ('x') RETURNING pg_sleep(1)` | rejected: function is not allowed (pg_sleep) |
| `MERGE INTO allowed_audit a USING allowed_orders o ON a.id = o.id WHEN MATCHED THEN DELETE` | rejected: MERGE is not allowed (MergeStmt) |
| `TRUNCATE allowed_audit` | rejected: TRUNCATE is not allowed (TruncateStmt) |
| `LOCK allowed_audit` | rejected: LOCK is not allowed (LockStmt) |
| `INSERT INTO allowed_audit (note) VALUES ('x'); DELETE FROM allowed_audit` | rejected: exactly one statement is required (2 statements) |
| `INSERT INTO allowed_audit (note) VALUES ('x') RETURNING allowed_audit.to_json` | rejected: not a column of the relation (functional column notation is not allowed) (allowed_audit.to_json) |
| `INSERT INTO allowed_audit AS a (note) VALUES ('x') RETURNING a.pg_typeof` | rejected: not a column of the relation (functional column notation is not allowed) (a.pg_typeof) |
| `INSERT INTO allowed_audit (id, note) VALUES (1, 'x') ON CONFLICT (id) DO UPDATE SET note = excluded.to_json::text` | rejected: not a column of the relation (functional column notation is not allowed) (excluded.to_json) |
| `UPDATE allowed_audit a SET note = a.to_json::text` | rejected: not a column of the relation (functional column notation is not allowed) (a.to_json) |
| `UPDATE allowed_audit SET note = 'x' FROM allowed_orders o WHERE o.pg_column_size > 0` | rejected: not a column of the relation (functional column notation is not allowed) (o.pg_column_size) |
| `DELETE FROM allowed_audit a USING allowed_orders o WHERE a.pg_typeof::text = 'x'` | rejected: not a column of the relation (functional column notation is not allowed) (a.pg_typeof) |
| `DELETE FROM allowed_audit RETURNING allowed_audit.record_out` | rejected: not a column of the relation (functional column notation is not allowed) (allowed_audit.record_out) |
| `INSERT INTO allowed_audit (note) VALUES ('x') RETURNING allowed_audit.id, allowed_audit.note` | accepted |
| `INSERT INTO allowed_audit AS a (note) VALUES ('x') RETURNING a.id` | accepted |
| `INSERT INTO allowed_audit (id, note) VALUES (1, 'x') ON CONFLICT (id) DO UPDATE SET note = excluded.note \|\| allowed_audit.note WHERE allowed_audit.id = excluded.id RETURNING allowed_audit.*` | accepted |
| `UPDATE allowed_audit a SET note = c.name FROM allowed_customers c WHERE c.id = a.id RETURNING a.id, c.name` | accepted |
| `UPDATE allowed_audit SET note = allowed_audit.note \|\| 'x' WHERE allowed_audit.id = 1` | accepted |
| `DELETE FROM allowed_audit a USING allowed_orders o WHERE a.id = o.id RETURNING a.note, o.status` | accepted |
| `DELETE FROM allowed_audit USING allowed_orders WHERE allowed_audit.id = allowed_orders.id` | accepted |
| `WITH d AS (DELETE FROM allowed_audit RETURNING id, note) SELECT d.id, d.note FROM d` | accepted |
| `WITH d AS (DELETE FROM allowed_audit a USING allowed_orders o WHERE a.id = o.id RETURNING a.*, o.status) SELECT d.note, d.status FROM d` | accepted |
| `WITH i AS (INSERT INTO allowed_audit (note) VALUES ('x') RETURNING *) SELECT i.id FROM i` | accepted |
| `WITH u AS (UPDATE allowed_audit SET note = 'x' RETURNING id AS uid) SELECT u.uid FROM u` | accepted |
| `INSERT INTO allowed_audit (note) VALUES ('x') RETURNING allowed_audit.to_json` | rejected: not a column of the relation (functional column notation is not allowed) (allowed_audit.to_json) |
| `INSERT INTO allowed_audit AS a (note) VALUES ('x') RETURNING a.pg_typeof` | rejected: not a column of the relation (functional column notation is not allowed) (a.pg_typeof) |
| `INSERT INTO allowed_audit (id, note) VALUES (1, 'x') ON CONFLICT (id) DO UPDATE SET note = excluded.to_json::text` | rejected: not a column of the relation (functional column notation is not allowed) (excluded.to_json) |
| `UPDATE allowed_audit a SET note = a.to_json::text` | rejected: not a column of the relation (functional column notation is not allowed) (a.to_json) |
| `UPDATE allowed_audit SET note = 'x' FROM allowed_orders o WHERE o.pg_column_size > 0` | rejected: not a column of the relation (functional column notation is not allowed) (o.pg_column_size) |
| `DELETE FROM allowed_audit a USING allowed_orders o WHERE a.pg_typeof::text = 'x'` | rejected: not a column of the relation (functional column notation is not allowed) (a.pg_typeof) |
| `DELETE FROM allowed_audit RETURNING allowed_audit.record_out` | rejected: not a column of the relation (functional column notation is not allowed) (allowed_audit.record_out) |
| `WITH d AS (DELETE FROM allowed_audit RETURNING *) SELECT d.to_json FROM d` | rejected: not a column of the relation (functional column notation is not allowed) (d.to_json) |

110 probes, 35 accepted, 75 rejected

### Byte-level probes (driven from Go)

| Probe | Result |
|---|---|
| `SELECT 1\x00; SELECT * FROM forbidden_secrets` | accepted as `SELECT 1` before; now rejected (NUL) |
| `SELECT * FROM allowed_orders\x00, forbidden_secrets` | accepted as `SELECT * FROM public.allowed_orders` before; now rejected (NUL) |
| `SELECT * FROM "allowed_orders\x00x"` | rejected (parse error, unterminated identifier) |
| `SELECT 'a\x00b'` | rejected (parse error, unterminated string) |
| `SELECT * FROM "allowed_orders\xff"` | rejected (invalid UTF-8) |
| `SELECT '\xff'` | rejected (invalid UTF-8) |
| `SELECT 1 --\r\n, 2` | accepted, `SELECT 1, 2` |
| `SELECT\f1` | accepted |
| 5,000 nested parentheses | accepted (`SELECT 1`) |
| 2,000 nested sub-selects | rejected (protobuf recursion depth) |
| 100,000 nested parentheses | rejected (parser memory exhausted, no crash) |
| 1 MiB target list | 42 s before; now rejected (too long) |
