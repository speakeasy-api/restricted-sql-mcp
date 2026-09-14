# Task R2 — Adversarial review of the ClickHouse guard

Branch: `review-ch-guard`. Target: `internal/sqlguard/clickhouse/` (guard I did
not write). Goal: find any input that reaches a non-allowlisted table, calls a
non-allowlisted function, leaks server state, or bypasses SETTINGS / FORMAT /
INTO OUTFILE rejection.

Method: fast probing with `cmd/sqlguard-check` (`--dialect clickhouse
--default-schema app --read-tables allowed_orders,allowed_customers`), AST dumps
of the `AfterShip/clickhouse-sql-parser` tree, and confirmation against the live
e2e ClickHouse over HTTP with `readonly=1` to check both that rejections are
warranted and that accepted statements are genuinely harmless. ~330 probes total
across the areas below.

## Real bypass found and fixed

### A table name in the set position of `IN` reaches a non-allowlisted table

The guard rejected a bare identifier directly on the right of `IN`
(`... IN forbidden_secrets`) but not the far more natural parenthesised form.
ClickHouse resolves the sole element of an `IN (...)` list as a table when it is
an identifier, so every one of these read `app.forbidden_secrets`, which is not
in the allowlist:

- `... id IN (forbidden_secrets)` — bare name in parens
- `... id IN (app.forbidden_secrets)` — qualified name in parens
- `... id IN ((app.forbidden_secrets))` — nested parens
- `... id GLOBAL IN (forbidden_secrets)` / `... NOT IN (app.forbidden_secrets)`
- `in(id, forbidden_secrets)`, `notIn(...)`, `globalIn(...)`, `globalNotIn(...)`
  — the function-call spellings of the operator, which are all on the function
  allowlist and pass their second argument straight to the table resolver
- the same expression hidden in a lambda body, e.g.
  `arrayFilter(x -> (x, 'y') IN (app.forbidden_secrets), [1])`

This is not just a reference — it is a working exfiltration oracle. Against the
live server, `SELECT (1,'hunter2') IN (app.forbidden_secrets)` returns `1` and
`SELECT (1,'wrongguess') IN (app.forbidden_secrets)` returns `0`, so an attacker
can read the secret column of the forbidden table one predicate at a time. The
function form `in((1,'hunter2'), app.forbidden_secrets)` returns `1` the same
way.

Fix (`internal/sqlguard/clickhouse/`):

- `nodes.go`: in the `IN` / `NOT IN` operator branch, after the existing
  bare-identifier check, unwrap any parenthesised single-element list and reject
  it when the operand is a qualified name (`NestedIdentifier` / `Path`) or a
  bare identifier that is not a CTE or scalar alias in scope. The membership
  functions `in` / `notin` / `globalin` / `globalnotin` get the same check on
  every argument after the first (the set position). Because the check runs in
  the expression walker, it also fires inside lambda bodies and subqueries.
- `guard.go`: added a separate scalar-alias scope. `WITH <expr> AS <name>` now
  records `<name>` there so `... IN (name)` still works when `name` is a scalar
  alias, without letting that name satisfy a *table* reference. This distinction
  matters: I confirmed that if scalar aliases were added to the relation scope,
  `WITH 5 AS forbidden_secrets SELECT * FROM forbidden_secrets` would read the
  real table (live returns `1  hunter2`). Keeping the scopes separate closes
  that door while the current code already rejected the `FROM` form.

Legitimate set-position operands still work: constant lists `IN (1,2,3)`,
subqueries `IN (SELECT ...)`, scalar aliases `WITH 5 AS s ... IN (s)`, relation
CTEs `WITH t AS (...) ... IN (t)`, and `in(id, (1,2,3))`.

e2e: added the operator, function, and lambda forms to `bypassCorpusClickHouse`
in `e2e/corpus_test.go`, and a dedicated `TestClickHouseInTableBypass` in
`e2e/clickhouse_read_test.go` that asserts each leak (including the concrete
`(1,'hunter2')` oracle) is rejected end to end and that the legitimate forms
still execute. `make e2e-ch` is green; `gofmt` and `go vet` are clean.

Commit: `fix(chguard): reject table refs in IN set position`.

## Everything else probed — all correctly rejected (no fix needed)

Dangerous functions, all casings/aliases (rejected, function not on allowlist):
`sleep`, `SLEEP`, `Sleep`, `sleepEachRow`, `url`, `URL`, `file`, `s3`, `remote`,
`remoteSecure`, `cluster`, `clusterAllReplicas`, `merge`, `numbers`,
`numbers_mt`, `generateRandom`, `input`, `values`, `executable`, `dictGet`,
`dictGetString`, `dictGetOrDefault`, `dictHas`, `currentUser`, `user`,
`current_user`, `hostName`, `version`, `getSetting`, `getMacro`, `FQDN`,
`currentDatabase`, `tcpPort`, `throwIf`, `transform` (not allowlisted),
`joinGet`, `viewIfPermitted`, `hasColumnInTable`, `catboostEvaluate`,
`replicate`, `currentProfiles`/`currentRoles`/`enabledRoles`, `serverUUID`,
`uptime`, `buildId`, `getServerPort`, `initialQueryID`, `zookeeperSessionUptime`,
`filesystemAvailable`, `getClientHTTPHeader`, `showCertificate`, `revision`,
`connectionId`, `demangle`, `addressToLine`/`addressToSymbol`, `__getScalar`,
`evalMLMethod`, `formatRow`, `s3Cluster`, `hdfs`, `mysql`, `postgresql`, `jdbc`,
`odbc`, `reinterpretAsUInt64`. Casing is handled because the allowlist match
lowercases the name.

Table functions in every structural position (rejected):
`FROM numbers(10)`, `FROM url(...)`, `FROM merge('app','.*')`,
`FROM remote(...)`, `FROM cluster(...)`, `FROM generateRandom(...)`,
`FROM input(...)`, `FROM values(...)`, `FROM executable(...)`,
`JOIN numbers(10)`, `FROM a, numbers(10)`, `CROSS JOIN numbers(10)`,
`ARRAY JOIN (SELECT ... FROM forbidden_secrets)`, `IN (SELECT ... FROM numbers)`.

Statement kinds other than a single SELECT (rejected):
`SHOW TABLES`, `SHOW CREATE TABLE`, `DESCRIBE`, `DESC`, `EXISTS TABLE`, `KILL`,
`SYSTEM ...`, `OPTIMIZE`, `CHECK TABLE`, `SET`, `USE`, `WATCH`, `INSERT`,
`ALTER TABLE ... DELETE`, `DROP`, `EXPLAIN ...`, `EXPLAIN` inside a subquery,
multiple statements (`SELECT 1; DROP TABLE ...`), and trailing content after a
`;` including trailing comments (`SELECT 1 /* c */ ; --`).

SETTINGS / FORMAT / INTO OUTFILE in every placement (rejected):
top-level, in a subquery (`FROM (SELECT ... SETTINGS ...)`), in a CTE body, in a
UNION branch, after a parenthesised group (`(SELECT ...) SETTINGS ...`,
`(SELECT ...) FORMAT JSON`, `(SELECT ...) INTO OUTFILE ...`), and
`SETTINGS readonly=0`. The visitor checks `Settings` and `Format` on every
`SelectQuery` node including inner/parenthesised queries and set-operation
branches.

Casts and types (rejected): `CAST(... AS Object('json'))`,
`CAST(x, 'Object(''json'')')`, `CAST(... AS AggregateFunction(...))`,
`CAST(... AS Enum(...))`, `'x'::regclass`. The builtin cast-type allowlist and
the string-form type parser both reject these; `Nullable(Int32)` / `Array(Int32)`
/ `FixedString(10)` are accepted as expected.

Identifier tricks: backtick and double-quote quoting of allowlisted tables is
accepted and canonicalised to `app.table`; `system`, `SYSTEM`, `System`,
`information_schema`, and `default.allowed_orders` are rejected; Cyrillic
look-alike `аllowed_orders` is rejected as a distinct (non-allowlisted) name.
Quote/backslash escape variants were checked against the parser's own lexer —
string literals and quoted identifiers are stored and re-emitted verbatim
between their delimiters, and the delimiter can never appear unescaped inside
the stored value, so the canonical SQL round-trips without an escaping-based
injection.

Parameterised queries (rejected): `{id:Int32}`, `{x:UInt8}` (bind parameters not
supported); `$1` parses as a plain identifier (an unknown column at runtime, no
table access).

Lambdas / higher-order functions (rejected where dangerous):
`arrayMap(x -> sleep(x), [1])`, `arrayMap(x -> currentUser(), [1])`,
`arrayFilter(x -> hostName() = 'x', [1])`, `arrayReduce('sum', ...)` and the
string-function-name higher-order forms (function not on allowlist), lambda
parameters constrained to identifiers.

`PREWHERE`, `SAMPLE`, and CTE forms: `PREWHERE id IN (SELECT ... FROM
forbidden_secrets)` and `PREWHERE sleep(1)=0` rejected; `SAMPLE 0.1` rejected;
`WITH (SELECT secret FROM forbidden_secrets) AS s SELECT s` rejected; the
intended CTE shadow `WITH forbidden_secrets AS (SELECT 1 AS id) SELECT id FROM
forbidden_secrets` accepted (matches spec and existing test).

## False alarms cleared (guard accepts, but harmless)

- `ARRAY JOIN forbidden_secrets` (bare or qualified): the guard accepts it, but
  ClickHouse raises `UNKNOWN_IDENTIFIER` — `ARRAY JOIN` takes an array
  expression, not a table, so no data is reached. Confirmed live.
- `exists(forbidden_secrets)` / `exists(app.forbidden_secrets)`: accepted by the
  guard (the `exists` function is allowlisted), but ClickHouse raises a syntax
  error because `EXISTS` expects a subquery, not a bare table. No leak.
- `NOT IN` / `GLOBAL NOT IN`: the parser's JSON shows the operation field as
  `IN`, but `parser.Format` reconstructs `NOT IN` / `GLOBAL NOT IN` faithfully,
  so the canonical SQL does not silently invert a predicate.

## Residual risks / notes

- The two false-alarm forms above (`ARRAY JOIN <table>`, `exists(<table>)`) are
  accepted by the guard and rejected only by ClickHouse. They are harmless
  today, but they rely on the server for a clean rejection rather than the
  guard. If a future ClickHouse version changed name resolution in either spot,
  the guard would not be the backstop. Tightening the guard to reject a bare or
  qualified table identifier in the `ARRAY JOIN` operand and the `exists`
  argument would make it self-sufficient. Left out of this change to avoid
  over-rejecting on behaviour I could not make leak.
- The fix trusts the `AfterShip/clickhouse-sql-parser` AST to agree with the
  ClickHouse server on how an `IN` operand is resolved. This held for every
  probe, and the second, session-level `readonly=1` layer remains in place, but
  the guard's safety is ultimately bounded by parser/server agreement.
- `readonly=1` is a strong second layer: it blocks writes, `SYSTEM`, most table
  functions, and settings changes at the server even if a future guard gap let
  one through. It does not, by itself, stop reading a non-allowlisted table, so
  the guard remains the authority for table-level isolation.
