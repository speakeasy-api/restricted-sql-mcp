package e2e

// Bypass and positive corpora from the design spec §6. These are data only;
// the dialect suites decide how to run them.

// bypassCorpusCommon must be rejected in read mode by both dialects.
var bypassCorpusCommon = []string{
	"SELECT 1; DROP TABLE allowed_orders",
	"SELECT * FROM forbidden_secrets",
	"SELECT * FROM allowed_orders JOIN forbidden_secrets USING (id)",
	"SELECT * FROM allowed_orders WHERE id IN (SELECT id FROM forbidden_secrets)",
	"WITH x AS (SELECT * FROM forbidden_secrets) SELECT * FROM x",
	"SELECT (SELECT count(*) FROM forbidden_secrets)",
	`SELECT * FROM "allowed_orders" a, forbidden_secrets b`,
	"SELECT * FROM information_schema.tables",
	"INSERT INTO allowed_orders VALUES (1)",
	"UPDATE allowed_orders SET amount = 0",
	"DELETE FROM allowed_orders",
	"TRUNCATE allowed_orders",
	"ALTER TABLE allowed_orders ADD COLUMN x int",
	"CREATE TABLE t (x int)",
	"EXPLAIN SELECT * FROM allowed_orders",
	"SET search_path = other",
	"SHOW search_path",
	"SELECT * FROM allowed_orders /* comment */ ; --",
	"",
	"   ",
}

// bypassCorpusPostgres must be rejected in read mode on Postgres.
var bypassCorpusPostgres = []string{
	"SELECT * FROM public.forbidden_secrets",
	"SELECT pg_sleep(10)",
	"SELECT * FROM allowed_orders, LATERAL generate_series(1,10)",
	"SELECT * FROM generate_series(1,10)",
	"SELECT lo_import('/etc/passwd')",
	"SELECT pg_read_file('/etc/passwd')",
	"SELECT current_setting('is_superuser')",
	"SELECT set_config('search_path','x',false)",
	"SELECT * FROM pg_catalog.pg_tables",
	"SELECT * FROM allowed_orders FOR UPDATE",
	"SELECT * INTO new_tbl FROM allowed_orders",
	"COPY allowed_orders TO '/tmp/x'",
	"SELECT 'x'::regclass",
	"SELECT * FROM allowed_orders TABLESAMPLE SYSTEM (1)",
	"SELECT $1",
	"SELECT 1\x00; SELECT * FROM forbidden_secrets",
	"SELECT pg_typeof(1)",
	"SELECT txid_current()",
	"SELECT o.pg_typeof FROM allowed_orders o",
	"SELECT o.leak_via_row FROM allowed_orders o",
	"SELECT (o).to_json FROM allowed_orders o",
	"SELECT x.pg_typeof FROM (SELECT 1 AS a) x",
	"SELECT (ROW(1, 2)).pg_typeof",
}

// bypassCorpusClickHouse must be rejected in read mode on ClickHouse.
var bypassCorpusClickHouse = []string{
	"SELECT * FROM app.forbidden_secrets",
	"SELECT * FROM system.tables",
	"SELECT * FROM url('http://x','CSV')",
	"SELECT * FROM numbers(10)",
	"SELECT * FROM allowed_orders SETTINGS max_threads=1",
	"SELECT * FROM allowed_orders FORMAT JSON",
	"SELECT * FROM allowed_orders INTO OUTFILE '/tmp/x'",
	"SELECT sleep(3)",
}

// bypassCorpusWritePostgres must be rejected in write mode on Postgres when
// the write set is {allowed_audit} and the read set is
// {allowed_orders, allowed_customers}.
var bypassCorpusWritePostgres = []string{
	"INSERT INTO allowed_audit (note) SELECT secret FROM forbidden_secrets",
	"UPDATE allowed_audit SET note = (SELECT max(secret) FROM forbidden_secrets)",
	"DELETE FROM allowed_audit USING forbidden_secrets WHERE allowed_audit.id = forbidden_secrets.id",
	"INSERT INTO forbidden_secrets VALUES (2, 'x')",
	"UPDATE allowed_orders SET amount = 0",
	"DELETE FROM allowed_customers",
	"INSERT INTO allowed_audit (note) VALUES ('x'); DELETE FROM allowed_audit",
	"TRUNCATE allowed_audit",
	"SELECT * FROM forbidden_secrets",
	"INSERT INTO allowed_audit (note) SELECT o.leak_via_row FROM allowed_orders o",
	"UPDATE allowed_audit a SET note = a.to_json::text",
	"DELETE FROM allowed_audit RETURNING allowed_audit.record_out",
}

// positiveCorpusCommon must be accepted in read mode by both dialects with the
// default read set {allowed_orders, allowed_customers}.
var positiveCorpusCommon = []string{
	"SELECT id, amount FROM allowed_orders ORDER BY id",
	"SELECT count(*) FROM allowed_orders",
	"SELECT o.id, c.name FROM allowed_orders o JOIN allowed_customers c ON c.id = o.customer_id ORDER BY o.id",
	"SELECT o.id, c.name FROM allowed_orders AS o LEFT JOIN allowed_customers AS c ON c.id = o.customer_id ORDER BY o.id",
	"WITH paid AS (SELECT * FROM allowed_orders WHERE status = 'paid') SELECT count(*) FROM paid",
	"SELECT customer_id, sum(amount) AS total FROM allowed_orders GROUP BY customer_id HAVING sum(amount) > 10 ORDER BY customer_id",
	"SELECT customer_id, min(amount), max(amount), avg(amount) FROM allowed_orders GROUP BY customer_id ORDER BY customer_id",
	"SELECT id, row_number() OVER (PARTITION BY customer_id ORDER BY id) AS rn FROM allowed_orders ORDER BY id",
	"SELECT id FROM allowed_orders ORDER BY id LIMIT 2 OFFSET 1",
	"SELECT name FROM allowed_customers WHERE id IN (SELECT customer_id FROM allowed_orders WHERE status = 'paid') ORDER BY name",
	"SELECT id FROM allowed_orders UNION ALL SELECT id FROM allowed_customers",
	"SELECT id, CASE WHEN amount > 20 THEN 'big' ELSE 'small' END AS size FROM allowed_orders ORDER BY id",
	"SELECT coalesce(status, 'none') AS s, nullif(status, 'paid') AS n FROM allowed_orders ORDER BY id",
	"SELECT CAST(id AS varchar) AS id_text, CAST(amount AS int) AS amount_int FROM allowed_orders ORDER BY id",
	"SELECT lower(name) AS n, upper(email) AS e, length(name) AS l FROM allowed_customers ORDER BY id",
	"SELECT DISTINCT status FROM allowed_orders ORDER BY status",
	"SELECT * FROM (SELECT id, amount FROM allowed_orders) sub WHERE sub.amount > 10 ORDER BY sub.id",
	"SELECT abs(amount) AS a, round(amount) AS r, greatest(amount, 1) AS g, least(amount, 1) AS l FROM allowed_orders ORDER BY id",
	"SELECT id FROM allowed_orders WHERE EXISTS (SELECT 1 FROM allowed_customers) ORDER BY id",
	"SELECT id FROM allowed_orders WHERE status = 'paid' AND amount > 5 OR NOT (customer_id = 2) ORDER BY id",
}
