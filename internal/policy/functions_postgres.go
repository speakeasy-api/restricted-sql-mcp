package policy

// postgresFunctions is the allowlist of callable functions for Postgres.
// Names are lowercase and unqualified. Extend deliberately; every entry must be
// side-effect free and unable to read files, settings, or other relations.
var postgresFunctions = setOf(
	// aggregates
	"count", "sum", "avg", "min", "max", "array_agg", "string_agg", "bool_and", "bool_or",
	"every", "json_agg", "jsonb_agg", "json_object_agg", "jsonb_object_agg",
	"stddev", "stddev_pop", "stddev_samp", "variance", "var_pop", "var_samp",
	"percentile_cont", "percentile_disc", "mode",
	// window
	"row_number", "rank", "dense_rank", "percent_rank", "cume_dist", "ntile",
	"lag", "lead", "first_value", "last_value", "nth_value",
	// conditional / null handling
	"coalesce", "nullif", "greatest", "least", "num_nonnulls", "num_nulls",
	// string
	"length", "char_length", "character_length", "octet_length", "lower", "upper", "initcap",
	"trim", "ltrim", "rtrim", "btrim", "substring", "substr", "left", "right", "lpad", "rpad",
	"replace", "position", "strpos", "split_part", "concat", "concat_ws", "reverse", "repeat",
	"translate", "starts_with", "regexp_replace", "regexp_match", "regexp_matches",
	"regexp_split_to_array", "md5", "to_char", "to_number", "format", "quote_literal",
	"encode", "decode", "ascii", "chr",
	// internal names the parser emits for SIMILAR TO / LIKE ... ESCAPE
	"similar_to_escape", "like_escape",
	// math
	"abs", "ceil", "ceiling", "floor", "round", "trunc", "sign", "sqrt", "cbrt", "power", "exp",
	"ln", "log", "log10", "mod", "div", "pi", "random", "width_bucket", "degrees", "radians",
	"sin", "cos", "tan",
	// date/time
	"now", "current_date", "current_time", "current_timestamp", "localtime", "localtimestamp",
	"clock_timestamp", "statement_timestamp", "transaction_timestamp", "age", "date_trunc",
	"date_part", "extract", "date_bin", "to_timestamp", "to_date", "make_date", "make_interval",
	"make_timestamp", "make_timestamptz", "justify_days", "justify_hours", "justify_interval",
	"isfinite", "timezone",
	// json
	"json_build_object", "jsonb_build_object", "json_build_array", "jsonb_build_array",
	"json_extract_path", "jsonb_extract_path", "json_extract_path_text", "jsonb_extract_path_text",
	"json_array_length", "jsonb_array_length", "json_typeof", "jsonb_typeof", "jsonb_pretty",
	"json_array_elements", "jsonb_array_elements", "json_array_elements_text",
	"jsonb_array_elements_text", "json_each", "jsonb_each", "json_each_text", "jsonb_each_text",
	"jsonb_path_query", "jsonb_path_query_array", "jsonb_path_query_first", "jsonb_path_exists",
	"jsonb_strip_nulls", "to_json", "to_jsonb", "row_to_json",
	// arrays
	"array_length", "cardinality", "array_position", "array_positions", "array_remove",
	"array_replace", "array_append", "array_prepend", "array_cat", "array_to_string",
	"string_to_array", "unnest", "array_upper", "array_lower", "array_ndims", "array_dims",
	// misc; no pg_* function is allowed (pg_typeof leaks type names,
	// txid_current assigns a transaction id even in a read-only transaction)
	"gen_random_uuid", "uuid_generate_v4",
)

// postgresCastTypes are the builtin type names allowed as cast targets.
var postgresCastTypes = setOf(
	"int", "integer", "int2", "int4", "int8", "smallint", "bigint", "serial", "bigserial",
	"numeric", "decimal", "real", "float4", "float8", "double precision", "float",
	"text", "varchar", "character varying", "char", "character", "bpchar", "name",
	"bool", "boolean", "bytea",
	"date", "time", "timetz", "timestamp", "timestamptz", "interval",
	"time without time zone", "time with time zone",
	"timestamp without time zone", "timestamp with time zone",
	"uuid", "json", "jsonb", "inet", "cidr", "macaddr",
)

func setOf(names ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		m[n] = struct{}{}
	}
	return m
}
