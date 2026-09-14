package policy

// clickhouseFunctions is the allowlist of callable functions for ClickHouse.
// Names are lowercase (ClickHouse function names are case-insensitive for
// matching purposes here). Table functions (url, file, s3, remote, numbers,
// merge, executable, ...) and side-effecting or introspective functions
// (sleep, sleepEachRow, throwIf, dictGet*, currentUser, hostName, version,
// getSetting, ...) are deliberately absent.
var clickhouseFunctions = setOf(
	// aggregates
	"count", "sum", "avg", "min", "max", "any", "anylast", "argmin", "argmax", "uniq",
	"uniqexact", "uniqcombined", "uniqhll12", "quantile", "quantiles", "quantileexact",
	"quantiletdigest", "median", "groupArray", "grouparray", "groupuniqarray", "topk",
	"stddevpop", "stddevsamp", "varpop", "varsamp", "sumif", "countif", "avgif", "minif",
	"maxif", "uniqif", "sumdistinct", "countdistinct",
	// window
	"row_number", "rank", "dense_rank", "lagInFrame", "laginframe", "leadinframe",
	"first_value", "last_value", "nth_value",
	// conditional / null
	"if", "multiif", "coalesce", "nullif", "ifnull", "isnull", "isnotnull", "greatest", "least",
	"assumenotnull", "tonullable",
	// string
	"length", "lengthutf8", "lower", "upper", "lowerutf8", "upperutf8", "trim", "trimleft",
	"trimright", "trimboth", "substring", "substr", "left", "right", "concat", "reverse",
	"replaceone", "replaceall", "replaceregexpone", "replaceregexpall", "position",
	"positioncaseinsensitive", "startswith", "endswith", "splitbychar", "splitbystring",
	"arraystringconcat", "format", "extract", "extractall", "match", "like", "notlike",
	"ilike", "empty", "notempty", "tolower", "toupper", "md5", "sha256", "hex", "unhex",
	"repeat", "leftpad", "rightpad",
	// math
	"abs", "ceil", "ceiling", "floor", "round", "roundbankers", "trunc", "truncate", "sign",
	"sqrt", "cbrt", "pow", "power", "exp", "log", "ln", "log10", "log2", "modulo", "intdiv",
	"intdivorzero", "pi", "rand", "rand64", "sin", "cos", "tan", "e", "plus", "minus",
	"multiply", "divide", "negate",
	// date/time
	"now", "now64", "today", "yesterday", "todate", "todate32", "todatetime", "todatetime64",
	"tostartofday", "tostartofhour", "tostartofminute", "tostartofmonth", "tostartofweek",
	"tostartofyear", "tostartofquarter", "tostartofinterval", "tostartoffiveminutes",
	"tostartoffifteenminutes", "toyear", "tomonth", "todayofmonth", "todayofweek", "tohour",
	"tominute", "tosecond", "toyyyymm", "toyyyymmdd", "tounixtimestamp", "fromunixtimestamp",
	"datediff", "date_diff", "dateadd", "date_add", "datesub", "date_sub", "adddays", "addhours",
	"addminutes", "addseconds", "addmonths", "addyears", "subtractdays", "subtracthours",
	"subtractminutes", "subtractseconds", "subtractmonths", "subtractyears", "formatdatetime",
	"parsedatetimebesteffort", "parsedatetimebesteffortornull", "totimezone", "age",
	"tointervalday", "tointervalhour", "tointervalminute", "tointervalsecond",
	// conversion
	"tostring", "toint8", "toint16", "toint32", "toint64", "touint8", "touint16", "touint32",
	"touint64", "tofloat32", "tofloat64", "todecimal32", "todecimal64", "todecimal128",
	"toint32ornull", "toint64ornull", "tofloat64ornull", "tostringornull", "touuid",
	"touuidornull", "cast", "accuratecast", "accuratecastornull", "tointervalday",
	"toint32orzero", "toint64orzero", "tofloat64orzero", "totypename",
	// arrays / maps / json
	"array", "arrayjoin", "arraylength", "arrayelement", "has", "hasall", "hasany", "indexof",
	"arraydistinct", "arraysort", "arrayreversesort", "arrayconcat", "arrayslice",
	"arrayfilter", "arraymap", "arraysum", "arraymin", "arraymax", "arrayavg", "arrayexists",
	"arrayall", "arraycount", "arrayfirst", "arrayflatten", "arrayuniq", "arrayreverse",
	"arrayzip", "arrayenumerate", "arraypushback", "arraypushfront", "range", "tuple",
	"tupleelement", "map", "mapkeys", "mapvalues", "mapcontains", "jsonextract",
	"jsonextractstring", "jsonextractint", "jsonextractfloat", "jsonextractbool",
	"jsonextractraw", "jsonextractarrayraw", "jsonextractkeys", "jsonhas", "jsonlength",
	"jsontype", "simplejsonextractstring", "simplejsonextractint", "simplejsonextractfloat",
	"simplejsonhas", "visitparamextractstring", "visitparamextractint",
	// misc pure
	"generateuuidv4", "toyearweek", "bitand", "bitor", "bitxor", "bitnot", "bitshiftleft",
	"bitshiftright", "cityhash64", "siphash64", "xxhash64", "halfmd5", "isnan", "isinfinite",
	"isfinite", "least", "greatest", "and", "or", "not", "xor", "equals", "notequals", "less",
	"greater", "lessorequals", "greaterorequals", "in", "notin", "globalin", "globalnotin",
)

// clickhouseCastTypes are the builtin type names allowed as cast targets.
var clickhouseCastTypes = setOf(
	"int8", "int16", "int32", "int64", "int128", "int256", "uint8", "uint16", "uint32",
	"uint64", "uint128", "uint256", "float32", "float64", "decimal", "decimal32", "decimal64",
	"decimal128", "decimal256", "bool", "boolean", "string", "fixedstring", "date", "date32",
	"datetime", "datetime64", "uuid", "ipv4", "ipv6", "nullable", "array", "tuple", "map",
	"lowcardinality", "json",
)
