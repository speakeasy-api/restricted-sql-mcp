package chguard

import (
	"strconv"
	"strings"

	"github.com/AfterShip/clickhouse-sql-parser/parser"

	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/policy"
	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/sqlguard"
)

// castType validates a cast target, whichever AST shape the parser produced:
// CAST(x AS T), x::T, or CAST(x, 'T').
func (v *visitor) castType(e parser.Expr) error {
	if isNil(e) {
		return sqlguard.Reject("cast without a type", "CastExpr")
	}
	switch n := e.(type) {
	case *parser.Ident:
		return allowedType(n.Name)
	case *parser.ScalarType:
		return allowedType(identName(n.Name))
	case *parser.ComplexType:
		if err := allowedType(identName(n.Name)); err != nil {
			return err
		}
		for _, p := range n.Params {
			if err := v.castType(p); err != nil {
				return err
			}
		}
		return nil
	case *parser.TypeWithParams:
		if err := allowedType(identName(n.Name)); err != nil {
			return err
		}
		for _, p := range n.Params {
			if err := typeParamLiteral(identName(n.Name), p); err != nil {
				return err
			}
		}
		return nil
	case *parser.JSONType:
		if n.Options != nil && len(n.Options.Items) > 0 {
			return sqlguard.Reject("JSON type options are not allowed", "JSONType")
		}
		return allowedType(identName(n.Name))
	case *parser.FunctionExpr:
		// x::Nullable(Int32) parses the type as a function call.
		if err := allowedType(identName(n.Name)); err != nil {
			return err
		}
		if n.Params == nil || n.Params.Items == nil {
			return nil
		}
		if n.Params.ColumnArgList != nil {
			return sqlguard.Reject("unsupported cast type syntax", nodeName(n))
		}
		for _, item := range n.Params.Items.Items {
			ce, ok := item.(*parser.ColumnExpr)
			if !ok {
				return sqlguard.Reject("unsupported cast type syntax", nodeName(item))
			}
			switch arg := ce.Expr.(type) {
			case *parser.NumberLiteral:
			case *parser.StringLiteral:
				if err := typeParamLiteral(identName(n.Name), arg); err != nil {
					return err
				}
			default:
				if err := v.castType(ce.Expr); err != nil {
					return err
				}
			}
		}
		return nil
	case *parser.StringLiteral:
		return allowedTypeString(n.Literal)
	}
	return sqlguard.Reject("unsupported cast type syntax", nodeName(e))
}

func identName(id *parser.Ident) string {
	if id == nil {
		return ""
	}
	return id.Name
}

func allowedType(name string) error {
	if !policy.AllowedCastType(policy.ClickHouse, name) {
		return sqlguard.Reject("cast type is not allowed", name)
	}
	return nil
}

// typeParamLiteral accepts numeric type parameters (Decimal(10, 2),
// FixedString(16), DateTime64(3)) and a timezone string for DateTime types.
func typeParamLiteral(typeName string, p parser.Expr) error {
	switch p.(type) {
	case *parser.NumberLiteral:
		return nil
	case *parser.StringLiteral:
		if isDateTimeType(typeName) {
			return nil
		}
	}
	return sqlguard.Reject("cast type parameter is not allowed", parser.Format(p))
}

func isDateTimeType(name string) bool {
	switch strings.ToLower(name) {
	case "datetime", "datetime64":
		return true
	}
	return false
}

// allowedTypeString validates a type written as a string literal, e.g.
// CAST(x, 'Nullable(Decimal(10, 2))'), using a small recursive parser.
func allowedTypeString(s string) error {
	rest, err := parseTypeString(strings.TrimSpace(s))
	if err != nil {
		return err
	}
	if strings.TrimSpace(rest) != "" {
		return sqlguard.Reject("cast type is not allowed", s)
	}
	return nil
}

func parseTypeString(s string) (string, error) {
	i := 0
	for i < len(s) && (s[i] == '_' || s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'z' || s[i] >= 'A' && s[i] <= 'Z') {
		i++
	}
	name := s[:i]
	if name == "" {
		return "", sqlguard.Reject("cast type is not allowed", s)
	}
	if err := allowedType(name); err != nil {
		return "", err
	}
	rest := strings.TrimSpace(s[i:])
	if !strings.HasPrefix(rest, "(") {
		return rest, nil
	}
	rest = strings.TrimSpace(rest[1:])
	for {
		switch {
		case rest == "":
			return "", sqlguard.Reject("cast type is not allowed", s)
		case rest[0] == '\'':
			end := strings.IndexByte(rest[1:], '\'')
			if end < 0 || !isDateTimeType(name) {
				return "", sqlguard.Reject("cast type parameter is not allowed", rest)
			}
			rest = strings.TrimSpace(rest[end+2:])
		case rest[0] >= '0' && rest[0] <= '9':
			j := 0
			for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
				j++
			}
			if _, err := strconv.Atoi(rest[:j]); err != nil {
				return "", sqlguard.Reject("cast type parameter is not allowed", rest)
			}
			rest = strings.TrimSpace(rest[j:])
		default:
			var err error
			rest, err = parseTypeString(rest)
			if err != nil {
				return "", err
			}
			rest = strings.TrimSpace(rest)
		}
		switch {
		case strings.HasPrefix(rest, ","):
			rest = strings.TrimSpace(rest[1:])
		case strings.HasPrefix(rest, ")"):
			return rest[1:], nil
		default:
			return "", sqlguard.Reject("cast type is not allowed", s)
		}
	}
}
