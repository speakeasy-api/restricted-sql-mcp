package config

import (
	"errors"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
)

type ReplicaPrincipal struct {
	GramUserID    string `json:"gramUserID,omitempty"`
	Email         string `json:"email,omitempty"`
	DatabaseLogin string `json:"databaseLogin"`
}

func (p ReplicaPrincipal) RoutingKey() string {
	if p.GramUserID != "" {
		return "user:" + p.GramUserID
	}
	return "email:" + NormalizeReplicaEmail(p.Email)
}

func NormalizeReplicaEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func (p ReplicaPrincipal) validIdentity() bool {
	if p.GramUserID != "" {
		return strings.IndexFunc(p.GramUserID, unicode.IsSpace) < 0 &&
			strings.IndexFunc(p.GramUserID, unicode.IsControl) < 0
	}
	email := NormalizeReplicaEmail(p.Email)
	address, err := mail.ParseAddress(email)
	return err == nil && address.Address == email
}

func validReplicaLogin(role string) bool {
	return role != "" && len(role) <= 63 && utf8.ValidString(role) &&
		!strings.HasPrefix(role, "pg_") && strings.IndexFunc(role, unicode.IsControl) < 0
}

func (c *Config) validateReplica() error {
	if c.Dialect != policy.Postgres || c.ConnectionLevelSecurity || c.Databases != "" || len(c.AnnotationTiers) == 0 {
		return errors.New("replica mode requires Postgres annotation mode")
	}
	if len(c.ReplicaPrincipals) == 0 {
		return errors.New("replica access requires at least one configured caller")
	}
	users, logins := map[string]bool{}, map[string]bool{}
	for _, principal := range c.ReplicaPrincipals {
		key := principal.RoutingKey()
		if !principal.validIdentity() || !validReplicaLogin(principal.DatabaseLogin) ||
			users[key] || logins[principal.DatabaseLogin] {
			return errors.New("replica roster requires a unique caller email or Gram user ID and database login per entry")
		}
		users[key], logins[principal.DatabaseLogin] = true, true
	}

	u, err := url.Parse(c.DSN)
	if err != nil || u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" || u.Port() != "5432" ||
		u.RawQuery != "sslmode=disable" || c.DefaultDatabase() == "" {
		return errors.New("replica mode requires a database URL through the local Postgres proxy")
	}
	switch c.ReplicaMode {
	case "reconcile":
		if c.Tunnel || c.TunnelOnly || c.ReplicaPasswords != "" || c.ReplicaVerifierPassword != "" {
			return errors.New("reconciliation uses only the grant database credentials")
		}
		if u.User == nil || u.User.Username() == "" || logins[u.User.Username()] {
			return errors.New("reconciliation requires a separate grant database login")
		}
		if password, _ := u.User.Password(); password == "" {
			return errors.New("reconciliation requires a database password")
		}
	case "serve":
		gateway, err := url.Parse(c.TunnelGatewayURL)
		if err != nil || gateway.Scheme != "wss" || gateway.Hostname() == "" || gateway.User != nil || gateway.Fragment != "" {
			return errors.New("replica serving requires a secure tunnel gateway URL")
		}
		// The gateway publishes the assertion issuer's keys at its HTTPS origin.
		c.ReplicaIssuer = "https://" + gateway.Host
		host, _, err := net.SplitHostPort(c.Listen)
		if err != nil || host != "127.0.0.1" || c.Transport != "http" || !c.TunnelOnly || u.User != nil {
			return errors.New("replica serving requires a private loopback tunnel and a credential-free replica URL")
		}
		if c.ReplicaPasswords == "" || c.ReplicaAudience == "" || c.ReplicaOrganization == "" ||
			!validReplicaLogin(c.ReplicaVerifierLogin) || logins[c.ReplicaVerifierLogin] || c.ReplicaVerifierPassword == "" ||
			c.ReplicaMaxConcurrentQueries <= 0 || strings.EqualFold(c.LogLevel, "debug") {
			return errors.New("replica serving requires credentials, identity scope, a positive query limit, and log level info or higher")
		}
	default:
		return errors.New("--replica-mode must be reconcile or serve")
	}
	return nil
}
