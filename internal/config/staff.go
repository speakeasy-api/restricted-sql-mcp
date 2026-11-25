package config

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
)

var (
	staffLogin = regexp.MustCompile(`^[^@[:space:],]+[+]restricted-sql@(?i:speakeasy[.]com|speakeasyapi[.]dev)$`)
	replayLSN  = regexp.MustCompile(`^[0-9A-Fa-f]{1,8}/[0-9A-Fa-f]{1,8}$`)
)

func ValidStaffLogin(role string) bool {
	return len(role) <= 63 && staffLogin.MatchString(role)
}

const (
	StaffGrantRole    = "restricted_sql_staff_grants"
	StaffVerifierRole = "restricted_sql_staff_verify"
)

func (c *Config) validateStaff() error {
	if c.Dialect != policy.Postgres || c.ConnectionLevelSecurity || c.Databases != "" ||
		len(c.AnnotationTiers) != 1 || c.AnnotationTiers[0] != "confidential" {
		return errors.New("staff mode requires Postgres and the confidential annotation class")
	}
	switch c.StaffMode {
	case "reconcile":
		if c.Tunnel || c.TunnelOnly || c.StaffAccounts != "" || c.StaffVerifierPassword != "" ||
			len(c.StaffLogins) == 0 || len(c.StaffLogins) > 5 {
			return errors.New("reconcile mode requires one to five dedicated logins and a primary DSN")
		}
		u, err := url.Parse(c.DSN)
		if err != nil || u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" || u.Port() != "5432" ||
			u.User == nil || u.User.Username() != StaffGrantRole || u.RawQuery != "sslmode=disable" || c.DefaultDatabase() == "" {
			return errors.New("staff reconciliation requires the dedicated grant login through the local primary proxy")
		}
		if password, _ := u.User.Password(); password == "" {
			return errors.New("staff reconciliation requires a password")
		}
		seen := map[string]bool{}
		for _, role := range c.StaffLogins {
			if !ValidStaffLogin(role) || seen[role] {
				return errors.New("invalid or duplicate staff database login")
			}
			seen[role] = true
		}
	case "serve":
		u, err := url.Parse(c.DSN)
		if err != nil || u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" || u.Port() != "5432" ||
			u.User != nil || u.RawQuery != "sslmode=disable" || c.DefaultDatabase() == "" {
			return errors.New("staff serving requires a credential-free DSN for the local replica proxy")
		}
		host, _, err := net.SplitHostPort(c.Listen)
		if err != nil || host != "127.0.0.1" || c.Transport != "http" || !c.TunnelOnly ||
			len(c.StaffLogins) != 0 || c.StaffAccounts == "" || c.StaffAudience == "" ||
			c.StaffOrganization == "" || c.StaffVerifierPassword == "" || !replayLSN.MatchString(c.StaffReplayLSN) || c.StaffReplayLSN == "0/0" ||
			c.MaxRows > 100 || c.StatementTimeout.Seconds() > 5 || strings.EqualFold(c.LogLevel, "debug") {
			return errors.New("staff serving requires a private loopback tunnel, staff credentials, identity scope, replay floor, and pilot limits")
		}
	default:
		return errors.New("--staff-mode must be reconcile or serve")
	}
	return nil
}
