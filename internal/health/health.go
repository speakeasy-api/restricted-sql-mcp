// Package health serves the liveness and readiness probes.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/db"
	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/policy"
)

// probeTimeout bounds one readiness evaluation so a hung database cannot
// stall the probe.
const probeTimeout = 3 * time.Second

// Checker evaluates readiness on every probe.
type Checker struct {
	backend     db.Backend
	tables      []policy.TableRef
	tunnelState func() string
	timeout     time.Duration
	logger      *slog.Logger
}

// New builds a checker. tunnelState may be nil, which reports "disabled".
func New(b db.Backend, tables []policy.TableRef, tunnelState func() string, logger *slog.Logger) *Checker {
	if logger == nil {
		logger = slog.Default()
	}
	if tunnelState == nil {
		tunnelState = func() string { return "disabled" }
	}
	return &Checker{backend: b, tables: tables, tunnelState: tunnelState, timeout: probeTimeout, logger: logger}
}

// Healthz reports liveness: 200 once the process is serving.
func (c *Checker) Healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

type readiness struct {
	Ready  bool   `json:"ready"`
	Reason string `json:"reason,omitempty"`
	Tunnel string `json:"tunnel"`
}

// Readyz reports readiness: the database answers a ping and every
// allowlisted table exists. Readiness is re-evaluated on each probe.
func (c *Checker) Readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), c.timeout)
	defer cancel()
	start := time.Now()
	reason := c.evaluate(ctx)
	body := readiness{Ready: reason == "", Reason: reason, Tunnel: c.tunnelState()}
	status := http.StatusOK
	if !body.Ready {
		status = http.StatusServiceUnavailable
	}
	c.logger.DebugContext(ctx, "readyz", "ready", body.Ready, "reason", reason, "tunnel", body.Tunnel, "duration", time.Since(start).String())
	writeJSON(w, status, body)
}

// evaluate returns an empty string when ready, else the reason.
func (c *Checker) evaluate(ctx context.Context) string {
	if err := c.backend.Ping(ctx); err != nil {
		return "db ping failed: " + err.Error()
	}
	if len(c.tables) == 0 {
		return ""
	}
	missing, err := c.backend.TablesExist(ctx, c.tables)
	if err != nil {
		return "table check failed: " + err.Error()
	}
	if len(missing) > 0 {
		names := make([]string, 0, len(missing))
		for _, m := range missing {
			names = append(names, m.String())
		}
		return "missing tables: " + strings.Join(names, ", ")
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		fmt.Fprintf(w, `{"error":%q}`, err.Error())
	}
}
