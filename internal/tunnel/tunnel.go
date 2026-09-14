// Package tunnel runs the gram tunnel agent, the only ingress to the MCP
// listener, and tracks its connection state for the readiness probe.
package tunnel

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/speakeasy-api/gram/tunnel/agent"
)

// Config is what the agent needs; all values come from the environment.
type Config struct {
	GatewayURL     string
	APIKey         string
	LocalMCPURL    string
	ServiceVersion string
	Metadata       map[string]string
}

// Runner wraps the agent and exposes its state.
type Runner struct {
	agent  *agent.Agent
	state  atomic.Value
	logger *slog.Logger
}

// New builds the runner. The agent's own log lines are observed to derive
// the connection state, since the agent does not expose one.
func New(cfg Config, logger *slog.Logger) (*Runner, error) {
	if logger == nil {
		logger = slog.Default()
	}
	r := &Runner{logger: logger}
	r.state.Store("connecting")
	a, err := agent.New(agent.Config{
		GatewayURL:     cfg.GatewayURL,
		APIKey:         cfg.APIKey,
		LocalMCPURL:    cfg.LocalMCPURL,
		ServiceVersion: cfg.ServiceVersion,
		Metadata:       cfg.Metadata,
	}, slog.New(&stateHandler{Handler: logger.Handler(), runner: r}))
	if err != nil {
		return nil, err
	}
	r.agent = a
	return r, nil
}

// Run blocks until ctx is cancelled, reconnecting as needed.
func (r *Runner) Run(ctx context.Context) error {
	r.state.Store("connecting")
	r.logger.InfoContext(ctx, "tunnel agent starting")
	err := r.agent.Run(ctx)
	r.state.Store("stopped")
	r.logger.InfoContext(ctx, "tunnel agent stopped", "error", errString(err))
	return err
}

// State is "disabled" for a nil runner, else connecting, connected, or
// stopped.
func (r *Runner) State() string {
	if r == nil {
		return "disabled"
	}
	if s, ok := r.state.Load().(string); ok {
		return s
	}
	return "connecting"
}

// stateHandler forwards agent log records and updates the runner state from
// the agent's lifecycle messages.
type stateHandler struct {
	slog.Handler
	runner *Runner
}

func (h *stateHandler) Handle(ctx context.Context, rec slog.Record) error {
	switch rec.Message {
	case "tunnel agent connected":
		h.runner.state.Store("connected")
	case "tunnel agent session ended", "tunnel agent reconnecting":
		h.runner.state.Store("connecting")
	}
	return h.Handler.Handle(ctx, rec)
}

func (h *stateHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &stateHandler{Handler: h.Handler.WithAttrs(attrs), runner: h.runner}
}

func (h *stateHandler) WithGroup(name string) slog.Handler {
	return &stateHandler{Handler: h.Handler.WithGroup(name), runner: h.runner}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
