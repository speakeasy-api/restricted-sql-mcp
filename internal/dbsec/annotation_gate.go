package dbsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/db"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
)

type annotationRefresh struct {
	done chan struct{}
	err  error
}

type AnnotationBuilder func(context.Context, Creds, *policy.Policy) (db.Backend, error)

// AnnotationGate owns admission, catalog publication and grants. Privileged
// catalog/provisioning operations are never exposed as a query backend.
type AnnotationGate struct {
	base          *policy.Policy
	source        AnnotationSource
	build         AnnotationBuilder
	timeout       time.Duration
	log           *slog.Logger
	sem           chan struct{}
	flight        *annotationRefresh
	mu            sync.Mutex
	pol           *policy.Policy
	inner         db.Backend
	ready, closed bool
	reason        error
	active        map[*annotationLease]struct{}
	changed       chan struct{}
	life          context.Context // cancelled by Close; bounds every refresh
	kill          context.CancelFunc
	lastRefresh   time.Time // completion time of the latest refresh
	lastErr       error
}

// probeRefreshInterval rate-limits refreshes triggered by readiness probes.
// Probes are unauthenticated; each one must not force a catalog scan.
const probeRefreshInterval = 2 * time.Second

type annotationLease struct {
	gate    *AnnotationGate
	backend db.Backend
	pol     *policy.Policy
	ctx     context.Context
	cancel  context.CancelFunc
	once    sync.Once
	err     error
}
type annotationLeaseKey struct{}

func NewAnnotationGate(base *policy.Policy, source AnnotationSource, build AnnotationBuilder, timeout time.Duration, log *slog.Logger) *AnnotationGate {
	if log == nil {
		log = slog.Default()
	}
	life, kill := context.WithCancel(context.Background())
	return &AnnotationGate{base: base, source: source, build: build, timeout: timeout, log: log, sem: make(chan struct{}, 1), active: map[*annotationLease]struct{}{}, changed: make(chan struct{}), reason: errors.New("catalog has not loaded"), life: life, kill: kill}
}
func (g *AnnotationGate) Dialect() policy.Dialect { return g.base.Dialect }
func (g *AnnotationGate) notifyLocked()           { close(g.changed); g.changed = make(chan struct{}) }
func (g *AnnotationGate) stopAdmission(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ready = false
	g.reason = err
	for l := range g.active {
		l.cancel()
	}
	g.notifyLocked()
}
func (g *AnnotationGate) drain(ctx context.Context) error {
	for {
		g.mu.Lock()
		n := len(g.active)
		changed := g.changed
		g.mu.Unlock()
		if n == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

// Refresh coalesces concurrent requests. The refresh itself runs detached from
// the caller: it is bounded only by the gate lifetime and the refresh timeout.
// A caller whose context ends (probe deadline, client disconnect) stops
// waiting but cannot abort the refresh, so a caller-side cancellation never
// looks like a control-plane failure. Failed control-plane checks invalidate
// admission even when a previous generation existed.
func (g *AnnotationGate) Refresh(parent context.Context) error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return errors.New("annotation backend is closed")
	}
	flight := g.flight
	if flight == nil {
		flight = &annotationRefresh{done: make(chan struct{})}
		g.flight = flight
		go g.runRefresh(flight)
	}
	g.mu.Unlock()
	select {
	case <-parent.Done():
		return fmt.Errorf("annotation refresh still running: %w", parent.Err())
	case <-flight.done:
		return flight.err
	}
}

func (g *AnnotationGate) runRefresh(flight *annotationRefresh) {
	err := g.refresh()
	g.mu.Lock()
	flight.err = err
	g.lastRefresh = time.Now()
	g.lastErr = err
	g.flight = nil
	close(flight.done)
	g.mu.Unlock()
}

func (g *AnnotationGate) refresh() (retErr error) {
	select {
	case g.sem <- struct{}{}:
	case <-g.life.Done():
		return errors.New("annotation backend is closed")
	}
	defer func() { <-g.sem }()
	ctx, cancel := context.WithTimeout(g.life, g.timeout)
	defer cancel()
	g.mu.Lock()
	closed := g.closed
	oldPol := g.pol
	wasReady := g.ready
	g.mu.Unlock()
	if closed {
		return errors.New("annotation backend is closed")
	}
	defer func() {
		if retErr != nil {
			g.stopAdmission(fmt.Errorf("annotation refresh failed: %w", retErr))
		}
	}()
	catalog, err := g.source.Load(ctx)
	if err != nil {
		return err
	}
	if wasReady && oldPol != nil && catalog.Digest == oldPol.Catalog.Digest {
		if err := g.source.Verify(ctx, oldPol); err != nil {
			return err
		}
		return nil
	}
	g.stopAdmission(errors.New("annotation catalog/grants are refreshing"))
	if err := g.drain(ctx); err != nil {
		return fmt.Errorf("draining previous catalog generation: %w", err)
	}
	candidate := g.base.WithCatalog(catalog)
	creds, err := g.source.Reconcile(ctx, candidate)
	if err != nil {
		return err
	}
	// Detect a migration racing provisioning before publishing either snapshot.
	again, err := g.source.Load(ctx)
	if err != nil {
		return err
	}
	if again.Digest != catalog.Digest {
		return errors.New("catalog changed during grant reconciliation; retry required")
	}
	backend, err := g.build(ctx, creds, candidate)
	if err != nil {
		return err
	}
	if err := backend.Ping(ctx); err != nil {
		_ = backend.Close()
		return err
	}
	if err := ctx.Err(); err != nil {
		_ = backend.Close()
		return err
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		_ = backend.Close()
		return errors.New("annotation backend is closed")
	}
	old := g.inner
	g.inner = backend
	g.pol = candidate
	g.ready = true
	g.reason = nil
	g.notifyLocked()
	g.mu.Unlock()
	if old != nil {
		// All leases are finished. Driver transport cleanup may outlive query
		// cancellation (pgx waits up to 15s); it must not stall readiness/publication.
		go func() {
			if err := old.Close(); err != nil {
				g.log.Warn("retired annotation pool close failed", "error", err)
			}
		}()
	}
	g.log.Info("annotation catalog published", "generation", catalog.Digest, "queryable_relations", len(candidate.ReadTables))
	return nil
}
func (g *AnnotationGate) Run(ctx context.Context, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			g.stopAdmission(ctx.Err())
			return
		case <-tick.C:
			if err := g.Refresh(ctx); err != nil && ctx.Err() == nil {
				g.log.Warn("annotation refresh unavailable", "error", err)
			}
		}
	}
}

// EnsureProvisioned serves readiness probes. A refresh completed within
// probeRefreshInterval is reused rather than repeated.
func (g *AnnotationGate) EnsureProvisioned(ctx context.Context) error {
	g.mu.Lock()
	recent := g.flight == nil && !g.lastRefresh.IsZero() && time.Since(g.lastRefresh) < probeRefreshInterval
	ready, reason, lastErr := g.ready, g.reason, g.lastErr
	g.mu.Unlock()
	if recent {
		if lastErr != nil {
			return lastErr
		}
		if !ready {
			return fmt.Errorf("annotation access unavailable: %v", reason)
		}
		return nil
	}
	return g.Refresh(ctx)
}
func (g *AnnotationGate) RefreshColumns(ctx context.Context) error { return nil } // coordinator already refreshed in readiness
func (g *AnnotationGate) Ping(ctx context.Context) error {
	g.mu.Lock()
	ready, reason, b := g.ready, g.reason, g.inner
	g.mu.Unlock()
	if !ready {
		return fmt.Errorf("annotation access unavailable: %v", reason)
	}
	return b.Ping(ctx)
}

// AcquireData holds one generation until the handler has constructed its result.
// Finish both releases the lease and reports invalidation, so canceled results
// cannot escape merely because a database driver returned partial success.
func (g *AnnotationGate) AcquireData(ctx context.Context) (context.Context, *policy.Policy, func() error, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.ready || g.closed {
		return nil, nil, nil, fmt.Errorf("annotation access unavailable: %v", g.reason)
	}
	lctx, cancel := context.WithCancel(ctx)
	l := &annotationLease{gate: g, backend: g.inner, pol: g.pol, ctx: lctx, cancel: cancel}
	g.active[l] = struct{}{}
	finish := func() error {
		l.once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			if l.ctx.Err() != nil || !g.ready || g.pol != l.pol {
				l.err = errors.New("annotation query canceled: catalog generation is no longer active")
			}
			delete(g.active, l)
			l.cancel()
			g.notifyLocked()
		})
		return l.err
	}
	return context.WithValue(lctx, annotationLeaseKey{}, l), l.pol, finish, nil
}
func (g *AnnotationGate) lease(ctx context.Context) (*annotationLease, error) {
	l, ok := ctx.Value(annotationLeaseKey{}).(*annotationLease)
	if !ok || l.gate != g {
		return nil, errors.New("annotation query requires a catalog lease")
	}
	if err := l.ctx.Err(); err != nil {
		return nil, err
	}
	return l, nil
}
func (g *AnnotationGate) Query(ctx context.Context, sql string, max int) (*db.Result, error) {
	l, err := g.lease(ctx)
	if err != nil {
		return nil, err
	}
	return l.backend.Query(ctx, sql, max)
}
func (g *AnnotationGate) Explain(ctx context.Context, sql string, opts db.ExplainOptions) (json.RawMessage, string, error) {
	l, err := g.lease(ctx)
	if err != nil {
		return nil, "", err
	}
	return l.backend.Explain(ctx, sql, opts)
}
func (g *AnnotationGate) ListSchemas(ctx context.Context) ([]db.Schema, error) {
	l, err := g.lease(ctx)
	if err != nil {
		return nil, err
	}
	out := []db.Schema{}
	for _, name := range l.pol.Catalog.Schemas {
		out = append(out, db.Schema{Name: name})
	}
	return out, nil
}
func (g *AnnotationGate) ListObjects(ctx context.Context, schema, kind string) ([]db.Object, error) {
	l, err := g.lease(ctx)
	if err != nil {
		return nil, err
	}
	out := []db.Object{}
	for _, r := range l.pol.Catalog.Relations {
		if r.Ref.Schema != schema {
			continue
		}
		if kind != "" && r.Kind != kind && !(kind == "view" && r.Kind == "materialized_view") {
			continue
		}
		out = append(out, db.Object{Name: r.Ref.Name, Type: r.Kind, Engine: r.Engine, Access: relationAccess(l.pol, r)})
	}
	return out, nil
}
func relationAccess(p *policy.Policy, r policy.Relation) *db.ObjectAccess {
	reason := r.Denial
	if reason == "" && !p.CanRead(r.Ref) {
		reason = "no selectable columns"
	}
	return &db.ObjectAccess{Generation: p.Catalog.Digest, Queryable: p.CanRead(r.Ref), SelectableColumns: len(p.ReadableColumns(r.Ref)), DenialReason: reason}
}
func (g *AnnotationGate) ObjectDetails(ctx context.Context, ref policy.TableRef) (*db.ObjectDetails, error) {
	l, err := g.lease(ctx)
	if err != nil {
		return nil, err
	}
	r, ok := l.pol.Relation(ref)
	if !ok {
		return nil, fmt.Errorf("object %s does not exist in the catalog", ref)
	}
	d := &db.ObjectDetails{Schema: ref.Schema, Name: ref.Name, Type: r.Kind, Engine: r.Engine, Columns: []db.ColumnDetail{}, Constraints: []db.Constraint{}, Indexes: []db.Index{}, Access: relationAccess(l.pol, *r)}
	for _, c := range r.Constraints {
		d.Constraints = append(d.Constraints, db.Constraint{Name: c.Name, Type: c.Kind, Columns: c.Columns, ReferencedTable: c.ReferencedTable, ReferencedColumns: c.ReferencedColumns})
	}
	for _, c := range r.Columns {
		d.Columns = append(d.Columns, db.ColumnDetail{Name: c.Name, Type: c.Type, Nullable: c.Nullable, Access: &db.ColumnAccess{Tier: string(c.Tier), AnnotationStatus: c.AnnotationStatus, Selectable: l.pol.CanReadColumn(ref, c.Name), DenialReason: l.pol.ColumnDenial(ref, c.Name)}})
	}
	return d, nil
}
func (g *AnnotationGate) Close() error {
	g.stopAdmission(errors.New("annotation backend is closed"))
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()
	g.kill()
	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()
	select {
	case g.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-g.sem }()
	if err := g.drain(ctx); err != nil {
		return err
	}
	g.mu.Lock()
	b := g.inner
	g.mu.Unlock()
	if b != nil {
		// Driver cleanup can wait on a canceled socket. Revoke credentials
		// promptly even when the transport has not finished closing.
		go func() { _ = b.Close() }()
	}
	return g.source.Close(ctx)
}
