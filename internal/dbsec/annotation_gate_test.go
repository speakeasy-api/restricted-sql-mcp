package dbsec

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/db"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
)

type gateTestSource struct {
	mu                               sync.Mutex
	tier                             policy.Tier
	loadErr, verifyErr, reconcileErr error
	reconciles, loads                int
	loadGate                         chan struct{} // when set, Load waits for it
}

func (s *gateTestSource) Load(ctx context.Context) (*policy.Catalog, error) {
	s.mu.Lock()
	wait := s.loadGate
	s.loads++
	s.mu.Unlock()
	if wait != nil {
		select {
		case <-wait:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	c := &policy.Catalog{Relations: []policy.Relation{{Ref: policy.TableRef{Schema: "public", Name: "records"}, Kind: "table", Columns: []policy.CatalogColumn{{Name: "id", Tier: s.tier, AnnotationStatus: "valid"}}}}}
	return c, c.Seal()
}
func (s *gateTestSource) Reconcile(context.Context, *policy.Policy) (Creds, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconciles++
	return Creds{}, s.reconcileErr
}
func (s *gateTestSource) Verify(context.Context, *policy.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifyErr
}
func (s *gateTestSource) Close(context.Context) error { return nil }

type gateTestBackend struct{ db.Backend }

func (*gateTestBackend) Ping(context.Context) error { return nil }
func (*gateTestBackend) Close() error               { return nil }
func newTestAnnotationGate(s *gateTestSource) *AnnotationGate {
	return NewAnnotationGate(&policy.Policy{AnnotationTiers: map[policy.Tier]bool{policy.Tier("safe"): true}}, s, func(context.Context, Creds, *policy.Policy) (db.Backend, error) { return &gateTestBackend{}, nil }, time.Second, nil)
}
func TestAnnotationGateInvalidatesOldResultsBeforePublication(t *testing.T) {
	s := &gateTestSource{tier: policy.Tier("safe")}
	g := newTestAnnotationGate(s)
	defer g.Close()
	if err := g.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, p, finish, err := g.AcquireData(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	old := p.Catalog.Digest
	s.mu.Lock()
	s.tier = policy.Tier("content")
	s.mu.Unlock()
	refreshed := make(chan error, 1)
	go func() { refreshed <- g.Refresh(context.Background()) }()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("old query was not canceled")
	}
	if _, _, _, err := g.AcquireData(context.Background()); err == nil {
		t.Fatal("new query admitted during refresh")
	}
	select {
	case err := <-refreshed:
		t.Fatalf("published with active old lease: %v", err)
	default:
	}
	if err := finish(); err == nil {
		t.Fatal("canceled result escaped")
	}
	if err := <-refreshed; err != nil {
		t.Fatal(err)
	}
	_, p, done, err := g.AcquireData(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	if p.Catalog.Digest == old || p.CanRead(policy.TableRef{Schema: "public", Name: "records"}) {
		t.Fatal("old policy survived")
	}
}
func TestAnnotationGateFailuresStayClosedAndRetry(t *testing.T) {
	for _, phase := range []string{"load", "grants", "verify"} {
		t.Run(phase, func(t *testing.T) {
			s := &gateTestSource{tier: policy.Tier("safe")}
			g := newTestAnnotationGate(s)
			defer g.Close()
			if err := g.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			fault := errors.New("injected control-plane failure")
			s.mu.Lock()
			switch phase {
			case "load":
				s.loadErr = fault
			case "grants":
				s.tier = policy.Tier("content")
				s.reconcileErr = fault
			case "verify":
				s.verifyErr = fault
			}
			s.mu.Unlock()
			if err := g.Refresh(context.Background()); err == nil {
				t.Fatal("failure hidden")
			}
			if _, _, _, err := g.AcquireData(context.Background()); err == nil {
				t.Fatal("stale policy remained open")
			}
			s.mu.Lock()
			s.loadErr = nil
			s.reconcileErr = nil
			s.verifyErr = nil
			s.mu.Unlock()
			if err := g.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			_, _, finish, err := g.AcquireData(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if err := finish(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestAnnotationGateUnchangedCatalogDoesNotReprovision(t *testing.T) {
	s := &gateTestSource{tier: policy.Tier("safe")}
	g := newTestAnnotationGate(s)
	defer g.Close()
	for i := 0; i < 3; i++ {
		if err := g.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if s.reconciles != 1 {
		t.Fatalf("reconciled %d times", s.reconciles)
	}
}

func TestAnnotationGateDrainTimeoutKeepsAdmissionClosed(t *testing.T) {
	s := &gateTestSource{tier: policy.Tier("safe")}
	g := newTestAnnotationGate(s)
	defer g.Close()
	if err := g.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, _, finish, err := g.AcquireData(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	s.mu.Lock()
	s.tier = policy.Tier("secret")
	s.mu.Unlock()
	g.timeout = 20 * time.Millisecond
	if err := g.Refresh(context.Background()); err == nil {
		t.Fatal("published without draining the previous operation")
	}
	if ctx.Err() == nil {
		t.Fatal("previous operation was not canceled")
	}
	if _, _, _, err := g.AcquireData(context.Background()); err == nil {
		t.Fatal("drain failure left admission open")
	}
	if s.reconciles != 1 {
		t.Fatal("reconciled grants before draining")
	}
	if err := finish(); err == nil {
		t.Fatal("canceled result was released")
	}
	g.timeout = time.Second
	if err := g.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// A caller that stops waiting (probe deadline, client disconnect) must not
// abort the refresh or close admission for everyone else.
func TestAnnotationGateCallerCancellationDoesNotCloseAdmission(t *testing.T) {
	s := &gateTestSource{tier: policy.Tier("safe")}
	g := newTestAnnotationGate(s)
	defer g.Close()
	if err := g.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	s.mu.Lock()
	s.loadGate = release
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := g.Refresh(ctx); err == nil {
		t.Fatal("expected the abandoned wait to report an error")
	}
	if _, _, finish, err := g.AcquireData(context.Background()); err != nil {
		t.Fatalf("admission closed by caller cancellation: %v", err)
	} else if err := finish(); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := g.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, finish, err := g.AcquireData(context.Background()); err != nil {
		t.Fatal(err)
	} else if err := finish(); err != nil {
		t.Fatal(err)
	}
}

func TestAnnotationGateProbeRefreshIsRateLimited(t *testing.T) {
	s := &gateTestSource{tier: policy.Tier("safe")}
	g := newTestAnnotationGate(s)
	defer g.Close()
	if err := g.EnsureProvisioned(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	first := s.loads
	s.mu.Unlock()
	for i := 0; i < 5; i++ {
		if err := g.EnsureProvisioned(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	s.mu.Lock()
	loads := s.loads
	s.mu.Unlock()
	if loads != first {
		t.Fatalf("repeated probes ran %d extra catalog loads, want 0", loads-first)
	}
	s.mu.Lock()
	s.loadErr = errors.New("catalog unavailable")
	s.mu.Unlock()
	if err := g.Refresh(context.Background()); err == nil {
		t.Fatal("expected refresh failure")
	}
	if err := g.EnsureProvisioned(context.Background()); err == nil {
		t.Fatal("recent failed refresh must keep readiness failing")
	}
}

// The refresh's own timeout is a real control-plane failure and fails closed.
func TestAnnotationGateRefreshTimeoutFailsClosed(t *testing.T) {
	s := &gateTestSource{tier: policy.Tier("safe")}
	g := NewAnnotationGate(&policy.Policy{AnnotationTiers: map[policy.Tier]bool{policy.Tier("safe"): true}}, s, func(context.Context, Creds, *policy.Policy) (db.Backend, error) { return &gateTestBackend{}, nil }, 50*time.Millisecond, nil)
	defer g.Close()
	if err := g.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.loadGate = make(chan struct{})
	s.mu.Unlock()
	if err := g.Refresh(context.Background()); err == nil {
		t.Fatal("expected refresh timeout")
	}
	if _, _, _, err := g.AcquireData(context.Background()); err == nil {
		t.Fatal("admission stayed open after refresh timeout")
	}
}
