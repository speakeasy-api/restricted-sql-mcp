package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/db"
)

type probeBackend struct {
	db.Backend                        // Unrelated database operations must never be called by a probe.
	provisionErr, pingErr, refreshErr error
	waitForDeadline                   bool
	calls                             []string
}

func (b *probeBackend) EnsureProvisioned(context.Context) error {
	b.calls = append(b.calls, "provision")
	return b.provisionErr
}
func (b *probeBackend) Ping(ctx context.Context) error {
	b.calls = append(b.calls, "ping")
	if b.waitForDeadline {
		<-ctx.Done()
		return ctx.Err()
	}
	return b.pingErr
}
func (b *probeBackend) RefreshColumns(context.Context) error {
	b.calls = append(b.calls, "refresh")
	return b.refreshErr
}

func TestProbeContract(t *testing.T) {
	for _, tc := range []struct {
		name    string
		backend probeBackend
		status  int
		reason  string
		calls   []string
	}{
		{"ready", probeBackend{}, 200, "", []string{"provision", "ping", "refresh"}},
		{"security failure", probeBackend{provisionErr: errors.New("not provisioned")}, 503, "not provisioned", []string{"provision"}},
		{"database failure", probeBackend{pingErr: errors.New("offline")}, 503, "db ping failed: offline", []string{"provision", "ping"}},
		{"metadata failure", probeBackend{refreshErr: errors.New("offline")}, 503, "column load failed: offline", []string{"provision", "ping", "refresh"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checker := New(&tc.backend, func() string { return "connecting" }, nil)
			live := httptest.NewRecorder()
			checker.Healthz(live, httptest.NewRequest("GET", "/healthz", nil))
			if live.Code != 200 || len(tc.backend.calls) != 0 {
				t.Fatalf("liveness depends on database: status=%d calls=%v", live.Code, tc.backend.calls)
			}
			for range 2 { // A failed probe must retry, and a successful one must refresh again.
				tc.backend.calls = nil
				ready := httptest.NewRecorder()
				checker.Readyz(ready, httptest.NewRequest("GET", "/readyz", nil))
				var body readiness
				if err := json.Unmarshal(ready.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if ready.Code != tc.status || body.Ready != (tc.status == 200) || body.Reason != tc.reason || body.Tunnel != "connecting" {
					t.Fatalf("readiness = %d %s", ready.Code, ready.Body.String())
				}
				if !reflect.DeepEqual(tc.backend.calls, tc.calls) {
					t.Fatalf("calls = %v, want %v", tc.backend.calls, tc.calls)
				}
			}
		})
	}
}

func TestReadinessTimeout(t *testing.T) {
	checker := New(&probeBackend{waitForDeadline: true}, nil, nil)
	checker.timeout = time.Millisecond
	ready := httptest.NewRecorder()
	checker.Readyz(ready, httptest.NewRequest("GET", "/readyz", nil))
	var body readiness
	if err := json.Unmarshal(ready.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if ready.Code != 503 || body.Reason != "db ping failed: context deadline exceeded" || body.Tunnel != "disabled" {
		t.Fatalf("readiness = %d %s", ready.Code, ready.Body.String())
	}
}
