package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestCollector_RegisterIdempotent guards against accidental double
// registration, which would panic in client_golang and is the most
// common boot-time failure mode for a Prometheus surface.
func TestCollector_RegisterIdempotent(t *testing.T) {
	c := NewCollector()
	if err := c.Register(); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := c.Register(); err != nil {
		t.Fatalf("second Register must be a no-op, got: %v", err)
	}
}

// TestCollector_CedarDivergenceLabels freezes the label schema for the
// Cedar divergence counter. ADR-0002 states this schema; adding or
// renaming a label requires a new ADR, so this test is intentionally
// strict.
func TestCollector_CedarDivergenceLabels(t *testing.T) {
	c := NewCollector()
	if err := c.Register(); err != nil {
		t.Fatalf("register: %v", err)
	}
	c.RecordCedarDivergence("read", "tenant_roles.admin", "role_only")
	c.RecordCedarDivergence("read", "tenant_roles.admin", "role_only")
	c.RecordCedarDivergence("create", "", "cedar_only")

	got := testutil.ToFloat64(c.cedarDivergence.WithLabelValues("read", "tenant_roles.admin", "role_only"))
	if got != 2 {
		t.Errorf("divergence counter for (read, tenant_roles.admin, role_only) = %v, want 2", got)
	}
	got = testutil.ToFloat64(c.cedarDivergence.WithLabelValues("create", "", "cedar_only"))
	if got != 1 {
		t.Errorf("divergence counter for (create, '', cedar_only) = %v, want 1", got)
	}
}

// TestCollector_CapabilityDeniedLabel verifies the single-label schema
// for the 402 counter.
func TestCollector_CapabilityDeniedLabel(t *testing.T) {
	c := NewCollector()
	if err := c.Register(); err != nil {
		t.Fatalf("register: %v", err)
	}
	c.RecordCapabilityDenied("billing.access")
	c.RecordCapabilityDenied("billing.access")
	c.RecordCapabilityDenied("rag.access")

	if got := testutil.ToFloat64(c.capabilityDenied.WithLabelValues("billing.access")); got != 2 {
		t.Errorf("denied counter for billing.access = %v, want 2", got)
	}
	if got := testutil.ToFloat64(c.capabilityDenied.WithLabelValues("rag.access")); got != 1 {
		t.Errorf("denied counter for rag.access = %v, want 1", got)
	}
}

// TestCollector_EntitlementLag_TracksRecency ensures a fresh apply
// reports ~0 lag and that the gauge rises monotonically with time until
// the next apply.
func TestCollector_EntitlementLag_TracksRecency(t *testing.T) {
	c := NewCollector()
	if err := c.Register(); err != nil {
		t.Fatalf("register: %v", err)
	}

	c.RecordEntitlementApply("external")
	first := testutil.ToFloat64(c.entitlementLag.WithLabelValues("external"))
	if first > 1.0 {
		t.Errorf("immediately after apply, lag should be near zero, got %v", first)
	}

	// Advance time by simulating a second pass — we cannot mock wall
	// clock without a clock abstraction, so sleep briefly and rely on
	// refreshLag.
	time.Sleep(50 * time.Millisecond)
	c.refreshLag()
	second := testutil.ToFloat64(c.entitlementLag.WithLabelValues("external"))
	if second <= first {
		t.Errorf("lag should rise after time passes: first=%v second=%v", first, second)
	}
}

// TestCollector_EntitlementLag_IgnoresEmptyKind prevents a background
// worker that forgets to look up tenant kind from accidentally polluting
// the gauge with an unlabeled series.
func TestCollector_EntitlementLag_IgnoresEmptyKind(t *testing.T) {
	c := NewCollector()
	if err := c.Register(); err != nil {
		t.Fatalf("register: %v", err)
	}
	c.RecordEntitlementApply("")
	if len(c.lastApply) != 0 {
		t.Errorf("empty tenant kind must not register a series, got: %+v", c.lastApply)
	}
}

// TestCollector_HandlerExposesFamilies confirms the HTTP handler serves
// the three metric families — the contract Prometheus relies on.
func TestCollector_HandlerExposesFamilies(t *testing.T) {
	c := NewCollector()
	if err := c.Register(); err != nil {
		t.Fatalf("register: %v", err)
	}
	c.RecordCedarDivergence("read", "platform.developer.nonprod", "role_only")
	c.RecordCedarEnforced("admin", "cedar_override_deny")
	c.RecordCapabilityDenied("agents.access")
	c.RecordEntitlementApply("internal")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics returned %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	s := string(body)
	for _, want := range []string{
		"orkestra_cedar_shadow_divergence_total",
		"orkestra_cedar_enforced_total",
		"orkestra_capability_denied_total",
		"orkestra_entitlement_projection_lag_seconds",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("expected metric family %q in exposition body", want)
		}
	}
}

// TestCollector_CedarEnforcedLabels freezes the label schema for the
// enforce counter (Section B item #1, 2026-04-24). Same cardinality
// discipline as the divergence counter.
func TestCollector_CedarEnforcedLabels(t *testing.T) {
	c := NewCollector()
	if err := c.Register(); err != nil {
		t.Fatalf("register: %v", err)
	}
	c.RecordCedarEnforced("admin", "agree_allow")
	c.RecordCedarEnforced("admin", "agree_allow")
	c.RecordCedarEnforced("admin", "cedar_override_deny")
	c.RecordCedarEnforced("admin", "fallback_role")

	if got := testutil.ToFloat64(c.cedarEnforced.WithLabelValues("admin", "agree_allow")); got != 2 {
		t.Errorf("enforced counter for (admin, agree_allow) = %v, want 2", got)
	}
	if got := testutil.ToFloat64(c.cedarEnforced.WithLabelValues("admin", "cedar_override_deny")); got != 1 {
		t.Errorf("enforced counter for (admin, cedar_override_deny) = %v, want 1", got)
	}
	if got := testutil.ToFloat64(c.cedarEnforced.WithLabelValues("admin", "fallback_role")); got != 1 {
		t.Errorf("enforced counter for (admin, fallback_role) = %v, want 1", got)
	}
}

// TestCollector_Start_StopsCleanly verifies the ticker background goroutine
// exits when the stop callback is invoked.
func TestCollector_Start_StopsCleanly(t *testing.T) {
	c := NewCollector()
	if err := c.Register(); err != nil {
		t.Fatalf("register: %v", err)
	}
	stop := c.Start(10 * time.Millisecond)
	time.Sleep(25 * time.Millisecond)
	stop()
	// If Start leaked a goroutine, `go test -race` would eventually
	// flag it. The smoke-test here is that the stop call returns.
}
