// Package modulegate provides the runtime-disable HTTP gate that wraps
// every non-core module's routes. When a module is toggled off at
// /admin/modules its routes return 503 instead of 404 so clients learn
// the surface still exists but is currently unavailable.
//
// Lives in the SDK so extracted addons can wrap their own routes with
// the gate without importing backend-internal middleware.
package modulegate

import (
	"context"
	"encoding/json"
	"net/http"
)

// ModuleEnabledChecker is satisfied by the SDK's ModuleConfigService.
// Declared here as an interface so this package has zero dependency on
// pkg/sdk/module — extracted addons that wrap a route with the gate
// only need the four-method handler shape, not the full registry.
type ModuleEnabledChecker interface {
	IsEnabled(ctx context.Context, moduleName string) bool
}

// ModuleGate returns middleware that rejects requests with 503 Service
// Unavailable when the named module is disabled at runtime. Applied to
// non-core modules only; core modules cannot be toggled off so the gate
// is omitted from their route registrations.
func ModuleGate(checker ModuleEnabledChecker, moduleName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !checker.IsEnabled(r.Context(), moduleName) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":  "module_disabled",
					"module": moduleName,
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
