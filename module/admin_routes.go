package module

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// RegisterAdminModuleRoutes registers the module management admin API.
// Should be called on a protected Huma API with administrator role guard.
// This is the legacy entry point kept for callers that don't care about
// MFA-splitting their route surface — it registers reads and mutations on
// the same API. New call sites should use the two helper methods below.
func RegisterAdminModuleRoutes(api huma.API, handler *ModuleAdminHandler) {
	RegisterAdminModuleReadRoutes(api, handler)
	RegisterAdminModuleMutationRoutes(api, handler)
}

// RegisterAdminModuleReadRoutes registers the read-only module admin routes.
// Safe to mount behind RequireSystemPermission alone — no privilege change.
func RegisterAdminModuleReadRoutes(api huma.API, handler *ModuleAdminHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "list-modules",
		Method:      http.MethodGet,
		Path:        "/v1/admin/modules",
		Summary:     "List all modules",
		Description: "Returns all registered modules with their configuration and status",
		Tags:        []string{"Admin - Modules"},
		Security:    []map[string][]string{{"bearerAuth": {}}},
	}, handler.ListModules)

	huma.Register(api, huma.Operation{
		OperationID: "get-module",
		Method:      http.MethodGet,
		Path:        "/v1/admin/modules/{name}",
		Summary:     "Get module configuration",
		Description: "Returns a single module's configuration. Secrets are never returned, only indicators of whether values are stored.",
		Tags:        []string{"Admin - Modules"},
		Security:    []map[string][]string{{"bearerAuth": {}}},
	}, handler.GetModule)

	huma.Register(api, huma.Operation{
		OperationID: "modules-health",
		Method:      http.MethodGet,
		Path:        "/v1/admin/modules/health",
		Summary:     "Check module health",
		Description: "Runs health checks on all registered modules and returns per-module status.",
		Tags:        []string{"Admin - Modules"},
		Security:    []map[string][]string{{"bearerAuth": {}}},
	}, handler.HealthCheck)

	huma.Register(api, huma.Operation{
		OperationID: "list-module-environments",
		Method:      http.MethodGet,
		Path:        "/v1/admin/modules/{name}/environments",
		Summary:     "List module environments",
		Description: "Returns available environments and the active environment for a module.",
		Tags:        []string{"Admin - Modules"},
		Security:    []map[string][]string{{"bearerAuth": {}}},
	}, handler.ListEnvironments)

	huma.Register(api, huma.Operation{
		OperationID: "get-module-environment",
		Method:      http.MethodGet,
		Path:        "/v1/admin/modules/{name}/environments/{env}",
		Summary:     "Get environment config",
		Description: "Returns config values and secret status for a specific environment.",
		Tags:        []string{"Admin - Modules"},
		Security:    []map[string][]string{{"bearerAuth": {}}},
	}, handler.GetEnvironment)
}

// RegisterAdminModuleMutationRoutes registers the mutation admin routes.
// These can write secrets and flip module enablement, so Block B mounts
// them behind an additional RequireMFA gate — a stolen pwd-only token
// should not be able to write API keys or disable billing.
func RegisterAdminModuleMutationRoutes(api huma.API, handler *ModuleAdminHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "update-module",
		Method:      http.MethodPatch,
		Path:        "/v1/admin/modules/{name}",
		Summary:     "Update module configuration",
		Description: "Enable/disable a module and update its configuration. Core modules cannot be disabled. Secret values are encrypted before storage.",
		Tags:        []string{"Admin - Modules"},
		Security:    []map[string][]string{{"bearerAuth": {}}},
	}, handler.UpdateModule)

	huma.Register(api, huma.Operation{
		OperationID: "update-module-environment",
		Method:      http.MethodPatch,
		Path:        "/v1/admin/modules/{name}/environments/{env}",
		Summary:     "Update environment config",
		Description: "Updates config values and secrets for a specific environment. Values are merged with existing config.",
		Tags:        []string{"Admin - Modules"},
		Security:    []map[string][]string{{"bearerAuth": {}}},
	}, handler.UpdateEnvironment)

	huma.Register(api, huma.Operation{
		OperationID: "set-active-environment",
		Method:      http.MethodPut,
		Path:        "/v1/admin/modules/{name}/active-environment",
		Summary:     "Set active environment",
		Description: "Switches the active configuration environment for a module. The module will use the selected environment's config values at runtime (after restart).",
		Tags:        []string{"Admin - Modules"},
		Security:    []map[string][]string{{"bearerAuth": {}}},
	}, handler.SetActiveEnvironment)
}
