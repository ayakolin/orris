package routes

import (
	"testing"

	"github.com/gin-gonic/gin"

	adminAPITokenHandlers "github.com/orris-inc/orris/internal/interfaces/http/handlers/admintoken"
	forwardAgentAPIHandlers "github.com/orris-inc/orris/internal/interfaces/http/handlers/forward/agent/api"
	forwardAgentCrudHandlers "github.com/orris-inc/orris/internal/interfaces/http/handlers/forward/agent/crud"
	forwardAgentHubHandlers "github.com/orris-inc/orris/internal/interfaces/http/handlers/forward/agent/hub"
	forwardRuleHandlers "github.com/orris-inc/orris/internal/interfaces/http/handlers/forward/rule"
	forwardUserHandlers "github.com/orris-inc/orris/internal/interfaces/http/handlers/forward/user"
	"github.com/orris-inc/orris/internal/interfaces/http/middleware"
)

// registeredRoutes returns the full method+path set for an engine.
func registeredRoutes(engine *gin.Engine) map[string]bool {
	routes := make(map[string]bool, len(engine.Routes()))
	for _, route := range engine.Routes() {
		routes[route.Method+" "+route.Path] = true
	}
	return routes
}

// TestSetupForwardRoutes_RegistersRetargetBeforeParamRoutes guards the route
// ordering: gin panics at registration time when a static segment collides with
// an existing wildcard, so a conflicting "POST /forward-rules/:id" would take
// the whole server down at startup.
func TestSetupForwardRoutes_RegistersRetargetBeforeParamRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	// Handlers are not invoked here; only registration is under test.
	SetupForwardRoutes(engine, &ForwardRouteConfig{
		ForwardRuleHandler:     &forwardRuleHandlers.Handler{},
		ForwardAgentHandler:    &forwardAgentCrudHandlers.Handler{},
		ForwardAgentAPIHandler: &forwardAgentAPIHandlers.Handler{},
		ForwardAgentHubHandler: &forwardAgentHubHandlers.Handler{},
		UserForwardHandler:     &forwardUserHandlers.Handler{},
		AuthMiddleware:         &middleware.AuthMiddleware{},
	})

	routes := registeredRoutes(engine)
	for _, want := range []string{
		"POST /forward-rules/retarget",
		"POST /forward-rules/batch",
		"PATCH /forward-rules/batch",
		"PATCH /forward-rules/batch/status",
		"POST /forward-rules/:id/enable",
		"POST /forward-rules/:id/disable",
	} {
		if !routes[want] {
			t.Errorf("missing route %q", want)
		}
	}
	if routes["POST /forward-rules/:id"] {
		t.Error("unexpected POST /forward-rules/:id route: it would shadow the retarget endpoint")
	}
}

// TestSetupAdminAPITokenRoutes_RegistersAllEndpoints verifies the token
// management surface, including the revoke action that must not collide with
// the generic :id routes.
func TestSetupAdminAPITokenRoutes_RegistersAllEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	SetupAdminAPITokenRoutes(engine, &AdminAPITokenRouteConfig{
		AdminAPITokenHandler: &adminAPITokenHandlers.Handler{},
		AuthMiddleware:       &middleware.AuthMiddleware{},
	})

	routes := registeredRoutes(engine)
	for _, want := range []string{
		"POST /admin/api-tokens",
		"GET /admin/api-tokens",
		"GET /admin/api-tokens/:id",
		"POST /admin/api-tokens/:id/revoke",
		"DELETE /admin/api-tokens/:id",
	} {
		if !routes[want] {
			t.Errorf("missing route %q", want)
		}
	}
}

// TestSetupAdminAPITokenRoutes_NilHandlerSkipsRegistration keeps the router
// tolerant of a partially wired container.
func TestSetupAdminAPITokenRoutes_NilHandlerSkipsRegistration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	SetupAdminAPITokenRoutes(engine, &AdminAPITokenRouteConfig{
		AuthMiddleware: &middleware.AuthMiddleware{},
	})

	if len(engine.Routes()) != 0 {
		t.Fatalf("expected no routes without a handler, got %d", len(engine.Routes()))
	}
}
