package routes

import (
	"github.com/gin-gonic/gin"

	tokenHandlers "github.com/orris-inc/orris/internal/interfaces/http/handlers/admintoken"
	"github.com/orris-inc/orris/internal/interfaces/http/middleware"
	"github.com/orris-inc/orris/internal/shared/authorization"
)

// AdminAPITokenRouteConfig holds dependencies for admin API token routes.
type AdminAPITokenRouteConfig struct {
	AdminAPITokenHandler *tokenHandlers.Handler
	AuthMiddleware       *middleware.AuthMiddleware
}

// SetupAdminAPITokenRoutes configures admin API token management routes.
//
// Every route requires an interactive admin session: middleware.RequireSessionAuth rejects
// requests authenticated by an API token, so a leaked token cannot create,
// enumerate, or extend other tokens.
func SetupAdminAPITokenRoutes(engine *gin.Engine, cfg *AdminAPITokenRouteConfig) {
	if cfg.AdminAPITokenHandler == nil {
		return
	}

	apiTokens := engine.Group("/admin/api-tokens")
	apiTokens.Use(cfg.AuthMiddleware.RequireAuth(), authorization.RequireAdmin())
	apiTokens.Use(middleware.RequireSessionAuth())
	{
		apiTokens.POST("", cfg.AdminAPITokenHandler.CreateToken)
		apiTokens.GET("", cfg.AdminAPITokenHandler.ListTokens)
		apiTokens.GET("/:id", cfg.AdminAPITokenHandler.GetToken)
		apiTokens.POST("/:id/revoke", cfg.AdminAPITokenHandler.RevokeToken)
		apiTokens.DELETE("/:id", cfg.AdminAPITokenHandler.DeleteToken)
	}
}
