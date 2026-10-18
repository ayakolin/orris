package routes

import (
	"github.com/gin-gonic/gin"

	"github.com/orris-inc/orris/internal/interfaces/http/handlers"
	"github.com/orris-inc/orris/internal/interfaces/http/middleware"
	"github.com/orris-inc/orris/internal/shared/authorization"
)

// UserRouteConfig holds dependencies for user management routes.
type UserRouteConfig struct {
	UserHandler      *handlers.UserHandler
	ProfileHandler   *handlers.ProfileHandler
	DashboardHandler *handlers.DashboardHandler
	PasskeyHandler   *handlers.PasskeyHandler // may be nil if WebAuthn is not configured
	AuthMiddleware   *middleware.AuthMiddleware
}

// SetupUserRoutes configures user management routes.
func SetupUserRoutes(engine *gin.Engine, cfg *UserRouteConfig) {
	users := engine.Group("/users")
	users.Use(cfg.AuthMiddleware.RequireAuth())
	{
		// Collection operations (no ID parameter)
		// Creating a user is credential creation: interactive sessions only.
		users.POST("", authorization.RequireAdmin(), middleware.RequireSessionAuth(), cfg.UserHandler.CreateUser)
		users.GET("", authorization.RequireAdmin(), cfg.UserHandler.ListUsers)

		// Specific named endpoints (must come BEFORE /:id to avoid conflicts)
		// Profile/password/passkey changes are credential management: interactive
		// sessions only, so a leaked API token cannot persist access.
		users.PATCH("/me", middleware.RequireSessionAuth(), cfg.ProfileHandler.UpdateProfile)
		users.PUT("/me/password", middleware.RequireSessionAuth(), cfg.ProfileHandler.ChangePassword)
		users.GET("/me/dashboard", cfg.DashboardHandler.GetDashboard)

		// Passkey management routes
		if cfg.PasskeyHandler != nil {
			users.GET("/me/passkeys", middleware.RequireSessionAuth(), cfg.PasskeyHandler.ListPasskeys)
			users.DELETE("/me/passkeys/:id", middleware.RequireSessionAuth(), cfg.PasskeyHandler.DeletePasskey)
		}

		users.GET("/email/:email", authorization.RequireAdmin(), cfg.UserHandler.GetUserByEmail)

		// Generic parameterized routes (must come LAST)
		users.GET("/:id", authorization.RequireAdmin(), cfg.UserHandler.GetUser)
		users.PATCH("/:id", authorization.RequireAdmin(), middleware.RequireSessionAuth(), cfg.UserHandler.UpdateUser)
		users.DELETE("/:id", authorization.RequireAdmin(), middleware.RequireSessionAuth(), cfg.UserHandler.DeleteUser)
		users.PATCH("/:id/password", authorization.RequireAdmin(), middleware.RequireSessionAuth(), cfg.UserHandler.AdminResetPassword)
	}
}
