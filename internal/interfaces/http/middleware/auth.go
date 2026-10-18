package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/orris-inc/orris/internal/application/admintoken/usecases"
	"github.com/orris-inc/orris/internal/domain/user"
	"github.com/orris-inc/orris/internal/infrastructure/auth"
	"github.com/orris-inc/orris/internal/infrastructure/token"
	"github.com/orris-inc/orris/internal/shared/authorization"
	"github.com/orris-inc/orris/internal/shared/config"
	"github.com/orris-inc/orris/internal/shared/constants"
	"github.com/orris-inc/orris/internal/shared/errors"
	"github.com/orris-inc/orris/internal/shared/logger"
	"github.com/orris-inc/orris/internal/shared/utils"
)

type AuthMiddleware struct {
	jwtService     *auth.JWTService
	userRepo       user.Repository
	sessionRepo    user.SessionRepository
	cookieConfig   config.CookieConfig
	adminTokenAuth AdminAPITokenAuthenticator
	logger         logger.Interface
}

func NewAuthMiddleware(jwtService *auth.JWTService, userRepo user.Repository, sessionRepo user.SessionRepository, cookieConfig config.CookieConfig, logger logger.Interface) *AuthMiddleware {
	return &AuthMiddleware{
		jwtService:   jwtService,
		userRepo:     userRepo,
		sessionRepo:  sessionRepo,
		cookieConfig: cookieConfig,
		logger:       logger,
	}
}

// SetAdminAPITokenAuthenticator wires the admin API token authenticator.
// Uses setter injection because the authenticator is built alongside the
// repositories that the middleware already depends on.
func (m *AuthMiddleware) SetAdminAPITokenAuthenticator(authenticator AdminAPITokenAuthenticator) {
	m.adminTokenAuth = authenticator
}

func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// An explicitly presented admin API token always wins, even when the client
		// also sent cookies. "orr_..." values are never parsed as JWTs; they are only
		// ever resolved against the admin_api_tokens table.
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			if parts := strings.SplitN(authHeader, " ", 2); len(parts) == 2 &&
				parts[0] == "Bearer" && token.IsAdminAPIToken(parts[1]) {
				m.authenticateAdminAPIToken(c, parts[1])
				return
			}
		}

		// Try to get token from cookie first
		rawToken := utils.GetTokenFromCookie(c, utils.AccessTokenCookie)

		// Fallback to Authorization header for backward compatibility
		if rawToken == "" {
			if authHeader == "" {
				utils.ErrorResponse(c, http.StatusUnauthorized, "missing authorization token")
				c.Abort()
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				utils.ErrorResponse(c, http.StatusUnauthorized, "invalid authorization header format")
				c.Abort()
				return
			}

			rawToken = parts[1]
		}

		m.authenticateJWT(c, rawToken)
	}
}

// authenticateJWT validates a JWT access token (from a cookie or a bearer header)
// and populates the request context.
func (m *AuthMiddleware) authenticateJWT(c *gin.Context, rawToken string) {
	claims, err := m.jwtService.Verify(rawToken)
	if err != nil {
		m.logger.Warnw("failed to verify token", "error", err)
		utils.ErrorResponse(c, http.StatusUnauthorized, "invalid or expired token")
		c.Abort()
		return
	}

	if claims.TokenType != auth.TokenTypeAccess {
		utils.ErrorResponse(c, http.StatusUnauthorized, "invalid token type")
		c.Abort()
		return
	}

	// Look up user by SID to get internal ID
	foundUser, err := m.userRepo.GetBySID(c.Request.Context(), claims.UserUUID)
	if err != nil || foundUser == nil {
		m.logger.Warnw("user not found by uuid", "user_uuid", claims.UserUUID, "error", err)
		utils.ErrorResponse(c, http.StatusUnauthorized, "user not found")
		c.Abort()
		return
	}

	// Re-check account status on every request so suspension/ban/deletion
	// takes effect immediately, even for an already-issued access token.
	if !foundUser.CanPerformActions() {
		m.logger.Warnw("rejecting request from user that cannot perform actions",
			"user_uuid", claims.UserUUID, "status", foundUser.Status())
		utils.ErrorResponse(c, http.StatusForbidden, "account is not active")
		c.Abort()
		return
	}

	c.Set(constants.ContextKeyUserID, foundUser.ID())
	c.Set("user_uuid", claims.UserUUID)
	c.Set("session_id", claims.SessionID)
	// Use the current role from database, not the stale role from JWT claims.
	// This ensures role changes (e.g. admin demotion) take effect immediately.
	c.Set(constants.ContextKeyUserRole, string(foundUser.Role()))
	c.Set(constants.ContextKeyAuthMethod, constants.AuthMethodSession)

	// Auto-refresh: if token is about to expire, generate a new one
	if m.jwtService.ShouldRefresh(claims) {
		m.refreshAccessToken(c, claims, foundUser.Role())
	}

	c.Next()
}

// authenticateAdminAPIToken validates an "orr_..." bearer token and populates the
// request context with the owning admin user. No cookies are issued or refreshed:
// API token authentication is stateless from the client's perspective.
func (m *AuthMiddleware) authenticateAdminAPIToken(c *gin.Context, plainToken string) {
	if m.adminTokenAuth == nil {
		m.logger.Errorw("admin API token authentication is not configured")
		utils.ErrorResponse(c, http.StatusUnauthorized, "invalid or expired token")
		c.Abort()
		return
	}

	identity, err := m.adminTokenAuth.Execute(c.Request.Context(), usecases.AuthenticateAdminAPITokenCommand{PlainToken: plainToken})
	if err != nil {
		// App errors carry the intended status (401 for bad credentials, 403 for an
		// inactive or demoted owner). Anything else is an infrastructure failure.
		status := http.StatusInternalServerError
		if appErr := errors.GetAppError(err); appErr != nil {
			status = appErr.Code
		}
		m.logger.Warnw("admin API token authentication failed",
			"ip", c.ClientIP(),
			"path", c.Request.URL.Path,
			"error", err,
		)
		utils.ErrorResponse(c, status, "invalid or expired token")
		c.Abort()
		return
	}
	if identity == nil || identity.User == nil {
		utils.ErrorResponse(c, http.StatusUnauthorized, "invalid or expired token")
		c.Abort()
		return
	}

	m.setAdminAPITokenContext(c, identity)
	c.Next()
}

// setAdminAPITokenContext records the API-token identity using the same context
// keys RequireAuth sets for session authentication.
func (m *AuthMiddleware) setAdminAPITokenContext(c *gin.Context, identity *usecases.AuthenticateAdminAPITokenResult) {
	owner := identity.User
	c.Set(constants.ContextKeyUserID, owner.ID())
	c.Set("user_uuid", owner.SID())
	c.Set(constants.ContextKeyUserRole, string(owner.Role()))
	c.Set(constants.ContextKeyAuthMethod, constants.AuthMethodAPIToken)
	c.Set(constants.ContextKeyAPITokenID, identity.TokenSID)
}

// refreshAccessToken generates a new access token and sets it in the cookie.
// freshRole is the user's current role from the database, ensuring the refreshed
// token reflects any role changes (e.g. demotion from admin).
func (m *AuthMiddleware) refreshAccessToken(c *gin.Context, claims *auth.Claims, freshRole authorization.UserRole) {
	// Do not silently renew a session that has been revoked (logout / logout-all /
	// password change) or has expired. Without this, auto-refresh would keep an
	// access token alive indefinitely and defeat session revocation.
	if claims.SessionID != "" {
		session, err := m.sessionRepo.GetByID(claims.SessionID)
		if err != nil || session == nil || session.IsExpired() {
			m.logger.Debugw("skipping auto-refresh: session revoked or expired",
				"user_uuid", claims.UserUUID, "session_id", claims.SessionID)
			return
		}
	}

	newToken, err := m.jwtService.RefreshAccessToken(claims, freshRole)
	if err != nil {
		m.logger.Warnw("failed to auto-refresh access token", "error", err, "user_uuid", claims.UserUUID)
		return
	}

	// Set the new access token in cookie
	accessMaxAge := m.jwtService.AccessExpMinutes() * 60
	utils.SetAccessTokenCookie(c, m.cookieConfig, newToken, accessMaxAge)

	// Refresh CSRF cookie alongside access token
	utils.SetCSRFCookie(c, m.cookieConfig, accessMaxAge)

	m.logger.Debugw("access token auto-refreshed", "user_uuid", claims.UserUUID)
}

func (m *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// An explicitly presented admin API token always wins, mirroring RequireAuth.
		authHeader := c.GetHeader("Authorization")
		if parts := strings.SplitN(authHeader, " ", 2); len(parts) == 2 &&
			parts[0] == "Bearer" && token.IsAdminAPIToken(parts[1]) {
			// API tokens are never JWTs. Resolve them (best effort) so
			// token-authenticated callers see the same identity, but let
			// unauthenticated requests continue when the token is invalid.
			if m.adminTokenAuth != nil {
				identity, err := m.adminTokenAuth.Execute(c.Request.Context(),
					usecases.AuthenticateAdminAPITokenCommand{PlainToken: parts[1]})
				if err == nil && identity != nil && identity.User != nil {
					m.setAdminAPITokenContext(c, identity)
				}
			}
			c.Next()
			return
		}

		// Try to get token from cookie first
		rawToken := utils.GetTokenFromCookie(c, utils.AccessTokenCookie)

		// Fallback to Authorization header for backward compatibility
		if rawToken == "" {
			if authHeader == "" {
				c.Next()
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && parts[0] == "Bearer" {
				rawToken = parts[1]
			} else {
				c.Next()
				return
			}
		}

		claims, err := m.jwtService.Verify(rawToken)
		if err == nil && claims.TokenType == auth.TokenTypeAccess {
			// Look up user by SID to get internal ID
			foundUser, lookupErr := m.userRepo.GetBySID(c.Request.Context(), claims.UserUUID)
			if lookupErr == nil && foundUser != nil && foundUser.CanPerformActions() {
				c.Set(constants.ContextKeyUserID, foundUser.ID())
				c.Set("user_uuid", claims.UserUUID)
				c.Set("session_id", claims.SessionID)
				// Use the current role from database, not the stale role from JWT claims.
				// This ensures role changes (e.g. admin demotion) take effect immediately.
				c.Set(constants.ContextKeyUserRole, string(foundUser.Role()))
				c.Set(constants.ContextKeyAuthMethod, constants.AuthMethodSession)
			}
		}

		c.Next()
	}
}
