package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/orris-inc/orris/internal/infrastructure/token"
	"github.com/orris-inc/orris/internal/shared/utils"
)

// csrfExactPaths lists exact paths exempt from CSRF validation.
// These are unauthenticated endpoints with no cookie session to protect.
var csrfExactPaths = map[string]struct{}{
	"/auth/login":           {},
	"/auth/register":        {},
	"/auth/verify-email":    {},
	"/auth/forgot-password": {},
	"/auth/reset-password":  {},
	"/auth/refresh":         {},
	// Logout is exempt because the CSRF cookie may have expired alongside the access token.
	// It is already protected by RequireAuth middleware.
	"/auth/logout":       {},
	"/payments/callback": {},
}

// csrfPrefixPaths lists path prefixes exempt from CSRF validation.
// These are directory-style paths for OAuth flows, webhooks, or machine-to-machine APIs.
var csrfPrefixPaths = []string{
	"/auth/oauth/",
	"/auth/passkey/login/",
	"/auth/passkey/signup/",
	"/webhooks/",
	// Machine-to-machine APIs (token-header authenticated, not cookie-based)
	"/agents/",
	"/forward-agent-api/",
	"/ws/",
}

// CSRF returns a middleware that validates CSRF tokens using the Double Submit Cookie pattern.
// For mutating requests (POST, PUT, DELETE, PATCH), it compares the csrf_token cookie value
// against the X-CSRF-Token header value. Safe methods (GET, HEAD, OPTIONS) are always skipped.
func CSRF() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip safe HTTP methods
		if isSafeMethod(c.Request.Method) {
			c.Next()
			return
		}

		// Skip exempt paths (exact match first, then prefix match)
		path := c.Request.URL.Path
		if _, ok := csrfExactPaths[path]; ok {
			c.Next()
			return
		}
		for _, prefix := range csrfPrefixPaths {
			if strings.HasPrefix(path, prefix) {
				c.Next()
				return
			}
		}

		// Skip the CSRF check for requests that are authenticated solely by an admin
		// API token (Authorization: Bearer orr_...) and carry no auth cookies.
		//
		// Why this is safe:
		//   - A browser performing a cross-site request always attaches the target
		//     site's cookies. If either auth cookie is present we fall through to the
		//     normal double-submit check, so cookie sessions keep their protection.
		//   - A request without auth cookies cannot be forged into an authenticated
		//     action: the credential has to be supplied explicitly by the caller.
		//   - This middleware runs before RequireAuth, so the skip is based on the
		//     request shape only. RequireAuth still fully validates the token (hash
		//     lookup, revocation, expiry, active admin owner) and returns 401 for an
		//     invalid one; the skip never authenticates anything by itself.
		if isCookieLessAdminAPITokenRequest(c) {
			c.Next()
			return
		}

		// Read CSRF token from cookie
		cookieToken, err := c.Cookie(utils.CSRFTokenCookie)
		if err != nil || cookieToken == "" {
			utils.ErrorResponse(c, http.StatusForbidden, "missing CSRF token")
			c.Abort()
			return
		}

		// Read CSRF token from header
		headerToken := c.GetHeader(utils.CSRFTokenHeader)
		if headerToken == "" {
			utils.ErrorResponse(c, http.StatusForbidden, "missing CSRF token header")
			c.Abort()
			return
		}

		// Constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(cookieToken), []byte(headerToken)) != 1 {
			utils.ErrorResponse(c, http.StatusForbidden, "invalid CSRF token")
			c.Abort()
			return
		}

		c.Next()
	}
}

// isCookieLessAdminAPITokenRequest reports whether the request presents an admin
// API token as its bearer credential and carries no session cookies.
func isCookieLessAdminAPITokenRequest(c *gin.Context) bool {
	bearer, ok := bearerCredential(c)
	if !ok || !token.IsAdminAPIToken(bearer) {
		return false
	}
	return !hasAuthCookie(c)
}

// bearerCredential extracts the credential from an "Authorization: Bearer ..." header.
// The scheme match is exact ("Bearer"), matching RequireAuth: a value this function
// rejects is still fully parsed by RequireAuth, so the two cannot disagree about
// which requests are bearer-authenticated.
func bearerCredential(c *gin.Context) (string, bool) {
	parts := strings.SplitN(c.GetHeader("Authorization"), " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

// hasAuthCookie reports whether the request carries an access or refresh token cookie.
func hasAuthCookie(c *gin.Context) bool {
	if v, err := c.Cookie(utils.AccessTokenCookie); err == nil && v != "" {
		return true
	}
	if v, err := c.Cookie(utils.RefreshTokenCookie); err == nil && v != "" {
		return true
	}
	return false
}

// isSafeMethod returns true for HTTP methods that do not mutate state.
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}
