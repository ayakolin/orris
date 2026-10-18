package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/orris-inc/orris/internal/shared/constants"
	"github.com/orris-inc/orris/internal/shared/utils"
)

// RequireSessionAuth rejects requests that were authenticated by an admin API
// token, leaving cookie/JWT sessions unaffected.
//
// It guards the credential- and account-management surface: admin API token
// management, passkey registration, profile and password changes, and admin user
// management. A leaked token therefore cannot mint new credentials, change a
// password, register a passkey, or alter roles to persist access beyond a
// revocation. Every other admin route stays available to tokens.
func RequireSessionAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetString(constants.ContextKeyAuthMethod) == constants.AuthMethodAPIToken {
			utils.ErrorResponse(c, http.StatusForbidden,
				"this endpoint requires an interactive session; admin API tokens cannot manage credentials")
			c.Abort()
			return
		}
		c.Next()
	}
}
