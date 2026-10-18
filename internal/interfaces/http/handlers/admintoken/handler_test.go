package tokens

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/orris-inc/orris/internal/application/admintoken/testutil"
	"github.com/orris-inc/orris/internal/application/admintoken/usecases"
	"github.com/orris-inc/orris/internal/domain/user"
	uvo "github.com/orris-inc/orris/internal/domain/user/valueobjects"
	"github.com/orris-inc/orris/internal/infrastructure/token"
	handlertestutil "github.com/orris-inc/orris/internal/interfaces/http/handlers/testutil"
	"github.com/orris-inc/orris/internal/interfaces/http/middleware"
	"github.com/orris-inc/orris/internal/shared/authorization"
	"github.com/orris-inc/orris/internal/shared/constants"
	sharederrors "github.com/orris-inc/orris/internal/shared/errors"
)

const (
	adminUserID  uint = 1
	otherUserID  uint = 2
	adminUserSID      = "usr_aaaaaaaaaaaa"
	otherUserSID      = "usr_bbbbbbbbbbbb"
)

// tokenEnv wires the real use cases to the in-memory fakes so the handler tests
// also prove the end-to-end create/list/revoke/delete behaviour.
type tokenEnv struct {
	handler *Handler
	tokens  *testutil.FakeAdminAPITokenRepository
	authUC  *usecases.AuthenticateAdminAPITokenUseCase
}

type createdToken struct {
	ID        string `json:"id"`
	Token     string `json:"token"`
	TokenHint string `json:"token_hint"`
	CreatedBy string `json:"created_by"`
}

func newAdminUser(t *testing.T, id uint, email, sid string) *user.User {
	t.Helper()

	emailVO, err := uvo.NewEmail(email)
	require.NoError(t, err)
	nameVO, err := uvo.NewName("Admin")
	require.NoError(t, err)

	u, err := user.NewUser(emailVO, nameVO, func() (string, error) { return sid, nil })
	require.NoError(t, err)
	require.NoError(t, u.SetID(id))
	u.SetRole(authorization.RoleAdmin)

	return u
}

func newTokenEnv(t *testing.T) *tokenEnv {
	t.Helper()

	tokenRepo := testutil.NewFakeAdminAPITokenRepository()
	userRepo := testutil.NewFakeUserRepository()
	userRepo.Add(newAdminUser(t, adminUserID, "admin@example.com", adminUserSID))
	userRepo.Add(newAdminUser(t, otherUserID, "other@example.com", otherUserSID))

	log := handlertestutil.NewMockLogger()
	generator := token.NewAdminAPITokenGenerator()

	handler := NewHandler(
		usecases.NewCreateAdminAPITokenUseCase(tokenRepo, userRepo, generator, log),
		usecases.NewListAdminAPITokensUseCase(tokenRepo, userRepo, log),
		usecases.NewGetAdminAPITokenUseCase(tokenRepo, userRepo, log),
		usecases.NewRevokeAdminAPITokenUseCase(tokenRepo, log),
		usecases.NewDeleteAdminAPITokenUseCase(tokenRepo, log),
		log,
	)

	return &tokenEnv{
		handler: handler,
		tokens:  tokenRepo,
		authUC:  usecases.NewAuthenticateAdminAPITokenUseCase(tokenRepo, userRepo, generator, log),
	}
}

// newTokenContext builds a gin context as the upstream auth middleware would:
// user_id set and auth_method defaulting to the interactive session.
func newTokenContext(method, path string, body any, userID uint) (*gin.Context, *httptest.ResponseRecorder) {
	c, w := handlertestutil.NewTestContext(method, path, body)
	if userID != 0 {
		handlertestutil.SetAuthContext(c, userID)
	}
	c.Set(constants.ContextKeyAuthMethod, constants.AuthMethodSession)
	return c, w
}

func createTokenViaHandler(t *testing.T, env *tokenEnv, userID uint, name string) *createdToken {
	t.Helper()

	c, w := newTokenContext(http.MethodPost, "/admin/api-tokens", map[string]string{"name": name}, userID)
	env.handler.CreateToken(c)

	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())

	var resp handlertestutil.APIResponse
	require.NoError(t, handlertestutil.ParseResponse(w, &resp))

	var created createdToken
	require.NoError(t, json.Unmarshal(resp.Data, &created))
	return &created
}

// =====================================================================
// CreateToken
// =====================================================================

func TestHandler_CreateToken_ReturnsTokenOnce(t *testing.T) {
	env := newTokenEnv(t)

	c, w := newTokenContext(http.MethodPost, "/admin/api-tokens", map[string]string{"name": "ops"}, adminUserID)
	env.handler.CreateToken(c)

	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())
	assert.False(t, strings.Contains(w.Body.String(), "token_hash"), "create response must not leak the hash")

	var resp handlertestutil.APIResponse
	require.NoError(t, handlertestutil.ParseResponse(w, &resp))
	assert.True(t, resp.Success)

	var created createdToken
	require.NoError(t, json.Unmarshal(resp.Data, &created))

	assert.True(t, strings.HasPrefix(created.Token, token.AdminAPITokenPrefix), "token = %q", created.Token)
	assert.True(t, strings.HasPrefix(created.ID, "apt_"), "id = %q", created.ID)
	assert.NotEmpty(t, created.TokenHint)
	assert.True(t, strings.HasPrefix(created.TokenHint, token.AdminAPITokenPrefix), "hint = %q", created.TokenHint)
	assert.Equal(t, adminUserSID, created.CreatedBy)
	assert.Contains(t, resp.Message, "will not be shown again")
}

func TestHandler_CreateToken_PlaintextTokenAuthenticates(t *testing.T) {
	env := newTokenEnv(t)
	created := createTokenViaHandler(t, env, adminUserID, "ops")

	result, err := env.authUC.Execute(context.Background(), usecases.AuthenticateAdminAPITokenCommand{
		PlainToken: created.Token,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, adminUserID, result.User.ID())
	assert.Equal(t, created.ID, result.TokenSID)
}

func TestHandler_CreateToken_EmptyNameRejected(t *testing.T) {
	env := newTokenEnv(t)

	c, w := newTokenContext(http.MethodPost, "/admin/api-tokens", map[string]string{"name": ""}, adminUserID)
	env.handler.CreateToken(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())

	var resp handlertestutil.APIResponse
	require.NoError(t, handlertestutil.ParseResponse(w, &resp))
	assert.False(t, resp.Success)
	require.NotNil(t, resp.Error)
	assert.Equal(t, string(sharederrors.ErrorTypeValidation), resp.Error.Type)
	assert.Empty(t, env.tokens.Tokens(), "no token must be persisted")
}

func TestHandler_CreateToken_PastExpiryRejected(t *testing.T) {
	env := newTokenEnv(t)

	body := map[string]any{
		"name":       "ops",
		"expires_at": time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	}
	c, w := newTokenContext(http.MethodPost, "/admin/api-tokens", body, adminUserID)
	env.handler.CreateToken(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())

	var resp handlertestutil.APIResponse
	require.NoError(t, handlertestutil.ParseResponse(w, &resp))
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "expires_at")
	assert.Empty(t, env.tokens.Tokens())
}

// =====================================================================
// ListTokens
// =====================================================================

func TestHandler_ListTokens_ScopedToCallerWithoutSecrets(t *testing.T) {
	env := newTokenEnv(t)

	createTokenViaHandler(t, env, adminUserID, "ops-1")
	createTokenViaHandler(t, env, adminUserID, "ops-2")
	otherToken := createTokenViaHandler(t, env, otherUserID, "other-ops")

	c, w := newTokenContext(http.MethodGet, "/admin/api-tokens", nil, adminUserID)
	env.handler.ListTokens(c)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	body := w.Body.String()
	assert.False(t, strings.Contains(body, `"token_hash"`), "list response must not leak hashes")
	assert.False(t, strings.Contains(body, `"token":`), "list response must not leak plaintext tokens")
	assert.False(t, strings.Contains(body, "other-ops"), "must not list another admin's token")

	var resp handlertestutil.APIResponse
	require.NoError(t, handlertestutil.ParseResponse(w, &resp))

	var tokens []struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		TokenHint string `json:"token_hint"`
		CreatedBy string `json:"created_by"`
	}
	require.NoError(t, json.Unmarshal(resp.Data, &tokens))

	require.Len(t, tokens, 2)
	names := make([]string, 0, len(tokens))
	ids := make([]string, 0, len(tokens))
	for _, tk := range tokens {
		names = append(names, tk.Name)
		ids = append(ids, tk.ID)
		assert.Equal(t, adminUserSID, tk.CreatedBy)
		assert.True(t, strings.HasPrefix(tk.ID, "apt_"))
		assert.NotEmpty(t, tk.TokenHint)
	}
	assert.ElementsMatch(t, []string{"ops-1", "ops-2"}, names)
	assert.NotContains(t, ids, otherToken.ID)
}

// =====================================================================
// GetToken
// =====================================================================

func TestHandler_GetToken_OwnToken(t *testing.T) {
	env := newTokenEnv(t)
	created := createTokenViaHandler(t, env, adminUserID, "ops")

	c, w := newTokenContext(http.MethodGet, "/admin/api-tokens/"+created.ID, nil, adminUserID)
	handlertestutil.SetURLParam(c, "id", created.ID)
	env.handler.GetToken(c)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp handlertestutil.APIResponse
	require.NoError(t, handlertestutil.ParseResponse(w, &resp))

	var got createdToken
	require.NoError(t, json.Unmarshal(resp.Data, &got))
	assert.Equal(t, created.ID, got.ID)
	assert.Empty(t, got.Token, "GET must never return the plaintext token")
	assert.False(t, strings.Contains(w.Body.String(), "token_hash"))
}

func TestHandler_GetToken_OtherOwnerNotFound(t *testing.T) {
	env := newTokenEnv(t)
	created := createTokenViaHandler(t, env, adminUserID, "ops")

	c, w := newTokenContext(http.MethodGet, "/admin/api-tokens/"+created.ID, nil, otherUserID)
	handlertestutil.SetURLParam(c, "id", created.ID)
	env.handler.GetToken(c)

	assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
}

func TestHandler_GetToken_MalformedID(t *testing.T) {
	env := newTokenEnv(t)

	c, w := newTokenContext(http.MethodGet, "/admin/api-tokens/not-an-id", nil, adminUserID)
	handlertestutil.SetURLParam(c, "id", "not-an-id")
	env.handler.GetToken(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
}

// =====================================================================
// RevokeToken
// =====================================================================

func TestHandler_RevokeToken_ThenAuthenticationFails(t *testing.T) {
	env := newTokenEnv(t)
	created := createTokenViaHandler(t, env, adminUserID, "ops")

	c, w := newTokenContext(http.MethodPost, "/admin/api-tokens/"+created.ID+"/revoke", nil, adminUserID)
	handlertestutil.SetURLParam(c, "id", created.ID)
	env.handler.RevokeToken(c)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	_, err := env.authUC.Execute(context.Background(), usecases.AuthenticateAdminAPITokenCommand{
		PlainToken: created.Token,
	})
	require.Error(t, err)
	appErr := sharederrors.GetAppError(err)
	require.NotNil(t, appErr)
	assert.Equal(t, http.StatusUnauthorized, appErr.Code)
}

func TestHandler_RevokeToken_IsIdempotent(t *testing.T) {
	env := newTokenEnv(t)
	created := createTokenViaHandler(t, env, adminUserID, "ops")

	for i := range 2 {
		c, w := newTokenContext(http.MethodPost, "/admin/api-tokens/"+created.ID+"/revoke", nil, adminUserID)
		handlertestutil.SetURLParam(c, "id", created.ID)
		env.handler.RevokeToken(c)
		assert.Equal(t, http.StatusOK, w.Code, "revoke #%d body: %s", i+1, w.Body.String())
	}
}

func TestHandler_RevokeToken_OtherOwnerNotFound(t *testing.T) {
	env := newTokenEnv(t)
	created := createTokenViaHandler(t, env, adminUserID, "ops")

	c, w := newTokenContext(http.MethodPost, "/admin/api-tokens/"+created.ID+"/revoke", nil, otherUserID)
	handlertestutil.SetURLParam(c, "id", created.ID)
	env.handler.RevokeToken(c)

	assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())

	// The token must remain usable: a foreign revoke attempt must not have an effect.
	_, err := env.authUC.Execute(context.Background(), usecases.AuthenticateAdminAPITokenCommand{
		PlainToken: created.Token,
	})
	require.NoError(t, err)
}

// =====================================================================
// DeleteToken
// =====================================================================

func TestHandler_DeleteToken_RemovesToken(t *testing.T) {
	env := newTokenEnv(t)
	created := createTokenViaHandler(t, env, adminUserID, "ops")

	c, w := newTokenContext(http.MethodDelete, "/admin/api-tokens/"+created.ID, nil, adminUserID)
	handlertestutil.SetURLParam(c, "id", created.ID)
	env.handler.DeleteToken(c)

	require.Equal(t, http.StatusNoContent, c.Writer.Status(), "body: %s", w.Body.String())

	stored, err := env.tokens.GetBySID(context.Background(), created.ID)
	require.NoError(t, err)
	assert.Nil(t, stored)

	_, err = env.authUC.Execute(context.Background(), usecases.AuthenticateAdminAPITokenCommand{
		PlainToken: created.Token,
	})
	require.Error(t, err)
}

func TestHandler_DeleteToken_OtherOwnerNotFound(t *testing.T) {
	env := newTokenEnv(t)
	created := createTokenViaHandler(t, env, adminUserID, "ops")

	c, w := newTokenContext(http.MethodDelete, "/admin/api-tokens/"+created.ID, nil, otherUserID)
	handlertestutil.SetURLParam(c, "id", created.ID)
	env.handler.DeleteToken(c)

	assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())

	stored, err := env.tokens.GetBySID(context.Background(), created.ID)
	require.NoError(t, err)
	assert.NotNil(t, stored, "another owner must not be able to delete the token")
}

// =====================================================================
// RequireSessionAuth (implemented in the middleware package)
// =====================================================================

func TestRequireSessionAuth_DirectInvocation(t *testing.T) {
	t.Run("api token is rejected", func(t *testing.T) {
		c, w := handlertestutil.NewTestContext(http.MethodGet, "/admin/api-tokens", nil)
		c.Set(constants.ContextKeyAuthMethod, constants.AuthMethodAPIToken)

		middleware.RequireSessionAuth()(c)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.True(t, c.IsAborted())

		var resp handlertestutil.APIResponse
		require.NoError(t, handlertestutil.ParseResponse(w, &resp))
		require.NotNil(t, resp.Error)
		assert.Contains(t, resp.Error.Message, "interactive session")
	})

	t.Run("session passes through", func(t *testing.T) {
		c, w := handlertestutil.NewTestContext(http.MethodGet, "/admin/api-tokens", nil)
		c.Set(constants.ContextKeyAuthMethod, constants.AuthMethodSession)

		middleware.RequireSessionAuth()(c)

		assert.False(t, c.IsAborted())
		assert.Empty(t, w.Body.String())
	})

	t.Run("missing auth method passes through", func(t *testing.T) {
		c, w := handlertestutil.NewTestContext(http.MethodGet, "/admin/api-tokens", nil)

		middleware.RequireSessionAuth()(c)

		assert.False(t, c.IsAborted())
		assert.Empty(t, w.Body.String())
	})
}

// newSessionGuardRouter builds a router containing only the token middleware, so
// every token-management route can be exercised without the full auth stack.
// The returned flag reports whether the wrapped handler was reached.
func newSessionGuardRouter(authMethod string) (*gin.Engine, *bool) {
	reached := false
	ok := func(c *gin.Context) {
		reached = true
		c.Status(http.StatusNoContent)
	}

	engine := gin.New()
	group := engine.Group("/admin/api-tokens")
	group.Use(func(c *gin.Context) {
		c.Set(constants.ContextKeyAuthMethod, authMethod)
		c.Set("user_id", adminUserID)
		c.Next()
	})
	group.Use(middleware.RequireSessionAuth())
	group.POST("", ok)
	group.GET("", ok)
	group.GET("/:id", ok)
	group.POST("/:id/revoke", ok)
	group.DELETE("/:id", ok)

	return engine, &reached
}

func TestRequireSessionAuth_RejectsAPITokenOnEveryRoute(t *testing.T) {
	routes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/admin/api-tokens"},
		{http.MethodGet, "/admin/api-tokens"},
		{http.MethodGet, "/admin/api-tokens/apt_abcdefghijkl"},
		{http.MethodPost, "/admin/api-tokens/apt_abcdefghijkl/revoke"},
		{http.MethodDelete, "/admin/api-tokens/apt_abcdefghijkl"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			engine, reached := newSessionGuardRouter(constants.AuthMethodAPIToken)
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, httptest.NewRequest(route.method, route.path, nil))

			assert.Equal(t, http.StatusForbidden, w.Code)
			assert.False(t, *reached, "handler must not run for an API-token caller")
		})
	}
}

func TestRequireSessionAuth_AllowsSessionOnEveryRoute(t *testing.T) {
	routes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/admin/api-tokens"},
		{http.MethodGet, "/admin/api-tokens"},
		{http.MethodGet, "/admin/api-tokens/apt_abcdefghijkl"},
		{http.MethodPost, "/admin/api-tokens/apt_abcdefghijkl/revoke"},
		{http.MethodDelete, "/admin/api-tokens/apt_abcdefghijkl"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			engine, reached := newSessionGuardRouter(constants.AuthMethodSession)
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, httptest.NewRequest(route.method, route.path, nil))

			assert.Equal(t, http.StatusNoContent, w.Code)
			assert.True(t, *reached)
		})
	}
}
