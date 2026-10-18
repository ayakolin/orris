package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/orris-inc/orris/internal/application/admintoken/testutil"
	"github.com/orris-inc/orris/internal/application/admintoken/usecases"
	"github.com/orris-inc/orris/internal/domain/admintoken"
	"github.com/orris-inc/orris/internal/domain/user"
	uvo "github.com/orris-inc/orris/internal/domain/user/valueobjects"
	"github.com/orris-inc/orris/internal/infrastructure/auth"
	"github.com/orris-inc/orris/internal/infrastructure/token"
	"github.com/orris-inc/orris/internal/shared/authorization"
	"github.com/orris-inc/orris/internal/shared/config"
	"github.com/orris-inc/orris/internal/shared/constants"
	"github.com/orris-inc/orris/internal/shared/id"
	"github.com/orris-inc/orris/internal/shared/logger"
)

// adminAuthUserRepo implements user.Repository for the JWT path of the auth
// middleware. Only GetBySID (JWT lookup) is exercised; the admin token path
// resolves owners through testutil.FakeUserRepository.GetByID instead.
type adminAuthUserRepo struct {
	user.Repository
	u *user.User
}

func (r *adminAuthUserRepo) GetBySID(_ context.Context, _ string) (*user.User, error) {
	return r.u, nil
}

func (r *adminAuthUserRepo) GetByID(_ context.Context, _ uint) (*user.User, error) {
	return r.u, nil
}

// adminTokenFixture wires the real auth middleware to the real
// AuthenticateAdminAPITokenUseCase backed by in-memory repositories, so every
// assertion exercises actual token hashing and validation.
type adminTokenFixture struct {
	middleware *AuthMiddleware
	jwtSvc     *auth.JWTService
	tokens     *testutil.FakeAdminAPITokenRepository
	users      *testutil.FakeUserRepository
	generator  *token.AdminAPITokenGenerator
	owner      *user.User
}

// newAdminUser reconstructs a user aggregate with the given role and status.
func newAdminUser(t *testing.T, userID uint, sid string, role authorization.UserRole, status uvo.Status) *user.User {
	t.Helper()
	email, err := uvo.NewEmail("admin@example.com")
	if err != nil {
		t.Fatalf("email: %v", err)
	}
	name, err := uvo.NewName("Admin User")
	if err != nil {
		t.Fatalf("name: %v", err)
	}
	now := time.Now().UTC()
	u, err := user.ReconstructUser(userID, sid, email, name, role, status, now, now, 1)
	if err != nil {
		t.Fatalf("reconstruct user: %v", err)
	}
	return u
}

func newAdminTokenFixture(t *testing.T) *adminTokenFixture {
	t.Helper()
	owner := newAdminUser(t, 7, "usr_admin0000001", authorization.RoleAdmin, uvo.StatusActive)

	tokenRepo := testutil.NewFakeAdminAPITokenRepository()
	userRepo := testutil.NewFakeUserRepository()
	userRepo.Add(owner)

	generator := token.NewAdminAPITokenGenerator()
	jwtSvc, err := auth.NewJWTService("test-secret", 15, 7, "debug")
	if err != nil {
		t.Fatalf("new jwt service: %v", err)
	}

	m := NewAuthMiddleware(jwtSvc, &adminAuthUserRepo{u: owner}, nil, config.CookieConfig{}, logger.NewLogger())
	m.SetAdminAPITokenAuthenticator(
		usecases.NewAuthenticateAdminAPITokenUseCase(tokenRepo, userRepo, generator, logger.NewLogger()),
	)

	return &adminTokenFixture{
		middleware: m,
		jwtSvc:     jwtSvc,
		tokens:     tokenRepo,
		users:      userRepo,
		generator:  generator,
		owner:      owner,
	}
}

// issueToken generates a real orr_ token and persists its hash for ownerID,
// returning the plaintext credential and the stored aggregate.
func (f *adminTokenFixture) issueToken(t *testing.T, ownerID uint, expiresAt *time.Time) (string, *admintoken.Token) {
	t.Helper()
	plain, hash, hint, err := f.generator.Generate()
	if err != nil {
		t.Fatalf("generate admin api token: %v", err)
	}
	stored, err := admintoken.NewToken("ci token", hash, hint, ownerID, expiresAt, id.NewAdminAPITokenID)
	if err != nil {
		t.Fatalf("new token: %v", err)
	}
	if err := f.tokens.Create(context.Background(), stored); err != nil {
		t.Fatalf("persist token: %v", err)
	}
	return plain, stored
}

// authOutcome captures the response status, whether the protected handler ran,
// and the request-context values the middleware populated.
type authOutcome struct {
	status     int
	handlerRan bool
	values     map[string]any
}

func (o authOutcome) has(key string) bool {
	_, ok := o.values[key]
	return ok
}

func (o authOutcome) value(key string) any {
	return o.values[key]
}

// runAuthMiddleware drives one request through the given middleware and a
// terminal handler using a real gin engine, so a 200 status proves the request
// was actually let through rather than being the recorder's default.
func runAuthMiddleware(t *testing.T, handler gin.HandlerFunc, req *http.Request) authOutcome {
	t.Helper()
	gin.SetMode(gin.TestMode)

	outcome := authOutcome{values: map[string]any{}}
	r := gin.New()
	r.Use(handler)
	r.GET("/", func(c *gin.Context) {
		outcome.handlerRan = true
		for _, key := range []string{
			constants.ContextKeyUserID,
			constants.ContextKeyUserRole,
			constants.ContextKeyAuthMethod,
			constants.ContextKeyAPITokenID,
			"session_id",
			"user_uuid",
		} {
			if v, ok := c.Get(key); ok {
				outcome.values[key] = v
			}
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	outcome.status = w.Code
	return outcome
}

func newBearerRequest(credential string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+credential)
	return req
}

// TestAdminAPITokenAuth_ValidToken asserts a real token authenticates as its
// admin owner with the API-token auth method and no session identity.
func TestAdminAPITokenAuth_ValidToken(t *testing.T) {
	f := newAdminTokenFixture(t)
	plain, stored := f.issueToken(t, f.owner.ID(), nil)

	out := runAuthMiddleware(t, f.middleware.RequireAuth(), newBearerRequest(plain))
	if out.status != http.StatusOK {
		t.Fatalf("expected 200 for valid API token, got %d", out.status)
	}
	if !out.handlerRan {
		t.Fatal("protected handler should run for a valid API token")
	}
	if got := out.value(constants.ContextKeyUserID); got != f.owner.ID() {
		t.Fatalf("expected user_id %v, got %v", f.owner.ID(), got)
	}
	if got := out.value(constants.ContextKeyUserRole); got != string(authorization.RoleAdmin) {
		t.Fatalf("expected user_role admin, got %v", got)
	}
	if got := out.value(constants.ContextKeyAuthMethod); got != constants.AuthMethodAPIToken {
		t.Fatalf("expected auth_method %q, got %v", constants.AuthMethodAPIToken, got)
	}
	if got := out.value(constants.ContextKeyAPITokenID); got != stored.SID() {
		t.Fatalf("expected api_token_id %q, got %v", stored.SID(), got)
	}
	if out.has("session_id") {
		t.Fatalf("API token authentication must not set session_id, got %v", out.value("session_id"))
	}
}

// TestAdminAPITokenAuth_RejectedCredentials covers revoked, expired, unknown and
// mismatched-hash tokens; all are indistinguishable to the caller (401).
func TestAdminAPITokenAuth_RejectedCredentials(t *testing.T) {
	t.Run("revoked", func(t *testing.T) {
		f := newAdminTokenFixture(t)
		plain, stored := f.issueToken(t, f.owner.ID(), nil)
		if _, err := f.tokens.Revoke(context.Background(), stored.ID(), time.Now().UTC()); err != nil {
			t.Fatalf("revoke token: %v", err)
		}

		out := runAuthMiddleware(t, f.middleware.RequireAuth(), newBearerRequest(plain))
		if out.status != http.StatusUnauthorized {
			t.Fatalf("expected 401 for revoked token, got %d", out.status)
		}
		if out.has(constants.ContextKeyUserID) {
			t.Fatalf("revoked token must not authenticate, got user_id %v", out.value(constants.ContextKeyUserID))
		}
	})

	t.Run("expired", func(t *testing.T) {
		f := newAdminTokenFixture(t)
		plain, _, hint, err := f.generator.Generate()
		if err != nil {
			t.Fatalf("generate admin api token: %v", err)
		}
		now := time.Now().UTC()
		expiredAt := now.Add(-time.Hour)
		// NewToken refuses to create an already-expired token, so rebuild it as
		// if it had been loaded from persistence.
		stored, err := admintoken.ReconstructToken(
			1, "apt_expired0001", "expired", f.generator.Hash(plain), hint,
			f.owner.ID(), nil, &expiredAt, nil, now.Add(-2*time.Hour), now.Add(-2*time.Hour),
		)
		if err != nil {
			t.Fatalf("reconstruct token: %v", err)
		}
		f.tokens.Add(stored)

		out := runAuthMiddleware(t, f.middleware.RequireAuth(), newBearerRequest(plain))
		if out.status != http.StatusUnauthorized {
			t.Fatalf("expected 401 for expired token, got %d", out.status)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		f := newAdminTokenFixture(t)
		plain, _, _, err := f.generator.Generate()
		if err != nil {
			t.Fatalf("generate admin api token: %v", err)
		}
		// Deliberately not persisted.

		out := runAuthMiddleware(t, f.middleware.RequireAuth(), newBearerRequest(plain))
		if out.status != http.StatusUnauthorized {
			t.Fatalf("expected 401 for unknown token, got %d", out.status)
		}
	})

	t.Run("hash belongs to different plaintext", func(t *testing.T) {
		f := newAdminTokenFixture(t)
		presented, _, _, err := f.generator.Generate()
		if err != nil {
			t.Fatalf("generate presented token: %v", err)
		}
		otherPlain, _, _, err := f.generator.Generate()
		if err != nil {
			t.Fatalf("generate stored token: %v", err)
		}
		stored, err := admintoken.NewToken(
			"mismatched", f.generator.Hash(otherPlain), "orr_other", f.owner.ID(), nil, id.NewAdminAPITokenID,
		)
		if err != nil {
			t.Fatalf("new token: %v", err)
		}
		if err := f.tokens.Create(context.Background(), stored); err != nil {
			t.Fatalf("persist token: %v", err)
		}

		out := runAuthMiddleware(t, f.middleware.RequireAuth(), newBearerRequest(presented))
		if out.status != http.StatusUnauthorized {
			t.Fatalf("expected 401 for mismatched hash, got %d", out.status)
		}
	})
}

// TestAdminAPITokenAuth_OwnerAuthorization covers the live owner checks applied
// on every request: demotion and suspension revoke access immediately.
func TestAdminAPITokenAuth_OwnerAuthorization(t *testing.T) {
	t.Run("demoted owner", func(t *testing.T) {
		f := newAdminTokenFixture(t)
		plain, _ := f.issueToken(t, f.owner.ID(), nil)
		f.users.Add(newAdminUser(t, f.owner.ID(), f.owner.SID(), authorization.RoleUser, uvo.StatusActive))

		out := runAuthMiddleware(t, f.middleware.RequireAuth(), newBearerRequest(plain))
		if out.status != http.StatusForbidden {
			t.Fatalf("expected 403 for demoted owner, got %d", out.status)
		}
		if out.has(constants.ContextKeyUserID) {
			t.Fatalf("demoted owner must not authenticate, got user_id %v", out.value(constants.ContextKeyUserID))
		}
	})

	t.Run("suspended owner", func(t *testing.T) {
		f := newAdminTokenFixture(t)
		plain, _ := f.issueToken(t, f.owner.ID(), nil)
		f.users.Add(newAdminUser(t, f.owner.ID(), f.owner.SID(), authorization.RoleAdmin, uvo.StatusSuspended))

		out := runAuthMiddleware(t, f.middleware.RequireAuth(), newBearerRequest(plain))
		if out.status != http.StatusForbidden {
			t.Fatalf("expected 403 for suspended owner, got %d", out.status)
		}
	})

	t.Run("missing owner", func(t *testing.T) {
		f := newAdminTokenFixture(t)
		// Token owned by an internal ID that has no user row.
		plain, _ := f.issueToken(t, 999, nil)

		out := runAuthMiddleware(t, f.middleware.RequireAuth(), newBearerRequest(plain))
		if out.status != http.StatusUnauthorized {
			t.Fatalf("expected 401 for missing owner, got %d", out.status)
		}
		if out.has(constants.ContextKeyUserID) {
			t.Fatalf("missing owner must not authenticate, got user_id %v", out.value(constants.ContextKeyUserID))
		}
	})
}

// TestAdminAPITokenAuth_NeverParsedAsJWT proves an orr_ value is routed only to
// the admin token use case: a validly signed JWT behind the prefix is rejected
// and never falls back to JWT verification.
func TestAdminAPITokenAuth_NeverParsedAsJWT(t *testing.T) {
	f := newAdminTokenFixture(t)
	pair, err := f.jwtSvc.Generate(f.owner.SID(), "sess_admin", authorization.RoleAdmin)
	if err != nil {
		t.Fatalf("generate jwt: %v", err)
	}

	out := runAuthMiddleware(t, f.middleware.RequireAuth(), newBearerRequest("orr_"+pair.AccessToken))
	if out.status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for orr_-prefixed JWT, got %d", out.status)
	}
	if out.has(constants.ContextKeyUserID) {
		t.Fatalf("orr_-prefixed JWT must not authenticate, got user_id %v", out.value(constants.ContextKeyUserID))
	}
	if out.has(constants.ContextKeyAuthMethod) {
		t.Fatalf("orr_-prefixed JWT must not set auth_method, got %v", out.value(constants.ContextKeyAuthMethod))
	}
}

// TestAdminAPITokenAuth_JWTBearerStillWorks guards the session path against
// regressions: a plain JWT bearer authenticates as a session.
func TestAdminAPITokenAuth_JWTBearerStillWorks(t *testing.T) {
	f := newAdminTokenFixture(t)
	pair, err := f.jwtSvc.Generate(f.owner.SID(), "sess_admin", authorization.RoleAdmin)
	if err != nil {
		t.Fatalf("generate jwt: %v", err)
	}

	out := runAuthMiddleware(t, f.middleware.RequireAuth(), newBearerRequest(pair.AccessToken))
	if out.status != http.StatusOK {
		t.Fatalf("expected 200 for valid JWT bearer, got %d", out.status)
	}
	if !out.handlerRan {
		t.Fatal("protected handler should run for a valid JWT bearer")
	}
	if got := out.value(constants.ContextKeyAuthMethod); got != constants.AuthMethodSession {
		t.Fatalf("expected auth_method %q, got %v", constants.AuthMethodSession, got)
	}
	if got := out.value("session_id"); got != "sess_admin" {
		t.Fatalf("expected session_id sess_admin, got %v", got)
	}
	if out.has(constants.ContextKeyAPITokenID) {
		t.Fatalf("JWT session must not set api_token_id, got %v", out.value(constants.ContextKeyAPITokenID))
	}
}

// TestAdminAPITokenAuth_CookieSessionUnchanged verifies cookie-based session
// authentication still works with no Authorization header.
func TestAdminAPITokenAuth_CookieSessionUnchanged(t *testing.T) {
	f := newAdminTokenFixture(t)
	pair, err := f.jwtSvc.Generate(f.owner.SID(), "sess_cookie", authorization.RoleAdmin)
	if err != nil {
		t.Fatalf("generate jwt: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: pair.AccessToken})

	out := runAuthMiddleware(t, f.middleware.RequireAuth(), req)
	if out.status != http.StatusOK {
		t.Fatalf("expected 200 for cookie session, got %d", out.status)
	}
	if !out.handlerRan {
		t.Fatal("protected handler should run for a cookie session")
	}
	if got := out.value(constants.ContextKeyAuthMethod); got != constants.AuthMethodSession {
		t.Fatalf("expected auth_method %q, got %v", constants.AuthMethodSession, got)
	}
	if got := out.value("session_id"); got != "sess_cookie" {
		t.Fatalf("expected session_id sess_cookie, got %v", got)
	}
}

// TestAdminAPITokenAuth_InvalidTokenDoesNotFallThrough ensures a bad orr_ bearer
// aborts with 401 even though a valid JWT would be accepted as a bearer
// credential; the API token path never re-interprets the value as a JWT.
func TestAdminAPITokenAuth_InvalidTokenDoesNotFallThrough(t *testing.T) {
	f := newAdminTokenFixture(t)
	pair, err := f.jwtSvc.Generate(f.owner.SID(), "sess_admin", authorization.RoleAdmin)
	if err != nil {
		t.Fatalf("generate jwt: %v", err)
	}

	out := runAuthMiddleware(t, f.middleware.RequireAuth(), newBearerRequest("orr_bogus"))
	if out.status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid api token, got %d", out.status)
	}
	if out.handlerRan {
		t.Fatal("protected handler must not run for an invalid api token")
	}
	if out.has(constants.ContextKeyUserID) {
		t.Fatalf("invalid api token must not authenticate, got user_id %v", out.value(constants.ContextKeyUserID))
	}

	// Sanity check that the credential the token path refuses is accepted when
	// presented as a session token.
	ok := runAuthMiddleware(t, f.middleware.RequireAuth(), newBearerRequest(pair.AccessToken))
	if ok.status != http.StatusOK {
		t.Fatalf("expected JWT bearer to still be accepted, got %d", ok.status)
	}
}

// TestOptionalAuth_AdminAPIToken covers the best-effort semantics of OptionalAuth
// for API tokens, invalid API tokens and JWT sessions.
func TestOptionalAuth_AdminAPIToken(t *testing.T) {
	t.Run("valid api token", func(t *testing.T) {
		f := newAdminTokenFixture(t)
		plain, stored := f.issueToken(t, f.owner.ID(), nil)

		out := runAuthMiddleware(t, f.middleware.OptionalAuth(), newBearerRequest(plain))
		if out.status != http.StatusOK {
			t.Fatalf("expected 200, got %d", out.status)
		}
		if got := out.value(constants.ContextKeyUserID); got != f.owner.ID() {
			t.Fatalf("expected user_id %v, got %v", f.owner.ID(), got)
		}
		if got := out.value(constants.ContextKeyAPITokenID); got != stored.SID() {
			t.Fatalf("expected api_token_id %q, got %v", stored.SID(), got)
		}
	})

	t.Run("invalid api token continues unauthenticated", func(t *testing.T) {
		f := newAdminTokenFixture(t)

		out := runAuthMiddleware(t, f.middleware.OptionalAuth(), newBearerRequest("orr_bogus"))
		if out.status != http.StatusOK {
			t.Fatalf("expected 200 without abort, got %d", out.status)
		}
		if !out.handlerRan {
			t.Fatal("OptionalAuth must not abort on an invalid api token")
		}
		if out.has(constants.ContextKeyUserID) {
			t.Fatalf("invalid api token must leave request unauthenticated, got user_id %v",
				out.value(constants.ContextKeyUserID))
		}
		if out.has(constants.ContextKeyAuthMethod) {
			t.Fatalf("invalid api token must not set auth_method, got %v", out.value(constants.ContextKeyAuthMethod))
		}
	})

	t.Run("valid jwt still sets session identity", func(t *testing.T) {
		f := newAdminTokenFixture(t)
		pair, err := f.jwtSvc.Generate(f.owner.SID(), "sess_optional", authorization.RoleAdmin)
		if err != nil {
			t.Fatalf("generate jwt: %v", err)
		}

		out := runAuthMiddleware(t, f.middleware.OptionalAuth(), newBearerRequest(pair.AccessToken))
		if out.status != http.StatusOK {
			t.Fatalf("expected 200, got %d", out.status)
		}
		if got := out.value(constants.ContextKeyUserID); got != f.owner.ID() {
			t.Fatalf("expected user_id %v, got %v", f.owner.ID(), got)
		}
		if got := out.value(constants.ContextKeyAuthMethod); got != constants.AuthMethodSession {
			t.Fatalf("expected auth_method %q, got %v", constants.AuthMethodSession, got)
		}
		if got := out.value("session_id"); got != "sess_optional" {
			t.Fatalf("expected session_id sess_optional, got %v", got)
		}
	})
}
