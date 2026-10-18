package routes

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	adminTokenTestutil "github.com/orris-inc/orris/internal/application/admintoken/testutil"
	adminTokenUC "github.com/orris-inc/orris/internal/application/admintoken/usecases"
	"github.com/orris-inc/orris/internal/domain/admintoken"
	"github.com/orris-inc/orris/internal/domain/user"
	uvo "github.com/orris-inc/orris/internal/domain/user/valueobjects"
	infraAuth "github.com/orris-inc/orris/internal/infrastructure/auth"
	"github.com/orris-inc/orris/internal/infrastructure/token"
	"github.com/orris-inc/orris/internal/interfaces/http/handlers"
	"github.com/orris-inc/orris/internal/interfaces/http/middleware"
	"github.com/orris-inc/orris/internal/shared/authorization"
	"github.com/orris-inc/orris/internal/shared/config"
	"github.com/orris-inc/orris/internal/shared/id"
	"github.com/orris-inc/orris/internal/shared/logger"
	"github.com/orris-inc/orris/internal/shared/utils"
)

// credentialGuardMessage is the distinctive half of the 403 body emitted by
// middleware.RequireSessionAuth. It is matched as a substring so the assertion
// does not depend on the exact wrapping of the JSON error envelope.
const credentialGuardMessage = "interactive session"

// credentialGuardedRoute is one credential-management endpoint that an admin API
// token must never reach.
type credentialGuardedRoute struct {
	name   string
	method string
	path   string
	body   string
}

// credentialGuardedRoutes is the full guarded surface: passkey registration,
// user creation, self-service profile/password/passkey management, and admin
// user mutations. Keep it in sync with the RequireSessionAuth wiring in
// authroutes.go and userroutes.go.
var credentialGuardedRoutes = []credentialGuardedRoute{
	{"passkey register start", http.MethodPost, "/auth/passkey/register/start", ""},
	{"passkey register finish", http.MethodPost, "/auth/passkey/register/finish", `{}`},
	{"create user", http.MethodPost, "/users", `{}`},
	{"update own profile", http.MethodPatch, "/users/me", `{}`},
	{"change own password", http.MethodPut, "/users/me/password", `{}`},
	{"list own passkeys", http.MethodGet, "/users/me/passkeys", ""},
	{"delete own passkey", http.MethodDelete, "/users/me/passkeys/pk_abcdefghijkl", ""},
	{"update user", http.MethodPatch, "/users/usr_abcdefghijkl", `{}`},
	{"delete user", http.MethodDelete, "/users/usr_abcdefghijkl", ""},
	{"reset user password", http.MethodPatch, "/users/usr_abcdefghijkl/password", `{}`},
}

// credentialReadOnlyRoute is a route that stays usable with an admin API token.
// None of these mint or modify credentials, so RequireSessionAuth must not fire.
type credentialReadOnlyRoute struct {
	name   string
	method string
	path   string
}

var credentialReadOnlyRoutes = []credentialReadOnlyRoute{
	{"list users", http.MethodGet, "/users"},
	{"get user", http.MethodGet, "/users/usr_abcdefghijkl"},
	{"get user by email", http.MethodGet, "/users/email/admin@example.com"},
	{"dashboard", http.MethodGet, "/users/me/dashboard"},
	{"current user", http.MethodGet, "/auth/me"},
}

// credentialTestEnv drives the REAL route wiring (SetupUserRoutes and
// SetupAuthRoutes) with real authentication middleware. RequireAuth is not
// bypassed or stubbed: an admin API token authenticates through
// AuthenticateAdminAPITokenUseCase backed by in-memory fakes, and a session
// request carries a JWT signed by the same JWT service. That way the tests
// cover the production ordering (RequireAuth -> RequireAdmin -> RequireSessionAuth
// -> handler) instead of a hand-rolled replica of it.
//
// Handlers are constructed without their service dependencies because only the
// middleware chain is under test; the requests below either fail request binding
// before a dependency is touched, or hit a nil dependency. A recovery shim
// installed ahead of the route setup converts such a panic into 501, so the
// tables can assert "the guard did not fire" without asserting an exact status
// (a real status would need the full service graph).
type credentialTestEnv struct {
	engine        *gin.Engine
	apiToken      string
	sessionCookie *http.Cookie
}

// credentialTestUserRepo satisfies the Repository interface for the JWT lookup
// path. Only the two lookups the middleware and GET /auth/me use are overridden;
// embedding the interface keeps the rest unimplemented (and unreachable).
type credentialTestUserRepo struct {
	user.Repository
	u *user.User
}

func (r *credentialTestUserRepo) GetBySID(context.Context, string) (*user.User, error) {
	return r.u, nil
}

func (r *credentialTestUserRepo) GetByID(context.Context, uint) (*user.User, error) {
	return r.u, nil
}

// terminalStubRecovery converts a panic from an unwired handler dependency into
// a bare 501 response. It stands in for the production Recovery middleware so a
// nil use case is reported as "reached the handler, could not execute" rather
// than crashing the test binary.
func terminalStubRecovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if recovered := recover(); recovered != nil {
				c.AbortWithStatus(http.StatusNotImplemented)
			}
		}()
		c.Next()
	}
}

func newCredentialTestEnv(t *testing.T) *credentialTestEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	log := logger.NewLoggerWithSlog(slog.New(slog.NewTextHandler(io.Discard, nil)))

	email, err := uvo.NewEmail("admin@example.com")
	require.NoError(t, err)
	name, err := uvo.NewName("Route Admin")
	require.NoError(t, err)
	now := time.Now().UTC()
	owner, err := user.ReconstructUser(7, "usr_abcdefghijkl", email, name,
		authorization.RoleAdmin, uvo.StatusActive, now, now, 1)
	require.NoError(t, err)

	// Admin API token stack: one stored token owned by an active admin.
	tokenRepo := adminTokenTestutil.NewFakeAdminAPITokenRepository()
	tokenUserRepo := adminTokenTestutil.NewFakeUserRepository()
	tokenUserRepo.Add(owner)

	generator := token.NewAdminAPITokenGenerator()
	plainToken, tokenHash, tokenHint, err := generator.Generate()
	require.NoError(t, err)
	storedToken, err := admintoken.NewToken("credential-routes", tokenHash, tokenHint,
		owner.ID(), nil, id.NewAdminAPITokenID)
	require.NoError(t, err)
	require.NoError(t, tokenRepo.Create(context.Background(), storedToken))

	jwtSvc, err := infraAuth.NewJWTService("credential-route-test-secret", 15, 7, "debug")
	require.NoError(t, err)

	// The JWT path looks the user up by SID and re-reads the role from the
	// database; credentialTestUserRepo serves both lookups from this admin.
	authMiddleware := middleware.NewAuthMiddleware(jwtSvc, &credentialTestUserRepo{u: owner}, nil,
		config.CookieConfig{}, log)
	authMiddleware.SetAdminAPITokenAuthenticator(
		adminTokenUC.NewAuthenticateAdminAPITokenUseCase(tokenRepo, tokenUserRepo, generator, log),
	)

	pair, err := jwtSvc.Generate(owner.SID(), "sess_credential_routes", authorization.RoleAdmin)
	require.NoError(t, err)

	// Handlers deliberately have nil services: the guard decides the outcome on
	// the rejected paths, and the recovery shim handles the allowed paths.
	passkeyHandler := &handlers.PasskeyHandler{}
	userHandler := &handlers.UserHandler{}
	profileHandler := &handlers.ProfileHandler{}
	dashboardHandler := &handlers.DashboardHandler{}

	engine := gin.New()
	engine.Use(terminalStubRecovery())

	SetupUserRoutes(engine, &UserRouteConfig{
		UserHandler:      userHandler,
		ProfileHandler:   profileHandler,
		DashboardHandler: dashboardHandler,
		PasskeyHandler:   passkeyHandler,
		AuthMiddleware:   authMiddleware,
	})
	SetupAuthRoutes(engine, &AuthRouteConfig{
		// Only GET /auth/me is exercised, which needs userRepo and nothing else.
		AuthHandler: handlers.NewAuthHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil,
			&credentialTestUserRepo{u: owner}, config.CookieConfig{}, config.JWTConfig{},
			config.SessionConfig{}, "", nil, nil, log),
		PasskeyHandler: passkeyHandler,
		AuthMiddleware: authMiddleware,
		// The limiter only hands back a closure at registration time; these tests
		// never call a rate-limited route, so no Redis client is needed.
		RateLimiter: middleware.NewRateLimiter(nil, 100, time.Minute),
	})

	return &credentialTestEnv{
		engine:        engine,
		apiToken:      plainToken,
		sessionCookie: &http.Cookie{Name: utils.AccessTokenCookie, Value: pair.AccessToken},
	}
}

// do issues one request as either an admin API token client or a session client.
func (e *credentialTestEnv) do(method, path, body string, withAPIToken bool) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if withAPIToken {
		req.Header.Set("Authorization", "Bearer "+e.apiToken)
	} else {
		req.AddCookie(e.sessionCookie)
	}
	rec := httptest.NewRecorder()
	e.engine.ServeHTTP(rec, req)
	return rec
}

// TestCredentialRoutes_AdminAPITokenRejected proves every credential-management
// endpoint refuses an admin API token with 403 and the interactive-session
// explanation, before any handler body runs.
func TestCredentialRoutes_AdminAPITokenRejected(t *testing.T) {
	env := newCredentialTestEnv(t)

	for _, route := range credentialGuardedRoutes {
		t.Run(route.name, func(t *testing.T) {
			rec := env.do(route.method, route.path, route.body, true)

			require.Equal(t, http.StatusForbidden, rec.Code,
				"%s %s must reject an admin API token: %s", route.method, route.path, rec.Body.String())
			require.Contains(t, rec.Body.String(), credentialGuardMessage,
				"%s %s must explain that an interactive session is required", route.method, route.path)
		})
	}
}

// TestCredentialRoutes_SessionAllowed proves the same endpoints still work for an
// interactive admin session, i.e. the guard keys off the authentication method
// and not the route.
//
// No exact status is asserted: the handlers are wired without their services, so
// an allowed request ends in a binding error (400) or in the recovery shim's 501.
// The contract under test is only that the request was not stopped by the
// credential guard.
func TestCredentialRoutes_SessionAllowed(t *testing.T) {
	env := newCredentialTestEnv(t)

	for _, route := range credentialGuardedRoutes {
		t.Run(route.name, func(t *testing.T) {
			rec := env.do(route.method, route.path, route.body, false)

			require.NotEqual(t, http.StatusForbidden, rec.Code,
				"%s %s must not be forbidden for an admin session: %s", route.method, route.path, rec.Body.String())
			require.NotContains(t, rec.Body.String(), credentialGuardMessage,
				"%s %s must not report the credential guard: %s", route.method, route.path, rec.Body.String())
		})
	}
}

// TestCredentialRoutes_ReadOnlyRoutesAllowAPIToken is the negative control: the
// read-only user/auth endpoints stay reachable with an admin API token, so the
// guard was not applied too broadly. The handler itself may still fail (401/500)
// because its services are unwired; what matters is that the failure is not the
// credential guard's.
func TestCredentialRoutes_ReadOnlyRoutesAllowAPIToken(t *testing.T) {
	env := newCredentialTestEnv(t)

	for _, route := range credentialReadOnlyRoutes {
		t.Run(route.name, func(t *testing.T) {
			rec := env.do(route.method, route.path, "", true)

			require.NotContains(t, rec.Body.String(), credentialGuardMessage,
				"%s %s must stay usable with an admin API token: %s", route.method, route.path, rec.Body.String())
			if rec.Code == http.StatusForbidden {
				t.Fatalf("%s %s must not be forbidden for an admin API token: %s",
					route.method, route.path, rec.Body.String())
			}
		})
	}
}
