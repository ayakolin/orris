package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/orris-inc/orris/internal/domain/user"
	uvo "github.com/orris-inc/orris/internal/domain/user/valueobjects"
	"github.com/orris-inc/orris/internal/infrastructure/auth"
	"github.com/orris-inc/orris/internal/shared/authorization"
	"github.com/orris-inc/orris/internal/shared/config"
	"github.com/orris-inc/orris/internal/shared/logger"
)

// stubUserRepo implements user.Repository; only GetBySID is exercised.
type stubUserRepo struct {
	user.Repository
	u *user.User
}

func (s *stubUserRepo) GetBySID(_ context.Context, _ string) (*user.User, error) {
	return s.u, nil
}

func newTestUser(t *testing.T, status uvo.Status) *user.User {
	t.Helper()
	email, err := uvo.NewEmail("user@example.com")
	if err != nil {
		t.Fatalf("email: %v", err)
	}
	name, err := uvo.NewName("Test User")
	if err != nil {
		t.Fatalf("name: %v", err)
	}
	now := time.Now().UTC()
	u, err := user.ReconstructUser(1, "usr_abcdefghijkl", email, name, authorization.RoleUser, status, now, now, 1)
	if err != nil {
		t.Fatalf("reconstruct user: %v", err)
	}
	return u
}

func newAuthMiddlewareForTest(u *user.User) (*AuthMiddleware, *auth.JWTService) {
	jwtSvc, _ := auth.NewJWTService("test-secret", 15, 7, "debug")
	repo := &stubUserRepo{u: u}
	return NewAuthMiddleware(jwtSvc, repo, nil, config.CookieConfig{}, logger.NewLogger()), jwtSvc
}

func runRequireAuth(t *testing.T, m *AuthMiddleware, token string) int {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("Authorization", "Bearer "+token)
	m.RequireAuth()(c)
	return w.Code
}

// A suspended user must be rejected even with a validly-signed access token.
func TestRequireAuth_RejectsSuspendedUser(t *testing.T) {
	u := newTestUser(t, uvo.StatusSuspended)
	m, jwtSvc := newAuthMiddlewareForTest(u)
	pair, err := jwtSvc.Generate(u.SID(), "sess_1", authorization.RoleUser)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	if code := runRequireAuth(t, m, pair.AccessToken); code != http.StatusForbidden {
		t.Fatalf("expected 403 for suspended user, got %d", code)
	}
}

// An active user is allowed through.
func TestRequireAuth_AllowsActiveUser(t *testing.T) {
	u := newTestUser(t, uvo.StatusActive)
	m, jwtSvc := newAuthMiddlewareForTest(u)
	pair, err := jwtSvc.Generate(u.SID(), "sess_1", authorization.RoleUser)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	if code := runRequireAuth(t, m, pair.AccessToken); code != http.StatusOK {
		t.Fatalf("expected 200 for active user, got %d", code)
	}
}
