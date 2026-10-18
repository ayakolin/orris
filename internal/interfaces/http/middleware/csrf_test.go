package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/orris-inc/orris/internal/shared/utils"
)

// csrfCase describes one CSRF middleware scenario.
type csrfCase struct {
	name       string
	method     string
	path       string
	authHeader string
	cookies    []*http.Cookie
	csrfHeader string
	wantStatus int
	wantHandle bool
}

// runCSRFCase executes a request through CSRF() followed by a terminal handler.
// It returns the response status and whether the terminal handler ran.
func runCSRFCase(t *testing.T, tc csrfCase) (int, bool) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	handled := false
	r := gin.New()
	r.Use(CSRF())
	r.Any("/*path", func(c *gin.Context) {
		handled = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(tc.method, tc.path, nil)
	if tc.authHeader != "" {
		req.Header.Set("Authorization", tc.authHeader)
	}
	if tc.csrfHeader != "" {
		req.Header.Set(utils.CSRFTokenHeader, tc.csrfHeader)
	}
	for _, cookie := range tc.cookies {
		req.AddCookie(cookie)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code, handled
}

func assertCSRFCase(t *testing.T, tc csrfCase) {
	t.Helper()
	status, handled := runCSRFCase(t, tc)
	if status != tc.wantStatus {
		t.Fatalf("%s: expected status %d, got %d", tc.name, tc.wantStatus, status)
	}
	if handled != tc.wantHandle {
		t.Fatalf("%s: expected handler ran=%v, got %v", tc.name, tc.wantHandle, handled)
	}
}

func csrfCookie(value string) *http.Cookie {
	return &http.Cookie{Name: utils.CSRFTokenCookie, Value: value}
}

func authCookie(name, value string) *http.Cookie {
	return &http.Cookie{Name: name, Value: value}
}

// TestCSRF_Matrix covers the full skip/validate decision matrix.
func TestCSRF_Matrix(t *testing.T) {
	const (
		protectedPath = "/api/items"
		adminBearer   = "Bearer orr_abc"
	)

	cases := []csrfCase{
		// 1. Cookie-less admin API token is skipped entirely.
		{
			name:       "admin token without cookies skips",
			method:     http.MethodPost,
			path:       protectedPath,
			authHeader: adminBearer,
			wantStatus: http.StatusOK,
			wantHandle: true,
		},
		// 2. Any auth cookie disables the skip.
		{
			name:       "admin token with access cookie is still checked",
			method:     http.MethodPost,
			path:       protectedPath,
			authHeader: adminBearer,
			cookies:    []*http.Cookie{authCookie(utils.AccessTokenCookie, "jwt-value")},
			wantStatus: http.StatusForbidden,
			wantHandle: false,
		},
		{
			name:       "admin token with access cookie and valid csrf passes",
			method:     http.MethodPost,
			path:       protectedPath,
			authHeader: adminBearer,
			cookies: []*http.Cookie{
				authCookie(utils.AccessTokenCookie, "jwt-value"),
				csrfCookie("csrf-value"),
			},
			csrfHeader: "csrf-value",
			wantStatus: http.StatusOK,
			wantHandle: true,
		},
		// 3. A refresh cookie alone also disables the skip.
		{
			name:       "admin token with refresh cookie only is still checked",
			method:     http.MethodPost,
			path:       protectedPath,
			authHeader: adminBearer,
			cookies:    []*http.Cookie{authCookie(utils.RefreshTokenCookie, "refresh-value")},
			wantStatus: http.StatusForbidden,
			wantHandle: false,
		},
		// 4. JWT bearer credentials never get the skip.
		{
			name:       "jwt bearer without cookies is rejected",
			method:     http.MethodPost,
			path:       protectedPath,
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfMSJ9.sig",
			wantStatus: http.StatusForbidden,
			wantHandle: false,
		},
		// 5. Plain double-submit behavior.
		{
			name:       "matching csrf cookie and header passes",
			method:     http.MethodPost,
			path:       protectedPath,
			cookies:    []*http.Cookie{csrfCookie("csrf-value")},
			csrfHeader: "csrf-value",
			wantStatus: http.StatusOK,
			wantHandle: true,
		},
		{
			name:       "mismatched csrf header is rejected",
			method:     http.MethodPost,
			path:       protectedPath,
			cookies:    []*http.Cookie{csrfCookie("csrf-value")},
			csrfHeader: "other-value",
			wantStatus: http.StatusForbidden,
			wantHandle: false,
		},
		{
			name:       "missing csrf header is rejected",
			method:     http.MethodPost,
			path:       protectedPath,
			cookies:    []*http.Cookie{csrfCookie("csrf-value")},
			wantStatus: http.StatusForbidden,
			wantHandle: false,
		},
		{
			name:       "missing csrf cookie is rejected",
			method:     http.MethodPost,
			path:       protectedPath,
			csrfHeader: "csrf-value",
			wantStatus: http.StatusForbidden,
			wantHandle: false,
		},
		// 6. Safe methods are always skipped.
		{
			name:       "get is skipped",
			method:     http.MethodGet,
			path:       protectedPath,
			wantStatus: http.StatusOK,
			wantHandle: true,
		},
		{
			name:       "head is skipped",
			method:     http.MethodHead,
			path:       protectedPath,
			wantStatus: http.StatusOK,
			wantHandle: true,
		},
		{
			name:       "options is skipped",
			method:     http.MethodOptions,
			path:       protectedPath,
			wantStatus: http.StatusOK,
			wantHandle: true,
		},
		// 7. Exempt paths stay exempt without CSRF tokens.
		{
			name:       "login is exempt",
			method:     http.MethodPost,
			path:       "/auth/login",
			wantStatus: http.StatusOK,
			wantHandle: true,
		},
		{
			name:       "refresh is exempt",
			method:     http.MethodPost,
			path:       "/auth/refresh",
			wantStatus: http.StatusOK,
			wantHandle: true,
		},
		{
			name:       "payments callback is exempt",
			method:     http.MethodPost,
			path:       "/payments/callback",
			wantStatus: http.StatusOK,
			wantHandle: true,
		},
		{
			name:       "forward agent api prefix is exempt",
			method:     http.MethodPost,
			path:       "/forward-agent-api/x",
			wantStatus: http.StatusOK,
			wantHandle: true,
		},
		// 8. The Bearer scheme is matched exactly, like RequireAuth; empty cookies
		// count as absent.
		{
			name:       "lowercase bearer scheme is not skipped",
			method:     http.MethodPost,
			path:       protectedPath,
			authHeader: "bearer orr_abc",
			wantStatus: http.StatusForbidden,
			wantHandle: false,
		},
		{
			name:       "empty access cookie counts as no cookie",
			method:     http.MethodPost,
			path:       protectedPath,
			authHeader: adminBearer,
			cookies:    []*http.Cookie{authCookie(utils.AccessTokenCookie, "")},
			wantStatus: http.StatusOK,
			wantHandle: true,
		},
		// 9. The skip is narrow: non-orr_ bearers get no exemption.
		{
			name:       "non admin token bearer without cookies is rejected",
			method:     http.MethodPost,
			path:       protectedPath,
			authHeader: "Bearer some-opaque-credential",
			wantStatus: http.StatusForbidden,
			wantHandle: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertCSRFCase(t, tc)
		})
	}
}

// TestCSRF_AdminTokenSkipRequiresBearerScheme verifies that an orr_ value
// without the Bearer scheme is not treated as an admin API token.
func TestCSRF_AdminTokenSkipRequiresBearerScheme(t *testing.T) {
	assertCSRFCase(t, csrfCase{
		name:       "raw orr value without bearer scheme is rejected",
		method:     http.MethodPost,
		path:       "/api/items",
		authHeader: "orr_abc",
		wantStatus: http.StatusForbidden,
		wantHandle: false,
	})
}

// TestCSRF_EmptyBearerIsRejected verifies an empty bearer credential is not a skip.
func TestCSRF_EmptyBearerIsRejected(t *testing.T) {
	assertCSRFCase(t, csrfCase{
		name:       "empty bearer credential is rejected",
		method:     http.MethodPost,
		path:       "/api/items",
		authHeader: "Bearer ",
		wantStatus: http.StatusForbidden,
		wantHandle: false,
	})
}
