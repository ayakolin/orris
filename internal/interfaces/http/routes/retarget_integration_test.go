package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	adminTokenTestutil "github.com/orris-inc/orris/internal/application/admintoken/testutil"
	adminTokenUC "github.com/orris-inc/orris/internal/application/admintoken/usecases"
	"github.com/orris-inc/orris/internal/application/forward/testutil"
	"github.com/orris-inc/orris/internal/application/forward/usecases"
	"github.com/orris-inc/orris/internal/domain/admintoken"
	"github.com/orris-inc/orris/internal/domain/forward"
	vo "github.com/orris-inc/orris/internal/domain/forward/valueobjects"
	"github.com/orris-inc/orris/internal/domain/user"
	uvo "github.com/orris-inc/orris/internal/domain/user/valueobjects"
	infraAuth "github.com/orris-inc/orris/internal/infrastructure/auth"
	"github.com/orris-inc/orris/internal/infrastructure/token"
	forwardRuleHandlers "github.com/orris-inc/orris/internal/interfaces/http/handlers/forward/rule"
	"github.com/orris-inc/orris/internal/interfaces/http/middleware"
	"github.com/orris-inc/orris/internal/shared/authorization"
	"github.com/orris-inc/orris/internal/shared/config"
	"github.com/orris-inc/orris/internal/shared/id"
	"github.com/orris-inc/orris/internal/shared/logger"
)

// adminTokenUserRepo satisfies user.Repository for the JWT lookup path; the
// integration test only authenticates with an API token.
type adminTokenUserRepo struct {
	user.Repository
	u *user.User
}

func (r *adminTokenUserRepo) GetBySID(context.Context, string) (*user.User, error) { return r.u, nil }
func (r *adminTokenUserRepo) GetByID(context.Context, uint) (*user.User, error)    { return r.u, nil }

// retargetTxRunner runs the callback directly, standing in for a committed transaction.
type retargetTxRunner struct{}

func (retargetTxRunner) RunInTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

func ruleBySID(t *testing.T, repo *testutil.MockForwardRuleRepository, sid string) *forward.ForwardRule {
	t.Helper()
	rule, err := repo.GetBySID(context.Background(), sid)
	require.NoError(t, err)
	require.NotNil(t, rule)
	return rule
}

// TestRetargetEndpoint_AdminAPITokenEndToEnd exercises the whole security path in
// one request: global CSRF middleware, bearer API-token authentication, the admin
// route group, the retarget handler, the transaction, and the post-commit config
// push. It uses a token-only request (no cookies, no CSRF header) so it also
// proves the documented CSRF skip works end to end.
func TestRetargetEndpoint_AdminAPITokenEndToEnd(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log := logger.NewLogger()

	email, err := uvo.NewEmail("ops@example.com")
	require.NoError(t, err)
	name, err := uvo.NewName("Ops Admin")
	require.NoError(t, err)
	now := time.Now().UTC()
	owner, err := user.ReconstructUser(42, "usr_aaaaaaaaaaaa", email, name,
		authorization.RoleAdmin, uvo.StatusActive, now, now, 1)
	require.NoError(t, err)

	tokenRepo := adminTokenTestutil.NewFakeAdminAPITokenRepository()
	userRepo := adminTokenTestutil.NewFakeUserRepository()
	userRepo.Add(owner)

	generator := token.NewAdminAPITokenGenerator()
	plainToken, tokenHash, tokenHint, err := generator.Generate()
	require.NoError(t, err)
	storedToken, err := admintoken.NewToken("integration", tokenHash, tokenHint, owner.ID(), nil, id.NewAdminAPITokenID)
	require.NoError(t, err)
	require.NoError(t, tokenRepo.Create(context.Background(), storedToken))

	jwtSvc, err := infraAuth.NewJWTService("test-secret", 15, 7, "debug")
	require.NoError(t, err)
	authMiddleware := middleware.NewAuthMiddleware(jwtSvc, &adminTokenUserRepo{u: owner}, nil, config.CookieConfig{}, log)
	authMiddleware.SetAdminAPITokenAuthenticator(
		adminTokenUC.NewAuthenticateAdminAPITokenUseCase(tokenRepo, userRepo, generator, log),
	)

	ruleRepo := testutil.NewMockForwardRuleRepository()
	agentRepo := testutil.NewMockForwardAgentRepository()
	notifier := testutil.NewMockConfigSyncNotifier()

	agent, err := forward.NewForwardAgent("agent", "203.0.113.77", "10.0.0.77", "",
		func() (string, error) { return "fa_aaaaaaaaaaaa", nil },
		func(string) (string, string) { return "token", "hash" })
	require.NoError(t, err)
	require.NoError(t, agent.SetID(7))
	agentRepo.AddAgent(agent)

	newRule := func(sid string, listenPort uint16) {
		rule, err := forward.NewForwardRule(7, nil, nil, vo.ForwardRuleTypeDirect, 0, nil,
			vo.DefaultLoadBalanceStrategy, nil, nil, nil, vo.TunnelTypeWS, sid, listenPort,
			"10.0.0.1", 443, nil, "", vo.IPVersionAuto, vo.ForwardProtocolTCP, "", nil, 0,
			vo.AddressPreferenceAuto, func() (string, error) { return sid, nil })
		require.NoError(t, err)
		require.NoError(t, rule.Enable())
		ruleRepo.AddRule(rule)
	}
	newRule("fr_aaaaaaaaaaa1", 443)
	newRule("fr_aaaaaaaaaaa2", 8443)

	updateUC := usecases.NewUpdateForwardRuleUseCase(ruleRepo, agentRepo, nil, nil, nil, nil, notifier, log)
	retargetUC := usecases.NewRetargetForwardRulesUseCase(ruleRepo, agentRepo, updateUC, retargetTxRunner{}, log)

	engine := gin.New()
	engine.Use(middleware.CSRF())
	SetupForwardRoutes(engine, &ForwardRouteConfig{
		ForwardRuleHandler: forwardRuleHandlers.NewHandler(
			nil, nil, updateUC, nil, nil, nil, nil, nil, nil, nil, retargetUC, nil, log,
		),
		AuthMiddleware: authMiddleware,
	})

	post := func(body string) (*httptest.ResponseRecorder, *http.Request) {
		req := httptest.NewRequest(http.MethodPost, "/forward-rules/retarget", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+plainToken)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		return w, req
	}

	// Dry run: reports the plan and writes nothing.
	w, _ := post(`{"from_address":"10.0.0.1","to_address":"10.0.1.1","dry_run":true}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var dryRun struct {
		Success bool                    `json:"success"`
		Data    usecases.RetargetResult `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &dryRun))
	require.True(t, dryRun.Success)
	require.True(t, dryRun.Data.DryRun)
	require.Equal(t, 2, dryRun.Data.Matched)
	require.Equal(t, "10.0.0.1:443", dryRun.Data.Affected[0].OldTarget)
	require.Equal(t, "10.0.1.1:443", dryRun.Data.Affected[0].NewTarget)
	require.Equal(t, "fa_aaaaaaaaaaaa", dryRun.Data.Affected[0].AgentID)
	require.Equal(t, "10.0.0.1", ruleBySID(t, ruleRepo, "fr_aaaaaaaaaaa1").TargetAddress(),
		"a dry run must not modify rules")

	// Real run.
	w, _ = post(`{"from_address":"10.0.0.1","to_address":"10.0.1.1","to_port":9443}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	for _, sid := range []string{"fr_aaaaaaaaaaa1", "fr_aaaaaaaaaaa2"} {
		updated := ruleBySID(t, ruleRepo, sid)
		require.Equal(t, "10.0.1.1", updated.TargetAddress())
		require.Equal(t, uint16(9443), updated.TargetPort())
	}

	// Config pushes happen only after the commit, asynchronously.
	require.Eventually(t, func() bool { return len(notifier.GetCalls()) >= 2 },
		2*time.Second, 10*time.Millisecond, "expected post-commit notifications")
	for _, call := range notifier.GetCalls() {
		require.Equal(t, uint(7), call.AgentID)
		require.Equal(t, "updated", call.ChangeType)
	}

	// An unknown orr_ token is rejected and never falls through to JWT handling.
	badReq := httptest.NewRequest(http.MethodPost, "/forward-rules/retarget", bytes.NewBufferString(`{}`))
	badReq.Header.Set("Authorization", "Bearer orr_bogus")
	badRec := httptest.NewRecorder()
	engine.ServeHTTP(badRec, badReq)
	require.Equal(t, http.StatusUnauthorized, badRec.Code, badRec.Body.String())

	// A request that also carries an auth cookie loses the CSRF skip.
	cookieReq := httptest.NewRequest(http.MethodPost, "/forward-rules/retarget",
		bytes.NewBufferString(`{"from_address":"10.0.1.1","to_address":"10.0.2.2"}`))
	cookieReq.Header.Set("Authorization", "Bearer "+plainToken)
	cookieReq.AddCookie(&http.Cookie{Name: "access_token", Value: "stale"})
	cookieRec := httptest.NewRecorder()
	engine.ServeHTTP(cookieRec, cookieReq)
	require.Equal(t, http.StatusForbidden, cookieRec.Code,
		"a cookie-bearing request must still be CSRF-checked: %s", cookieRec.Body.String())
}
