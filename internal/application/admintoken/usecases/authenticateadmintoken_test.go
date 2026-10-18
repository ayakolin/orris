package usecases

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/orris-inc/orris/internal/application/admintoken/testutil"
	"github.com/orris-inc/orris/internal/domain/admintoken"
	"github.com/orris-inc/orris/internal/domain/user"
	uvo "github.com/orris-inc/orris/internal/domain/user/valueobjects"
	"github.com/orris-inc/orris/internal/infrastructure/token"
	"github.com/orris-inc/orris/internal/shared/authorization"
	apperrors "github.com/orris-inc/orris/internal/shared/errors"
	"github.com/orris-inc/orris/internal/shared/logger"
)

func newTestLogger() logger.Interface {
	return logger.NewLoggerWithSlog(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func newTestGenerator() *token.AdminAPITokenGenerator {
	return token.NewAdminAPITokenGenerator()
}

// fixedSID returns a SID generator that always yields sid. Token SIDs are
// assigned by the create use case; tests only need a stable value.
func fixedSID(sid string) admintoken.SIDGenerator {
	return func() (string, error) { return sid, nil }
}

// mustNewToken builds a token through the aggregate constructor (used by the
// create flow) so the persist-then-authenticate path is exercised end to end.
func mustNewToken(t *testing.T, name, tokenHash, hint string, createdBy uint, expiresAt *time.Time) *admintoken.Token {
	t.Helper()
	tok, err := admintoken.NewToken(name, tokenHash, hint, createdBy, expiresAt, fixedSID("apt_created01"))
	require.NoError(t, err)
	return tok
}

// mustReconstructToken rebuilds a persisted token with an explicit ID.
func mustReconstructToken(
	t *testing.T,
	id uint,
	sid string,
	tokenHash string,
	createdBy uint,
	lastUsedAt *time.Time,
	expiresAt *time.Time,
	revokedAt *time.Time,
) *admintoken.Token {
	t.Helper()
	now := time.Now().UTC()
	tok, err := admintoken.ReconstructToken(
		id, sid, "test token", tokenHash, "orr_hint", createdBy,
		lastUsedAt, expiresAt, revokedAt, now, now,
	)
	require.NoError(t, err)
	return tok
}

func mustUser(t *testing.T, id uint, role authorization.UserRole, status uvo.Status) *user.User {
	t.Helper()
	email, err := uvo.NewEmail(fmt.Sprintf("admin%d@example.com", id))
	require.NoError(t, err)
	name, err := uvo.NewName(fmt.Sprintf("Admin %d", id))
	require.NoError(t, err)
	now := time.Now().UTC()
	u, err := user.ReconstructUser(id, fmt.Sprintf("usr_%012d", id), email, name, role, status, now, now, 1)
	require.NoError(t, err)
	return u
}

func newUseCase(
	t *testing.T,
	tokenRepo admintoken.Repository,
	userRepo *testutil.FakeUserRepository,
) *AuthenticateAdminAPITokenUseCase {
	t.Helper()
	return NewAuthenticateAdminAPITokenUseCase(tokenRepo, userRepo, newTestGenerator(), newTestLogger())
}

// lookupCountingRepo counts GetByTokenHash calls so tests can prove that an
// empty credential never reaches the database.
type lookupCountingRepo struct {
	*testutil.FakeAdminAPITokenRepository
	lookups int
}

func (r *lookupCountingRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*admintoken.Token, error) {
	r.lookups++
	return r.FakeAdminAPITokenRepository.GetByTokenHash(ctx, tokenHash)
}

// failingLastUsedRepo makes last_used_at writes fail. Authentication must still
// succeed: the write is best effort.
type failingLastUsedRepo struct {
	*testutil.FakeAdminAPITokenRepository
	updates int
}

func (r *failingLastUsedRepo) UpdateLastUsed(_ context.Context, _ uint, _ time.Time) (bool, error) {
	r.updates++
	return false, errors.New("simulated last_used_at write failure")
}

func TestAuthenticateAdminAPIToken_ValidActiveAdmin(t *testing.T) {
	const ownerID uint = 42

	gen := newTestGenerator()
	plainToken, tokenHash, hint, err := gen.Generate()
	require.NoError(t, err)

	tokenRepo := testutil.NewFakeAdminAPITokenRepository()
	tok := mustNewToken(t, "ci token", tokenHash, hint, ownerID, nil)
	require.NoError(t, tokenRepo.Create(context.Background(), tok))
	require.Equal(t, uint(1), tok.ID())

	userRepo := testutil.NewFakeUserRepository()
	userRepo.Add(mustUser(t, ownerID, authorization.RoleAdmin, uvo.StatusActive))

	uc := newUseCase(t, tokenRepo, userRepo)

	result, err := uc.Execute(context.Background(), AuthenticateAdminAPITokenCommand{PlainToken: plainToken})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.User)

	assert.Equal(t, ownerID, result.User.ID())
	assert.Equal(t, "apt_created01", result.TokenSID)
	assert.Equal(t, authorization.RoleAdmin, result.User.Role())
	assert.NotNil(t, tok.LastUsedAt(), "a successful authentication records last_used_at")
}

func TestAuthenticateAdminAPIToken_Rejections(t *testing.T) {
	const ownerID uint = 7

	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	oldLastUsed := now.Add(-2 * time.Minute)

	tests := []struct {
		name     string
		build    func(t *testing.T) (plainToken string, tokenRepo *testutil.FakeAdminAPITokenRepository, userRepo *testutil.FakeUserRepository)
		wantCode int
	}{
		{
			name: "unknown_token",
			build: func(t *testing.T) (string, *testutil.FakeAdminAPITokenRepository, *testutil.FakeUserRepository) {
				t.Helper()
				gen := newTestGenerator()
				plainToken, _, _, err := gen.Generate()
				require.NoError(t, err)
				tokenRepo := testutil.NewFakeAdminAPITokenRepository()
				userRepo := testutil.NewFakeUserRepository()
				userRepo.Add(mustUser(t, ownerID, authorization.RoleAdmin, uvo.StatusActive))
				return plainToken, tokenRepo, userRepo
			},
			wantCode: 401,
		},
		{
			name: "revoked_token",
			build: func(t *testing.T) (string, *testutil.FakeAdminAPITokenRepository, *testutil.FakeUserRepository) {
				t.Helper()
				gen := newTestGenerator()
				plainToken, tokenHash, _, err := gen.Generate()
				require.NoError(t, err)
				tokenRepo := testutil.NewFakeAdminAPITokenRepository()
				tokenRepo.Add(mustReconstructToken(t, 1, "apt_revoked01", tokenHash, ownerID, nil, nil, &past))
				userRepo := testutil.NewFakeUserRepository()
				userRepo.Add(mustUser(t, ownerID, authorization.RoleAdmin, uvo.StatusActive))
				return plainToken, tokenRepo, userRepo
			},
			wantCode: 401,
		},
		{
			name: "expired_token",
			build: func(t *testing.T) (string, *testutil.FakeAdminAPITokenRepository, *testutil.FakeUserRepository) {
				t.Helper()
				gen := newTestGenerator()
				plainToken, tokenHash, _, err := gen.Generate()
				require.NoError(t, err)
				tokenRepo := testutil.NewFakeAdminAPITokenRepository()
				tokenRepo.Add(mustReconstructToken(t, 1, "apt_expired01", tokenHash, ownerID, nil, &past, nil))
				userRepo := testutil.NewFakeUserRepository()
				userRepo.Add(mustUser(t, ownerID, authorization.RoleAdmin, uvo.StatusActive))
				return plainToken, tokenRepo, userRepo
			},
			wantCode: 401,
		},
		{
			name: "expires_exactly_now",
			build: func(t *testing.T) (string, *testutil.FakeAdminAPITokenRepository, *testutil.FakeUserRepository) {
				t.Helper()
				gen := newTestGenerator()
				plainToken, tokenHash, _, err := gen.Generate()
				require.NoError(t, err)
				expiresAt := time.Now().UTC()
				tokenRepo := testutil.NewFakeAdminAPITokenRepository()
				tokenRepo.Add(mustReconstructToken(t, 1, "apt_expiring01", tokenHash, ownerID, nil, &expiresAt, nil))
				userRepo := testutil.NewFakeUserRepository()
				userRepo.Add(mustUser(t, ownerID, authorization.RoleAdmin, uvo.StatusActive))
				return plainToken, tokenRepo, userRepo
			},
			wantCode: 401,
		},
		{
			name: "owner_deleted",
			build: func(t *testing.T) (string, *testutil.FakeAdminAPITokenRepository, *testutil.FakeUserRepository) {
				t.Helper()
				gen := newTestGenerator()
				plainToken, tokenHash, _, err := gen.Generate()
				require.NoError(t, err)
				tokenRepo := testutil.NewFakeAdminAPITokenRepository()
				tokenRepo.Add(mustReconstructToken(t, 1, "apt_orphan01", tokenHash, ownerID, &oldLastUsed, nil, nil))
				return plainToken, tokenRepo, testutil.NewFakeUserRepository()
			},
			wantCode: 401,
		},
		{
			name: "owner_suspended",
			build: func(t *testing.T) (string, *testutil.FakeAdminAPITokenRepository, *testutil.FakeUserRepository) {
				t.Helper()
				gen := newTestGenerator()
				plainToken, tokenHash, _, err := gen.Generate()
				require.NoError(t, err)
				tokenRepo := testutil.NewFakeAdminAPITokenRepository()
				tokenRepo.Add(mustReconstructToken(t, 1, "apt_suspend01", tokenHash, ownerID, &oldLastUsed, nil, nil))
				userRepo := testutil.NewFakeUserRepository()
				userRepo.Add(mustUser(t, ownerID, authorization.RoleAdmin, uvo.StatusSuspended))
				return plainToken, tokenRepo, userRepo
			},
			wantCode: 403,
		},
		{
			name: "owner_demoted",
			build: func(t *testing.T) (string, *testutil.FakeAdminAPITokenRepository, *testutil.FakeUserRepository) {
				t.Helper()
				gen := newTestGenerator()
				plainToken, tokenHash, _, err := gen.Generate()
				require.NoError(t, err)
				tokenRepo := testutil.NewFakeAdminAPITokenRepository()
				tokenRepo.Add(mustReconstructToken(t, 1, "apt_demoted01", tokenHash, ownerID, &oldLastUsed, nil, nil))
				userRepo := testutil.NewFakeUserRepository()
				userRepo.Add(mustUser(t, ownerID, authorization.RoleUser, uvo.StatusActive))
				return plainToken, tokenRepo, userRepo
			},
			wantCode: 403,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plainToken, tokenRepo, userRepo := tt.build(t)
			uc := newUseCase(t, tokenRepo, userRepo)

			result, err := uc.Execute(context.Background(), AuthenticateAdminAPITokenCommand{PlainToken: plainToken})

			require.Error(t, err)
			assert.Nil(t, result)
			appErr := apperrors.GetAppError(err)
			require.NotNil(t, appErr, "rejections must carry an AppError, got %v", err)
			assert.Equal(t, tt.wantCode, appErr.Code)
		})
	}
}

func TestAuthenticateAdminAPIToken_EmptyPlainToken(t *testing.T) {
	tokenRepo := &lookupCountingRepo{FakeAdminAPITokenRepository: testutil.NewFakeAdminAPITokenRepository()}
	userRepo := testutil.NewFakeUserRepository()
	uc := newUseCase(t, tokenRepo, userRepo)

	result, err := uc.Execute(context.Background(), AuthenticateAdminAPITokenCommand{PlainToken: ""})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, 0, tokenRepo.lookups, "an empty credential must not trigger a repository lookup")
	assert.Equal(t, 401, apperrors.GetAppError(err).Code)
}

func TestAuthenticateAdminAPIToken_LookupFailure(t *testing.T) {
	tokenRepo := testutil.NewFakeAdminAPITokenRepository()
	tokenRepo.SetLookupError(errors.New("database unavailable"))
	userRepo := testutil.NewFakeUserRepository()
	uc := newUseCase(t, tokenRepo, userRepo)

	gen := newTestGenerator()
	plainToken, _, _, err := gen.Generate()
	require.NoError(t, err)

	result, err := uc.Execute(context.Background(), AuthenticateAdminAPITokenCommand{PlainToken: plainToken})

	require.Error(t, err)
	assert.Nil(t, result, "a lookup failure must never be treated as a valid token")
	assert.Contains(t, err.Error(), "database unavailable")
}

func TestAuthenticateAdminAPIToken_LastUsedThrottle(t *testing.T) {
	ctx := context.Background()
	gen := newTestGenerator()

	tokenRepo := testutil.NewFakeAdminAPITokenRepository()
	userRepo := testutil.NewFakeUserRepository()
	userRepo.Add(mustUser(t, 1, authorization.RoleAdmin, uvo.StatusActive))

	plainToken, tokenHash, _, err := gen.Generate()
	require.NoError(t, err)
	tok := mustReconstructToken(t, 1, "apt_throttle01", tokenHash, 1, nil, nil, nil)
	tokenRepo.Add(tok)

	uc := newUseCase(t, tokenRepo, userRepo)

	// First use persists last_used_at.
	_, err = uc.Execute(ctx, AuthenticateAdminAPITokenCommand{PlainToken: plainToken})
	require.NoError(t, err)
	require.NotNil(t, tok.LastUsedAt())
	first := *tok.LastUsedAt()

	// An immediate second use is throttled: the stored value must not move.
	_, err = uc.Execute(ctx, AuthenticateAdminAPITokenCommand{PlainToken: plainToken})
	require.NoError(t, err)
	require.NotNil(t, tok.LastUsedAt())
	assert.True(t, tok.LastUsedAt().Equal(first), "last_used_at must not be rewritten within the throttle window")

	// A token last used two minutes ago is due for a refresh.
	old := time.Now().UTC().Add(-2 * time.Minute)
	plainToken2, tokenHash2, _, err := gen.Generate()
	require.NoError(t, err)
	stale := mustReconstructToken(t, 2, "apt_stale0001", tokenHash2, 1, &old, nil, nil)
	tokenRepo.Add(stale)

	_, err = uc.Execute(ctx, AuthenticateAdminAPITokenCommand{PlainToken: plainToken2})
	require.NoError(t, err)
	require.NotNil(t, stale.LastUsedAt())
	assert.True(t, stale.LastUsedAt().After(old), "a stale last_used_at must be refreshed")
	assert.False(t, stale.LastUsedAt().Before(time.Now().UTC().Add(-lastUsedThrottle)),
		"the refreshed last_used_at must be current")
}

func TestAuthenticateAdminAPIToken_LastUsedUpdateFailureDoesNotFailAuth(t *testing.T) {
	ctx := context.Background()
	gen := newTestGenerator()

	plainToken, tokenHash, _, err := gen.Generate()
	require.NoError(t, err)

	repo := &failingLastUsedRepo{FakeAdminAPITokenRepository: testutil.NewFakeAdminAPITokenRepository()}
	repo.Add(mustReconstructToken(t, 1, "apt_writefail", tokenHash, 1, nil, nil, nil))

	userRepo := testutil.NewFakeUserRepository()
	userRepo.Add(mustUser(t, 1, authorization.RoleAdmin, uvo.StatusActive))

	uc := newUseCase(t, repo, userRepo)

	result, err := uc.Execute(ctx, AuthenticateAdminAPITokenCommand{PlainToken: plainToken})

	require.NoError(t, err, "a last_used_at write failure must not fail authentication")
	require.NotNil(t, result)
	assert.Equal(t, uint(1), result.User.ID())
	assert.Equal(t, 1, repo.updates, "the use case must have attempted the write")
}
