package usecases

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/orris-inc/orris/internal/domain/user"
	uvo "github.com/orris-inc/orris/internal/domain/user/valueobjects"
	"github.com/orris-inc/orris/internal/shared/authorization"
	"github.com/orris-inc/orris/internal/shared/logger"
)

// adminTokenRevokeRecorder records RevokeByUserID calls and can fail on demand.
type adminTokenRevokeRecorder struct {
	mu       sync.Mutex
	userIDs  []uint
	revoked  int64
	err      error
	callTime time.Time
}

func (r *adminTokenRevokeRecorder) RevokeByUserID(_ context.Context, userID uint, revokedAt time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.callTime = revokedAt
	if r.err != nil {
		return 0, r.err
	}
	r.userIDs = append(r.userIDs, userID)
	return r.revoked, nil
}

func (r *adminTokenRevokeRecorder) calls() []uint {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]uint(nil), r.userIDs...)
}

// resetTestUserRepo serves a single user for the admin reset use case.
type resetTestUserRepo struct {
	user.Repository
	u       *user.User
	updated *user.User
}

func (r *resetTestUserRepo) GetBySID(_ context.Context, _ string) (*user.User, error) {
	return r.u, nil
}
func (r *resetTestUserRepo) Update(_ context.Context, u *user.User) error {
	r.updated = u
	return nil
}

// resetTestSessionRepo records session invalidation.
type resetTestSessionRepo struct {
	user.SessionRepository
	deletedFor []uint
}

func (r *resetTestSessionRepo) DeleteByUserID(userID uint) error {
	r.deletedFor = append(r.deletedFor, userID)
	return nil
}

// resetTestHasher is a trivial PasswordHasher; the policy, not the hash, is under test.
type resetTestHasher struct{}

func (resetTestHasher) Hash(password string) (string, error) { return "hash:" + password, nil }
func (resetTestHasher) Verify(_, _ string) error             { return nil }

// resetTestEmail records password-changed notifications.
type resetTestEmail struct{}

func (resetTestEmail) SendVerificationEmail(string, string) error  { return nil }
func (resetTestEmail) SendPasswordResetEmail(string, string) error { return nil }
func (resetTestEmail) SendPasswordChangedEmail(string) error       { return nil }

func newResetTestUser(t *testing.T, id uint) *user.User {
	t.Helper()
	email, err := uvo.NewEmail("user@example.com")
	require.NoError(t, err)
	name, err := uvo.NewName("Test User")
	require.NoError(t, err)
	now := time.Now().UTC()
	u, err := user.ReconstructUser(id, "usr_aaaaaaaaaaaa", email, name,
		authorization.RoleUser, uvo.StatusActive, now, now, 1)
	require.NoError(t, err)
	return u
}

// TestAdminResetPassword_RevokesAdminAPITokens is the regression guard for leaked
// credentials: a password reset must not leave the user's admin API tokens usable.
func TestAdminResetPassword_RevokesAdminAPITokens(t *testing.T) {
	const userID uint = 42

	userRepo := &resetTestUserRepo{u: newResetTestUser(t, userID)}
	sessionRepo := &resetTestSessionRepo{}
	revoker := &adminTokenRevokeRecorder{revoked: 2}

	uc := NewAdminResetPasswordUseCase(userRepo, sessionRepo, resetTestHasher{}, resetTestEmail{}, nil, logger.NewLogger())
	uc.SetAdminTokenRevoker(revoker)

	err := uc.Execute(context.Background(), AdminResetPasswordCommand{
		UserSID:     "usr_aaaaaaaaaaaa",
		NewPassword: "N3w-Passw0rd!",
	})
	require.NoError(t, err)
	require.Equal(t, []uint{userID}, revoker.calls())
	require.Equal(t, []uint{userID}, sessionRepo.deletedFor, "sessions are still invalidated")
	require.NotNil(t, userRepo.updated)
}

// TestAdminResetPassword_TokenRevocationFailureDoesNotFailReset documents the
// best-effort contract: the password change has already happened and must stand.
func TestAdminResetPassword_TokenRevocationFailureDoesNotFailReset(t *testing.T) {
	userRepo := &resetTestUserRepo{u: newResetTestUser(t, 7)}
	revoker := &adminTokenRevokeRecorder{err: context.DeadlineExceeded}

	uc := NewAdminResetPasswordUseCase(userRepo, &resetTestSessionRepo{}, resetTestHasher{}, resetTestEmail{}, nil, logger.NewLogger())
	uc.SetAdminTokenRevoker(revoker)

	err := uc.Execute(context.Background(), AdminResetPasswordCommand{
		UserSID:     "usr_aaaaaaaaaaaa",
		NewPassword: "N3w-Passw0rd!",
	})
	require.NoError(t, err, "a revocation failure must not roll back the password reset")
	require.NotNil(t, userRepo.updated)
}

// TestAdminResetPassword_WithoutRevokerStillWorks keeps the use case usable when
// the revoker is not wired (for example in a stripped-down deployment).
func TestAdminResetPassword_WithoutRevokerStillWorks(t *testing.T) {
	userRepo := &resetTestUserRepo{u: newResetTestUser(t, 9)}

	uc := NewAdminResetPasswordUseCase(userRepo, &resetTestSessionRepo{}, resetTestHasher{}, resetTestEmail{}, nil, logger.NewLogger())

	err := uc.Execute(context.Background(), AdminResetPasswordCommand{
		UserSID:     "usr_aaaaaaaaaaaa",
		NewPassword: "N3w-Passw0rd!",
	})
	require.NoError(t, err)
	require.NotNil(t, userRepo.updated)
}
