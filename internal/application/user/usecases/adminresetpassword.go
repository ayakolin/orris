package usecases

import (
	"context"
	"fmt"
	"time"

	"github.com/orris-inc/orris/internal/domain/user"
	vo "github.com/orris-inc/orris/internal/domain/user/valueobjects"
	"github.com/orris-inc/orris/internal/shared/biztime"
	"github.com/orris-inc/orris/internal/shared/errors"
	"github.com/orris-inc/orris/internal/shared/logger"
)

// AdminTokenRevoker revokes every admin API token owned by a user.
// It is satisfied by the admin API token repository and is optional: when it is
// not set, password resets leave tokens untouched (they still fail once the user
// is disabled or demoted).
type AdminTokenRevoker interface {
	RevokeByUserID(ctx context.Context, userID uint, revokedAt time.Time) (int64, error)
}

type AdminResetPasswordCommand struct {
	UserSID     string
	NewPassword string
}

type AdminResetPasswordUseCase struct {
	userRepo               user.Repository
	sessionRepo            user.SessionRepository
	passwordHasher         user.PasswordHasher
	emailService           EmailService
	passwordPolicyProvider PasswordPolicyProvider
	tokenRevoker           AdminTokenRevoker
	logger                 logger.Interface
}

func NewAdminResetPasswordUseCase(
	userRepo user.Repository,
	sessionRepo user.SessionRepository,
	hasher user.PasswordHasher,
	emailService EmailService,
	passwordPolicyProvider PasswordPolicyProvider,
	logger logger.Interface,
) *AdminResetPasswordUseCase {
	return &AdminResetPasswordUseCase{
		userRepo:               userRepo,
		sessionRepo:            sessionRepo,
		passwordHasher:         hasher,
		emailService:           emailService,
		passwordPolicyProvider: passwordPolicyProvider,
		logger:                 logger,
	}
}

// SetAdminTokenRevoker wires the admin API token revoker.
// Uses setter injection because the token repository is created alongside the
// user use cases in the container.
func (uc *AdminResetPasswordUseCase) SetAdminTokenRevoker(revoker AdminTokenRevoker) {
	uc.tokenRevoker = revoker
}

func (uc *AdminResetPasswordUseCase) Execute(ctx context.Context, cmd AdminResetPasswordCommand) error {
	existingUser, err := uc.userRepo.GetBySID(ctx, cmd.UserSID)
	if err != nil {
		uc.logger.Errorw("failed to get user", "error", err, "user_sid", cmd.UserSID)
		return fmt.Errorf("failed to get user: %w", err)
	}
	if existingUser == nil {
		return errors.NewNotFoundError("user not found")
	}

	// Get password policy from settings
	var passwordPolicy *vo.PasswordPolicy
	if uc.passwordPolicyProvider != nil {
		passwordPolicy = uc.passwordPolicyProvider.GetPasswordPolicy(ctx)
	}

	newPassword, err := vo.NewPasswordWithPolicy(cmd.NewPassword, passwordPolicy)
	if err != nil {
		return err
	}

	if err := existingUser.AdminResetPassword(newPassword, uc.passwordHasher); err != nil {
		uc.logger.Errorw("failed to reset password", "error", err, "user_id", existingUser.ID())
		return err
	}

	// Invalidate all existing sessions for security
	if err := uc.sessionRepo.DeleteByUserID(existingUser.ID()); err != nil {
		uc.logger.Warnw("failed to delete user sessions", "error", err, "user_id", existingUser.ID())
	}

	// A password reset is a remediation action, so the user's admin API tokens are
	// revoked too: otherwise a leaked token would outlive the reset.
	uc.revokeAdminTokens(ctx, existingUser.ID())

	if err := uc.userRepo.Update(ctx, existingUser); err != nil {
		uc.logger.Errorw("failed to update user", "error", err, "user_id", existingUser.ID())
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Notify user about password change
	if err := uc.emailService.SendPasswordChangedEmail(existingUser.Email().String()); err != nil {
		uc.logger.Warnw("failed to send password changed email", "error", err, "user_id", existingUser.ID())
	}

	uc.logger.Infow("admin reset password successfully", "user_id", existingUser.ID())

	return nil
}

// revokeAdminTokens revokes the user's admin API tokens. Failures are logged, not
// returned: the password change itself has already succeeded.
func (uc *AdminResetPasswordUseCase) revokeAdminTokens(ctx context.Context, userID uint) {
	if uc.tokenRevoker == nil {
		return
	}
	revoked, err := uc.tokenRevoker.RevokeByUserID(ctx, userID, biztime.NowUTC())
	if err != nil {
		uc.logger.Warnw("failed to revoke admin API tokens after password reset",
			"user_id", userID, "error", err)
		return
	}
	if revoked > 0 {
		uc.logger.Infow("revoked admin API tokens after password reset",
			"user_id", userID, "count", revoked)
	}
}
