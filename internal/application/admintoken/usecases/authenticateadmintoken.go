// Package usecases implements the admin API token application use cases.
package usecases

import (
	"context"
	"fmt"
	"time"

	"github.com/orris-inc/orris/internal/domain/admintoken"
	"github.com/orris-inc/orris/internal/domain/user"
	"github.com/orris-inc/orris/internal/infrastructure/token"
	"github.com/orris-inc/orris/internal/shared/biztime"
	"github.com/orris-inc/orris/internal/shared/errors"
	"github.com/orris-inc/orris/internal/shared/logger"
)

// lastUsedThrottle is the minimum interval between last_used_at writes.
// Authentication must not perform a write on every request.
const lastUsedThrottle = time.Minute

// AdminAPITokenUserRepository is the narrow user lookup needed to resolve a
// token owner. Implemented by user.Repository.
type AdminAPITokenUserRepository interface {
	GetByID(ctx context.Context, id uint) (*user.User, error)
}

// AuthenticateAdminAPITokenCommand carries the raw bearer credential.
type AuthenticateAdminAPITokenCommand struct {
	PlainToken string
}

// AuthenticateAdminAPITokenResult is the identity established by a valid token.
type AuthenticateAdminAPITokenResult struct {
	// User is the token owner, freshly loaded from the database.
	User *user.User
	// TokenSID is the Stripe-style ID of the token that was used.
	TokenSID string
}

// AuthenticateAdminAPITokenUseCase validates admin API tokens for the auth middleware.
type AuthenticateAdminAPITokenUseCase struct {
	tokenRepo admintoken.Repository
	userRepo  AdminAPITokenUserRepository
	generator *token.AdminAPITokenGenerator
	logger    logger.Interface
}

// NewAuthenticateAdminAPITokenUseCase creates a new AuthenticateAdminAPITokenUseCase.
func NewAuthenticateAdminAPITokenUseCase(
	tokenRepo admintoken.Repository,
	userRepo AdminAPITokenUserRepository,
	generator *token.AdminAPITokenGenerator,
	logger logger.Interface,
) *AuthenticateAdminAPITokenUseCase {
	return &AuthenticateAdminAPITokenUseCase{
		tokenRepo: tokenRepo,
		userRepo:  userRepo,
		generator: generator,
		logger:    logger,
	}
}

// Execute resolves a plaintext token to the owning admin user.
//
// The token value is hashed and looked up by the unique hash index, so no secret
// material is compared in application memory. Unknown, revoked and expired
// tokens all fail with the same error to avoid telling a caller which condition
// applied. The owner is re-read on every request: a deleted, disabled or demoted
// admin immediately loses access, and a token can never grant more than the
// current admin role of its owner.
func (uc *AuthenticateAdminAPITokenUseCase) Execute(
	ctx context.Context,
	cmd AuthenticateAdminAPITokenCommand,
) (*AuthenticateAdminAPITokenResult, error) {
	if cmd.PlainToken == "" {
		return nil, errors.NewUnauthorizedError("missing API token")
	}

	tokenHash := uc.generator.Hash(cmd.PlainToken)
	storedToken, err := uc.tokenRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		uc.logger.Errorw("failed to look up admin API token", "error", err)
		return nil, fmt.Errorf("failed to look up admin API token: %w", err)
	}
	if storedToken == nil {
		return nil, errors.NewUnauthorizedError("invalid API token")
	}

	now := biztime.NowUTC()
	if !storedToken.IsUsable(now) {
		uc.logger.Warnw("rejected unusable admin API token",
			"token_sid", storedToken.SID(),
			"revoked", storedToken.IsRevoked(),
			"expired", storedToken.IsExpired(now),
		)
		return nil, errors.NewUnauthorizedError("invalid or expired API token")
	}

	owner, err := uc.userRepo.GetByID(ctx, storedToken.CreatedBy())
	if err != nil {
		uc.logger.Errorw("failed to load admin API token owner",
			"token_sid", storedToken.SID(),
			"user_id", storedToken.CreatedBy(),
			"error", err,
		)
		return nil, fmt.Errorf("failed to load token owner: %w", err)
	}
	if owner == nil {
		uc.logger.Warnw("admin API token owner no longer exists",
			"token_sid", storedToken.SID(),
			"user_id", storedToken.CreatedBy(),
		)
		return nil, errors.NewUnauthorizedError("token owner not found")
	}

	// The token must never grant more than the current role of a currently-active
	// admin: a disabled or demoted owner disables the token immediately.
	if !owner.CanPerformActions() {
		uc.logger.Warnw("rejecting admin API token for inactive owner",
			"token_sid", storedToken.SID(),
			"user_id", owner.ID(),
			"status", owner.Status(),
		)
		return nil, errors.NewForbiddenError("account is not active")
	}
	if !owner.IsAdmin() {
		uc.logger.Warnw("rejecting admin API token for non-admin owner",
			"token_sid", storedToken.SID(),
			"user_id", owner.ID(),
			"role", owner.Role(),
		)
		return nil, errors.NewForbiddenError("admin access required")
	}

	uc.touchLastUsed(ctx, storedToken, now)

	return &AuthenticateAdminAPITokenResult{
		User:     owner,
		TokenSID: storedToken.SID(),
	}, nil
}

// touchLastUsed updates last_used_at at most once per lastUsedThrottle.
// A failure here must never fail the request.
func (uc *AuthenticateAdminAPITokenUseCase) touchLastUsed(ctx context.Context, storedToken *admintoken.Token, now time.Time) {
	if lastUsed := storedToken.LastUsedAt(); lastUsed != nil && now.Sub(*lastUsed) < lastUsedThrottle {
		return
	}
	if _, err := uc.tokenRepo.UpdateLastUsed(ctx, storedToken.ID(), now); err != nil {
		uc.logger.Warnw("failed to update admin API token last_used_at",
			"token_sid", storedToken.SID(),
			"error", err,
		)
	}
}
