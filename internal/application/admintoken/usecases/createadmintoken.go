package usecases

import (
	"context"
	"time"

	"github.com/orris-inc/orris/internal/application/admintoken/dto"
	"github.com/orris-inc/orris/internal/domain/admintoken"
	"github.com/orris-inc/orris/internal/domain/user"
	"github.com/orris-inc/orris/internal/infrastructure/token"
	"github.com/orris-inc/orris/internal/shared/errors"
	"github.com/orris-inc/orris/internal/shared/id"
	"github.com/orris-inc/orris/internal/shared/logger"
)

// CreateAdminAPITokenCommand is the input for creating a token.
type CreateAdminAPITokenCommand struct {
	Name      string
	CreatedBy uint
	ExpiresAt *time.Time
}

// CreateAdminAPITokenUseCase creates admin API tokens.
type CreateAdminAPITokenUseCase struct {
	tokenRepo admintoken.Repository
	userRepo  AdminAPITokenUserRepository
	generator *token.AdminAPITokenGenerator
	logger    logger.Interface
}

// NewCreateAdminAPITokenUseCase creates a new CreateAdminAPITokenUseCase.
func NewCreateAdminAPITokenUseCase(
	tokenRepo admintoken.Repository,
	userRepo AdminAPITokenUserRepository,
	generator *token.AdminAPITokenGenerator,
	logger logger.Interface,
) *CreateAdminAPITokenUseCase {
	return &CreateAdminAPITokenUseCase{
		tokenRepo: tokenRepo,
		userRepo:  userRepo,
		generator: generator,
		logger:    logger,
	}
}

// Execute creates a token and returns the plaintext value exactly once.
// The caller must be a currently-active admin: tokens are only ever issued to
// admins, and an issued token never grants more than its owner's live role.
func (uc *CreateAdminAPITokenUseCase) Execute(ctx context.Context, cmd CreateAdminAPITokenCommand) (*dto.CreateTokenResponse, error) {
	if cmd.CreatedBy == 0 {
		return nil, errors.NewUnauthorizedError("user not authenticated")
	}

	owner, err := uc.userRepo.GetByID(ctx, cmd.CreatedBy)
	if err != nil {
		uc.logger.Errorw("failed to load token owner", "user_id", cmd.CreatedBy, "error", err)
		return nil, err
	}
	if owner == nil {
		return nil, errors.NewUnauthorizedError("user not found")
	}
	if !owner.CanPerformActions() {
		return nil, errors.NewForbiddenError("account is not active")
	}
	if !owner.IsAdmin() {
		return nil, errors.NewForbiddenError("admin access required")
	}

	plainToken, tokenHash, tokenHint, err := uc.generator.Generate()
	if err != nil {
		uc.logger.Errorw("failed to generate admin API token", "error", err)
		return nil, err
	}

	newToken, err := admintoken.NewToken(
		cmd.Name,
		tokenHash,
		tokenHint,
		cmd.CreatedBy,
		cmd.ExpiresAt,
		id.NewAdminAPITokenID,
	)
	if err != nil {
		return nil, errors.NewValidationError(err.Error())
	}

	if err := uc.tokenRepo.Create(ctx, newToken); err != nil {
		uc.logger.Errorw("failed to persist admin API token", "error", err)
		return nil, err
	}

	uc.logger.Infow("admin API token created",
		"token_sid", newToken.SID(),
		"created_by", newToken.CreatedBy(),
	)

	return &dto.CreateTokenResponse{
		TokenResponse: toTokenResponse(newToken, owner.SID()),
		Token:         plainToken,
	}, nil
}

// toTokenResponse maps a token aggregate to its API representation.
func toTokenResponse(t *admintoken.Token, ownerSID string) dto.TokenResponse {
	return dto.TokenResponse{
		ID:         t.SID(),
		Name:       t.Name(),
		TokenHint:  t.TokenHint(),
		CreatedBy:  ownerSID,
		LastUsedAt: t.LastUsedAt(),
		ExpiresAt:  t.ExpiresAt(),
		RevokedAt:  t.RevokedAt(),
		CreatedAt:  t.CreatedAt(),
		UpdatedAt:  t.UpdatedAt(),
	}
}

// ownerSID resolves a user SID, returning an empty string when unavailable.
func ownerSID(u *user.User) string {
	if u == nil {
		return ""
	}
	return u.SID()
}
