package usecases

import (
	"context"
	"time"

	"github.com/orris-inc/orris/internal/application/admintoken/dto"
	"github.com/orris-inc/orris/internal/domain/admintoken"
	"github.com/orris-inc/orris/internal/shared/errors"
	"github.com/orris-inc/orris/internal/shared/id"
	"github.com/orris-inc/orris/internal/shared/logger"
)

// ListAdminAPITokensQuery lists the tokens owned by a caller.
type ListAdminAPITokensQuery struct {
	// CreatedBy limits the result to tokens owned by this user.
	// 0 lists every token (superuser-style administrative listing).
	CreatedBy uint
}

// ListAdminAPITokensUseCase lists admin API tokens without exposing secrets.
type ListAdminAPITokensUseCase struct {
	tokenRepo admintoken.Repository
	userRepo  AdminAPITokenUserRepository
	logger    logger.Interface
}

// NewListAdminAPITokensUseCase creates a new ListAdminAPITokensUseCase.
func NewListAdminAPITokensUseCase(
	tokenRepo admintoken.Repository,
	userRepo AdminAPITokenUserRepository,
	logger logger.Interface,
) *ListAdminAPITokensUseCase {
	return &ListAdminAPITokensUseCase{
		tokenRepo: tokenRepo,
		userRepo:  userRepo,
		logger:    logger,
	}
}

// Execute returns the tokens visible to the caller.
func (uc *ListAdminAPITokensUseCase) Execute(ctx context.Context, query ListAdminAPITokensQuery) ([]dto.TokenResponse, error) {
	tokens, err := uc.tokenRepo.List(ctx, query.CreatedBy)
	if err != nil {
		uc.logger.Errorw("failed to list admin API tokens", "error", err)
		return nil, err
	}

	ownerSIDs := make(map[uint]string)
	responses := make([]dto.TokenResponse, 0, len(tokens))
	for _, t := range tokens {
		sid, ok := ownerSIDs[t.CreatedBy()]
		if !ok {
			owner, err := uc.userRepo.GetByID(ctx, t.CreatedBy())
			if err != nil {
				uc.logger.Warnw("failed to load token owner", "user_id", t.CreatedBy(), "error", err)
			} else {
				sid = ownerSID(owner)
			}
			ownerSIDs[t.CreatedBy()] = sid
		}
		responses = append(responses, toTokenResponse(t, sid))
	}
	return responses, nil
}

// GetAdminAPITokenQuery identifies a single token.
type GetAdminAPITokenQuery struct {
	SID string
	// OwnerID, when non-zero, requires the token to belong to this user.
	// A non-owned token is reported as not found so IDs cannot be enumerated.
	OwnerID uint
}

// GetAdminAPITokenUseCase returns a single token by SID.
type GetAdminAPITokenUseCase struct {
	tokenRepo admintoken.Repository
	userRepo  AdminAPITokenUserRepository
	logger    logger.Interface
}

// NewGetAdminAPITokenUseCase creates a new GetAdminAPITokenUseCase.
func NewGetAdminAPITokenUseCase(
	tokenRepo admintoken.Repository,
	userRepo AdminAPITokenUserRepository,
	logger logger.Interface,
) *GetAdminAPITokenUseCase {
	return &GetAdminAPITokenUseCase{tokenRepo: tokenRepo, userRepo: userRepo, logger: logger}
}

// Execute returns the token, or a not-found error.
func (uc *GetAdminAPITokenUseCase) Execute(ctx context.Context, query GetAdminAPITokenQuery) (*dto.TokenResponse, error) {
	if err := id.ValidatePrefix(query.SID, id.PrefixAdminAPIToken); err != nil {
		return nil, errors.NewValidationError("invalid token ID format, expected apt_xxxxx")
	}

	storedToken, err := uc.tokenRepo.GetBySID(ctx, query.SID)
	if err != nil {
		uc.logger.Errorw("failed to get admin API token", "token_sid", query.SID, "error", err)
		return nil, err
	}
	if storedToken == nil || (query.OwnerID != 0 && storedToken.CreatedBy() != query.OwnerID) {
		return nil, errors.NewNotFoundError("admin API token", query.SID)
	}

	ownerSIDValue := ""
	if owner, err := uc.userRepo.GetByID(ctx, storedToken.CreatedBy()); err != nil {
		uc.logger.Warnw("failed to load token owner", "user_id", storedToken.CreatedBy(), "error", err)
	} else {
		ownerSIDValue = ownerSID(owner)
	}

	response := toTokenResponse(storedToken, ownerSIDValue)
	return &response, nil
}

// RevokeAdminAPITokenCommand identifies the token to revoke.
type RevokeAdminAPITokenCommand struct {
	SID string
	// OwnerID, when non-zero, requires the token to belong to this user.
	OwnerID uint
}

// RevokeAdminAPITokenUseCase revokes a token. Revocation is idempotent.
type RevokeAdminAPITokenUseCase struct {
	tokenRepo admintoken.Repository
	logger    logger.Interface
}

// NewRevokeAdminAPITokenUseCase creates a new RevokeAdminAPITokenUseCase.
func NewRevokeAdminAPITokenUseCase(tokenRepo admintoken.Repository, logger logger.Interface) *RevokeAdminAPITokenUseCase {
	return &RevokeAdminAPITokenUseCase{tokenRepo: tokenRepo, logger: logger}
}

// Execute revokes the token. Revoking an already-revoked token succeeds.
func (uc *RevokeAdminAPITokenUseCase) Execute(ctx context.Context, cmd RevokeAdminAPITokenCommand) error {
	if err := id.ValidatePrefix(cmd.SID, id.PrefixAdminAPIToken); err != nil {
		return errors.NewValidationError("invalid token ID format, expected apt_xxxxx")
	}

	storedToken, err := uc.tokenRepo.GetBySID(ctx, cmd.SID)
	if err != nil {
		uc.logger.Errorw("failed to get admin API token", "token_sid", cmd.SID, "error", err)
		return err
	}
	if storedToken == nil || (cmd.OwnerID != 0 && storedToken.CreatedBy() != cmd.OwnerID) {
		return errors.NewNotFoundError("admin API token", cmd.SID)
	}

	now := time.Now().UTC()
	if start := storedToken.RevokedAt(); start != nil {
		// Already revoked: keep the original timestamp and report success.
		return nil
	}

	if _, err := uc.tokenRepo.Revoke(ctx, storedToken.ID(), now); err != nil {
		uc.logger.Errorw("failed to revoke admin API token", "token_sid", cmd.SID, "error", err)
		return err
	}

	uc.logger.Infow("admin API token revoked", "token_sid", cmd.SID)
	return nil
}

// DeleteAdminAPITokenCommand identifies the token to delete.
type DeleteAdminAPITokenCommand struct {
	SID string
	// OwnerID, when non-zero, requires the token to belong to this user.
	OwnerID uint
}

// DeleteAdminAPITokenUseCase permanently deletes a token.
type DeleteAdminAPITokenUseCase struct {
	tokenRepo admintoken.Repository
	logger    logger.Interface
}

// NewDeleteAdminAPITokenUseCase creates a new DeleteAdminAPITokenUseCase.
func NewDeleteAdminAPITokenUseCase(tokenRepo admintoken.Repository, logger logger.Interface) *DeleteAdminAPITokenUseCase {
	return &DeleteAdminAPITokenUseCase{tokenRepo: tokenRepo, logger: logger}
}

// Execute deletes the token.
func (uc *DeleteAdminAPITokenUseCase) Execute(ctx context.Context, cmd DeleteAdminAPITokenCommand) error {
	if err := id.ValidatePrefix(cmd.SID, id.PrefixAdminAPIToken); err != nil {
		return errors.NewValidationError("invalid token ID format, expected apt_xxxxx")
	}

	storedToken, err := uc.tokenRepo.GetBySID(ctx, cmd.SID)
	if err != nil {
		uc.logger.Errorw("failed to get admin API token", "token_sid", cmd.SID, "error", err)
		return err
	}
	if storedToken == nil || (cmd.OwnerID != 0 && storedToken.CreatedBy() != cmd.OwnerID) {
		return errors.NewNotFoundError("admin API token", cmd.SID)
	}

	deleted, err := uc.tokenRepo.Delete(ctx, storedToken.ID())
	if err != nil {
		uc.logger.Errorw("failed to delete admin API token", "token_sid", cmd.SID, "error", err)
		return err
	}
	if !deleted {
		return errors.NewNotFoundError("admin API token", cmd.SID)
	}

	uc.logger.Infow("admin API token deleted", "token_sid", cmd.SID)
	return nil
}
