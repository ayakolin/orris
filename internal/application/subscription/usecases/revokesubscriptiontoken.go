package usecases

import (
	"context"
	"fmt"

	"github.com/orris-inc/orris/internal/domain/subscription"
	"github.com/orris-inc/orris/internal/shared/errors"
	"github.com/orris-inc/orris/internal/shared/logger"
)

type RevokeSubscriptionTokenCommand struct {
	// SubscriptionID scopes the operation to a subscription the caller owns.
	// The token is only acted upon when it belongs to this subscription.
	SubscriptionID uint
	TokenID        uint
}

type RevokeSubscriptionTokenUseCase struct {
	tokenRepo subscription.SubscriptionTokenRepository
	logger    logger.Interface
}

func NewRevokeSubscriptionTokenUseCase(
	tokenRepo subscription.SubscriptionTokenRepository,
	logger logger.Interface,
) *RevokeSubscriptionTokenUseCase {
	return &RevokeSubscriptionTokenUseCase{
		tokenRepo: tokenRepo,
		logger:    logger,
	}
}

func (uc *RevokeSubscriptionTokenUseCase) Execute(ctx context.Context, cmd RevokeSubscriptionTokenCommand) error {
	token, err := uc.tokenRepo.GetByID(ctx, cmd.TokenID)
	if err != nil {
		uc.logger.Errorw("failed to get token", "error", err, "token_id", cmd.TokenID)
		return fmt.Errorf("failed to get token: %w", err)
	}

	// Authorization: the token must belong to the caller's subscription.
	// Respond as "not found" rather than "forbidden" so token IDs owned by
	// other subscriptions cannot be enumerated.
	if token == nil || token.SubscriptionID() != cmd.SubscriptionID {
		uc.logger.Warnw("token not found for subscription",
			"token_id", cmd.TokenID,
			"subscription_id", cmd.SubscriptionID,
		)
		return errors.NewNotFoundError("subscription token")
	}

	if err := token.Revoke(); err != nil {
		uc.logger.Warnw("failed to revoke token", "error", err, "token_id", cmd.TokenID)
		return err
	}

	if err := uc.tokenRepo.Update(ctx, token); err != nil {
		uc.logger.Errorw("failed to update token", "error", err, "token_id", cmd.TokenID)
		return fmt.Errorf("failed to update token: %w", err)
	}

	uc.logger.Infow("token revoked successfully",
		"token_id", cmd.TokenID,
		"subscription_id", token.SubscriptionID(),
	)

	return nil
}
