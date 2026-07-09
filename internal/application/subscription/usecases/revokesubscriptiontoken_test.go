package usecases

import (
	"context"
	"testing"

	"github.com/orris-inc/orris/internal/domain/subscription"
	vo "github.com/orris-inc/orris/internal/domain/subscription/valueobjects"
	"github.com/orris-inc/orris/internal/shared/errors"
	"github.com/orris-inc/orris/internal/shared/logger"
)

// stubTokenRepo implements subscription.SubscriptionTokenRepository. Only the
// methods exercised by the use case are overridden; any other call would
// nil-panic (which is what we want — it flags unexpected access).
type stubTokenRepo struct {
	subscription.SubscriptionTokenRepository
	token        *subscription.SubscriptionToken
	updateCalled bool
}

func (s *stubTokenRepo) GetByID(_ context.Context, _ uint) (*subscription.SubscriptionToken, error) {
	return s.token, nil
}

func (s *stubTokenRepo) Update(_ context.Context, _ *subscription.SubscriptionToken) error {
	s.updateCalled = true
	return nil
}

func newTestToken(t *testing.T, subscriptionID uint) *subscription.SubscriptionToken {
	t.Helper()
	tok, err := subscription.NewSubscriptionToken(subscriptionID, "test", "hash1234", "prefix12", vo.TokenScopeFull, nil)
	if err != nil {
		t.Fatalf("failed to build test token: %v", err)
	}
	return tok
}

// A token belonging to another subscription must NOT be revocable, and the
// repository must never be asked to persist a change (IDOR regression).
func TestRevokeSubscriptionToken_RejectsCrossSubscription(t *testing.T) {
	repo := &stubTokenRepo{token: newTestToken(t, 100)}
	uc := NewRevokeSubscriptionTokenUseCase(repo, logger.NewLogger())

	err := uc.Execute(context.Background(), RevokeSubscriptionTokenCommand{
		SubscriptionID: 999, // caller owns a different subscription
		TokenID:        5,
	})

	if err == nil {
		t.Fatal("expected an error revoking a token from another subscription, got nil")
	}
	if !errors.IsNotFoundError(err) {
		t.Fatalf("expected a not-found error (enumeration-safe), got %v", err)
	}
	if repo.updateCalled {
		t.Fatal("token from another subscription must not be persisted/revoked")
	}
}

// A token that belongs to the caller's subscription is revoked normally.
func TestRevokeSubscriptionToken_AllowsOwnSubscription(t *testing.T) {
	repo := &stubTokenRepo{token: newTestToken(t, 100)}
	uc := NewRevokeSubscriptionTokenUseCase(repo, logger.NewLogger())

	err := uc.Execute(context.Background(), RevokeSubscriptionTokenCommand{
		SubscriptionID: 100,
		TokenID:        5,
	})

	if err != nil {
		t.Fatalf("expected revoke to succeed for owning subscription, got %v", err)
	}
	if !repo.updateCalled {
		t.Fatal("expected the revoked token to be persisted")
	}
}
