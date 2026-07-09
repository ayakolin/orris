package usecases

import (
	"context"

	"github.com/orris-inc/orris/internal/domain/subscription"
)

// NodeSubscriptionAuthorizer resolves which subscriptions are authorized to use a
// node (via resource-group membership). Node agents may only report traffic/online
// data for subscriptions in this set — otherwise a node operator could forge usage
// for arbitrary subscriptions and exhaust another user's quota.
type NodeSubscriptionAuthorizer interface {
	GetActiveSubscriptionsByNodeID(ctx context.Context, nodeID uint) ([]*subscription.Subscription, error)
}

// authorizedSubscriptionIDs returns the set of internal subscription IDs a node is
// allowed to report data for. Callers should fail closed on error.
func authorizedSubscriptionIDs(ctx context.Context, authorizer NodeSubscriptionAuthorizer, nodeID uint) (map[uint]struct{}, error) {
	subs, err := authorizer.GetActiveSubscriptionsByNodeID(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	set := make(map[uint]struct{}, len(subs))
	for _, s := range subs {
		set[s.ID()] = struct{}{}
	}
	return set, nil
}
