package usecases

import (
	"context"
	"sort"
	"sync"

	"github.com/orris-inc/orris/internal/domain/forward"
	"github.com/orris-inc/orris/internal/shared/goroutine"
	"github.com/orris-inc/orris/internal/shared/logger"
)

// RuleChangeNotification describes a single config-sync push for a rule change.
type RuleChangeNotification struct {
	AgentID     uint
	RuleShortID string
	ChangeType  string
}

type ruleNotificationCollectorKey struct{}

// RuleNotificationCollector captures the side effects of a rule update so that a
// caller running several updates inside one transaction can push them only after
// the transaction has committed.
//
// It covers both kinds of post-update work:
//   - forward-agent config-sync pushes (NotifyRuleChange)
//   - node subscription re-syncs (SyncSubscriptionsToNode)
type RuleNotificationCollector struct {
	mu      sync.Mutex
	calls   []RuleChangeNotification
	nodeIDs []uint
}

// WithDeferredRuleNotifications returns a context that collects rule change
// notifications instead of dispatching them immediately.
func WithDeferredRuleNotifications(ctx context.Context) (context.Context, *RuleNotificationCollector) {
	collector := &RuleNotificationCollector{}
	return context.WithValue(ctx, ruleNotificationCollectorKey{}, collector), collector
}

// deferredRuleNotificationsFromContext returns the collector attached to ctx, if any.
func deferredRuleNotificationsFromContext(ctx context.Context) *RuleNotificationCollector {
	if collector, ok := ctx.Value(ruleNotificationCollectorKey{}).(*RuleNotificationCollector); ok {
		return collector
	}
	return nil
}

func (c *RuleNotificationCollector) add(calls ...RuleChangeNotification) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, calls...)
}

// addNodeSyncs records node IDs whose subscription snapshot must be re-synced.
// Duplicates are dropped so a batch touching the same node repeatedly pushes once.
func (c *RuleNotificationCollector) addNodeSyncs(nodeIDs ...uint) {
	c.mu.Lock()
	defer c.mu.Unlock()

	seen := make(map[uint]struct{}, len(c.nodeIDs)+len(nodeIDs))
	for _, nodeID := range c.nodeIDs {
		seen[nodeID] = struct{}{}
	}
	for _, nodeID := range nodeIDs {
		if _, ok := seen[nodeID]; ok {
			continue
		}
		seen[nodeID] = struct{}{}
		c.nodeIDs = append(c.nodeIDs, nodeID)
	}
}

// Calls returns a copy of the collected notifications.
func (c *RuleNotificationCollector) Calls() []RuleChangeNotification {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]RuleChangeNotification(nil), c.calls...)
}

// NodeIDs returns a copy of the collected node IDs, in insertion order.
func (c *RuleNotificationCollector) NodeIDs() []uint {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uint(nil), c.nodeIDs...)
}

// Flush dispatches all collected notifications in a background goroutine,
// mirroring the asynchronous behaviour of a single rule update.
func (c *RuleNotificationCollector) Flush(notifier ConfigSyncNotifier, log logger.Interface) {
	calls := c.Calls()
	if len(calls) == 0 || notifier == nil {
		return
	}
	goroutine.SafeGo(log, "deferred-notify-agents", func() {
		for _, call := range calls {
			if err := notifier.NotifyRuleChange(context.Background(), call.AgentID, call.RuleShortID, call.ChangeType); err != nil {
				log.Debugw("config sync notification skipped after deferred update",
					"rule_id", call.RuleShortID,
					"agent_id", call.AgentID,
					"reason", err.Error())
			}
		}
	})
}

// FlushNodeSyncs dispatches the collected node subscription re-syncs in a
// background goroutine. Like Flush it must only be called after the transaction
// has committed, so a node never receives a snapshot of uncommitted state.
func (c *RuleNotificationCollector) FlushNodeSyncs(syncer NodeSubscriptionSyncer, log logger.Interface) {
	nodeIDs := c.NodeIDs()
	if len(nodeIDs) == 0 || syncer == nil {
		return
	}
	goroutine.SafeGo(log, "deferred-sync-node-subscriptions", func() {
		for _, nodeID := range nodeIDs {
			if err := syncer.SyncSubscriptionsToNode(context.Background(), nodeID); err != nil {
				log.Warnw("failed to sync subscriptions to node after deferred rule update",
					"node_id", nodeID,
					"error", err,
				)
			}
		}
	})
}

// buildRuleChangeNotifications derives the notification set for an updated rule.
// It mirrors the notification logic of a single rule update: the entry agent is
// notified first, then removed agents are told to drop the rule, then the exit
// and chain agents are notified. Agent IDs are sorted for deterministic ordering.
func buildRuleChangeNotifications(
	originalAgentID uint,
	originalExitAgentIDs []uint,
	originalChainAgentIDs []uint,
	rule *forward.ForwardRule,
) []RuleChangeNotification {
	if rule == nil || !rule.IsEnabled() {
		return nil
	}

	newAgentID := rule.AgentID()
	calls := make([]RuleChangeNotification, 0, 4)
	calls = append(calls, RuleChangeNotification{
		AgentID:     newAgentID,
		RuleShortID: rule.SID(),
		ChangeType:  "updated",
	})

	if originalAgentID != newAgentID {
		calls = append(calls, RuleChangeNotification{
			AgentID:     originalAgentID,
			RuleShortID: rule.SID(),
			ChangeType:  "deleted",
		})
	}

	ruleType := rule.RuleType().String()
	if ruleType == "entry" {
		calls = append(calls, diffAgentNotifications(originalExitAgentIDs, rule.GetAllExitAgentIDs(), rule.SID())...)
	}
	if ruleType == "chain" || ruleType == "direct_chain" {
		calls = append(calls, diffAgentNotifications(originalChainAgentIDs, rule.ChainAgentIDs(), rule.SID())...)
	}

	return calls
}

// diffAgentNotifications notifies the new agents with "updated" and the agents
// that are no longer part of the rule with "deleted".
func diffAgentNotifications(original, current []uint, ruleShortID string) []RuleChangeNotification {
	currentSet := make(map[uint]struct{}, len(current))
	calls := make([]RuleChangeNotification, 0, len(current)+len(original))
	for _, agentID := range current {
		if _, seen := currentSet[agentID]; seen {
			continue
		}
		currentSet[agentID] = struct{}{}
		calls = append(calls, RuleChangeNotification{
			AgentID:     agentID,
			RuleShortID: ruleShortID,
			ChangeType:  "updated",
		})
	}

	removed := make([]uint, 0, len(original))
	for _, agentID := range original {
		if _, ok := currentSet[agentID]; !ok {
			removed = append(removed, agentID)
		}
	}
	sort.Slice(removed, func(i, j int) bool { return removed[i] < removed[j] })
	for _, agentID := range removed {
		calls = append(calls, RuleChangeNotification{
			AgentID:     agentID,
			RuleShortID: ruleShortID,
			ChangeType:  "deleted",
		})
	}
	return calls
}
