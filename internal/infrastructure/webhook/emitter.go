package webhook

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/orris-inc/orris/internal/domain/forward"
	"github.com/orris-inc/orris/internal/domain/node"
	"github.com/orris-inc/orris/internal/shared/config"
	"github.com/orris-inc/orris/internal/shared/logger"
)

// Rule sync/run status values reported by forward agents.
const (
	syncStatusSynced = "synced"
	syncStatusFailed = "failed"
	runStatusRunning = "running"
	runStatusStopped = "stopped"
	runStatusError   = "error"
)

// NodeInfoResolver resolves a node for event detail enrichment.
type NodeInfoResolver interface {
	GetByID(ctx context.Context, id uint) (*node.Node, error)
}

// Emitter translates domain transitions into node-watch events. Every method is
// a no-op when the notifier is disabled, and each edge is emitted at most once
// through the shared StateStore.
type Emitter struct {
	notifier     *Notifier
	state        *StateStore
	nodes        NodeInfoResolver
	thresholdPct int
	logger       logger.Interface
}

// NewEmitter creates an Emitter. notifier may be disabled; nodes is only used
// for traffic events and may be nil.
func NewEmitter(
	notifier *Notifier,
	state *StateStore,
	nodes NodeInfoResolver,
	cfg config.WebhookConfig,
	log logger.Interface,
) *Emitter {
	if log == nil {
		log = logger.NewLogger()
	}
	return &Emitter{
		notifier:     notifier,
		state:        state,
		nodes:        nodes,
		thresholdPct: cfg.TrafficThresholdPercent,
		logger:       log,
	}
}

// Enabled reports whether events will be delivered.
func (e *Emitter) Enabled() bool {
	return e != nil && e.notifier.Enabled() && e.state != nil
}

// Agent emits an agent liveness event for the given entity.
func (e *Emitter) Agent(ctx context.Context, agent *forward.ForwardAgent, event, reason string) {
	if agent == nil || !e.Enabled() {
		return
	}
	key := EntityKey("agent", agent.ID())
	state := stateForEvent(event)
	if !e.state.Transition(ctx, key, state) {
		return
	}

	detail := map[string]any{
		"id":     agent.ID(),
		"sid":    agent.SID(),
		"name":   agent.Name(),
		"reason": reason,
	}
	if event == EventAgentOnline {
		// The socket is open now; the persisted last_seen_at may still hold a
		// pre-disconnect value until the next heartbeat is written.
		detail["last_seen_at"] = rfc3339(time.Now().UTC())
	} else if lastSeen := agent.LastSeenAt(); lastSeen != nil {
		detail["last_seen_at"] = rfc3339(*lastSeen)
	}
	if ip := ipv4(agent.PublicAddress()); ip != "" {
		detail["public_ipv4"] = ip
	}

	e.notifier.Emit(ctx, Event{
		Event:  event,
		Entity: Entity("agent", agent.Name()),
		Detail: detail,
	})
}

// Node emits a node liveness event for the given entity.
func (e *Emitter) Node(ctx context.Context, n *node.Node, event, reason string) {
	if n == nil || !e.Enabled() {
		return
	}
	key := EntityKey("node", n.ID())
	if !e.state.Transition(ctx, key, stateForEvent(event)) {
		return
	}

	detail := map[string]any{
		"id":     n.ID(),
		"sid":    n.SID(),
		"name":   n.Name(),
		"reason": reason,
	}
	if event == EventNodeOnline {
		detail["last_seen_at"] = rfc3339(time.Now().UTC())
	} else if lastSeen := n.LastSeenAt(); lastSeen != nil {
		detail["last_seen_at"] = rfc3339(*lastSeen)
	}
	if ip := n.PublicIPv4(); ip != nil && *ip != "" {
		detail["public_ipv4"] = *ip
	}

	e.notifier.Emit(ctx, Event{
		Event:  event,
		Entity: Entity("node", n.Name()),
		Detail: detail,
	})
}

// ObserveRuleStatus implements forward usecases.RuleStatusObserver. Failed means
// the rule is not serving traffic: sync failed, or runtime error/stopped.
// Recovered means synced and running. Any transitional combination
// (pending/starting) leaves the recorded state untouched so it cannot flap.
//
// Chains are reported by every agent in them, so failures are tracked as a set
// of failing agents per rule: the rule emits rule.failed when the first agent
// starts failing and rule.recovered only when the last one recovers.
func (e *Emitter) ObserveRuleStatus(
	ctx context.Context,
	ruleSID, ruleName string,
	agentID uint,
	syncStatus, runStatus, errorMessage string,
) {
	if ruleSID == "" || !e.Enabled() {
		return
	}

	member := strconv.FormatUint(uint64(agentID), 10)
	key := "rule:" + ruleSID

	switch {
	case ruleFailed(syncStatus, runStatus):
		becameFailed, _ := e.state.SetTransition(ctx, key, member, true)
		if !becameFailed {
			return
		}
		e.emitRule(ctx, EventRuleFailed, ruleSID, ruleName, agentID, syncStatus, runStatus, errorMessage)

	case syncStatus == syncStatusSynced && runStatus == runStatusRunning:
		_, becameHealthy := e.state.SetTransition(ctx, key, member, false)
		if !becameHealthy {
			return
		}
		e.emitRule(ctx, EventRuleRecovered, ruleSID, ruleName, agentID, syncStatus, runStatus, errorMessage)
	}
}

func ruleFailed(syncStatus, runStatus string) bool {
	return syncStatus == syncStatusFailed || runStatus == runStatusError || runStatus == runStatusStopped
}

func (e *Emitter) emitRule(
	ctx context.Context,
	event, ruleSID, ruleName string,
	agentID uint,
	syncStatus, runStatus, errorMessage string,
) {
	e.notifier.Emit(ctx, Event{
		Event:  event,
		Entity: Entity("rule", ruleName),
		Detail: map[string]any{
			"rule_id":       ruleSID,
			"name":          ruleName,
			"agent_id":      agentID,
			"sync_status":   syncStatus,
			"run_status":    runStatus,
			"error_message": errorMessage,
			"last_check_at": rfc3339(time.Now().UTC()),
		},
	})
}

// ObserveTrafficThreshold emits traffic.threshold when a node subscription
// crosses the configured usage percentage and re-arms once it drops back below.
// limitBytes <= 0 means unlimited and is ignored.
func (e *Emitter) ObserveTrafficThreshold(
	ctx context.Context,
	nodeID, subscriptionID uint,
	usedBytes, limitBytes uint64,
) {
	if !e.Enabled() || e.thresholdPct <= 0 || limitBytes == 0 {
		return
	}

	percent := float64(usedBytes) / float64(limitBytes) * 100
	key := "traffic:" + strconv.FormatUint(uint64(subscriptionID), 10)

	if percent < float64(e.thresholdPct) {
		// Re-arm: only a state change matters, no recovery event exists.
		e.state.Transition(ctx, key, "normal")
		return
	}

	if e.nodes == nil {
		return
	}
	n, err := e.nodes.GetByID(ctx, nodeID)
	if err != nil {
		e.logger.Warnw("failed to resolve node for traffic webhook",
			"node_id", nodeID, "subscription_id", subscriptionID, "error", err)
		return
	}
	if n == nil {
		return
	}

	if !e.state.Transition(ctx, key, "alert") {
		return
	}

	name := n.Name()

	detail := map[string]any{
		"id":                nodeID,
		"sid":               n.SID(),
		"name":              name,
		"subscription_id":   subscriptionID,
		"used_bytes":        usedBytes,
		"limit_bytes":       limitBytes,
		"percent":           round2(percent),
		"threshold_percent": e.thresholdPct,
		"last_check_at":     rfc3339(time.Now().UTC()),
	}
	if ip := n.PublicIPv4(); ip != nil && *ip != "" {
		detail["public_ipv4"] = *ip
	}

	e.notifier.Emit(ctx, Event{
		Event:  EventTrafficThreshold,
		Entity: Entity("node", name),
		Detail: detail,
	})
}

func stateForEvent(event string) string {
	if TypeForEvent(event) == TypeOnline {
		return "online"
	}
	return "offline"
}

func rfc3339(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func round2(v float64) float64 {
	return float64(int64(v*100+0.5)) / 100
}

// ipv4 returns value when it is a literal IPv4 address, else "".
func ipv4(value string) string {
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return ""
	}
	return ip.String()
}
