package webhook

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/orris-inc/orris/internal/domain/forward"
	"github.com/orris-inc/orris/internal/domain/node"
	"github.com/orris-inc/orris/internal/domain/shared"
	"github.com/orris-inc/orris/internal/shared/logger"
)

// Reasons attached to watcher-detected liveness edges.
const (
	reasonHeartbeatTimeout = "heartbeat_timeout"
	reasonHeartbeatResumed = "heartbeat_resumed"
)

// offlineAgentSource is the slice of forward.AgentRepository the watcher needs.
// The real repository satisfies it; tests can provide a tiny fake instead.
type offlineAgentSource interface {
	FindOfflineAgents(ctx context.Context, cutoff time.Time) ([]*forward.OfflineAgentInfo, error)
	GetByIDs(ctx context.Context, ids []uint) (map[uint]*forward.ForwardAgent, error)
}

// offlineNodeSource is the slice of node.NodeRepository the watcher needs.
type offlineNodeSource interface {
	FindOfflineNodes(ctx context.Context, cutoff time.Time) ([]*node.OfflineNodeInfo, error)
	GetByIDs(ctx context.Context, ids []uint) ([]*node.Node, error)
}

// Watcher periodically compares persisted last_seen_at values against a
// staleness threshold and emits edge-triggered liveness events. It complements
// the WebSocket callbacks: an entity whose socket stays connected while its
// heartbeats stop is still reported offline, and its recovery is reported once
// last_seen_at is fresh again. Delivery goes through the shared StateStore, so
// both observers dedupe against each other and no Telegram involvement exists.
type Watcher struct {
	agents   offlineAgentSource
	nodes    offlineNodeSource
	notifier *Notifier
	state    *StateStore
	logger   logger.Interface
	now      func() time.Time
}

// NewWatcher creates a Watcher. A nil or disabled notifier, or a nil state
// store, turns Run into a no-op.
func NewWatcher(
	agents offlineAgentSource,
	nodes offlineNodeSource,
	notifier *Notifier,
	state *StateStore,
	log logger.Interface,
) *Watcher {
	if log == nil {
		log = logger.NewLogger()
	}
	return &Watcher{
		agents:   agents,
		nodes:    nodes,
		notifier: notifier,
		state:    state,
		logger:   log,
		now:      time.Now,
	}
}

// Run performs one liveness pass: entities stale beyond shared.DefaultOnlineTimeout
// are reported offline, entities whose recorded state is offline but whose
// last_seen_at is fresh again are reported online. Errors are logged and never
// abort the rest of the pass, so callers are expected to invoke Run on a ticker.
func (w *Watcher) Run(ctx context.Context) {
	if w == nil || w.state == nil || !w.notifier.Enabled() {
		return
	}
	if ctx.Err() != nil {
		return
	}

	now := w.now().UTC()
	cutoff := now.Add(-shared.DefaultOnlineTimeout)

	agentsOffline, agentsOnline := w.checkAgents(ctx, cutoff, now, w.state.Snapshot(ctx, "agent:"))
	nodesOffline, nodesOnline := w.checkNodes(ctx, cutoff, now, w.state.Snapshot(ctx, "node:"))

	if total := agentsOffline + agentsOnline + nodesOffline + nodesOnline; total > 0 {
		w.logger.Infow("webhook heartbeat watch emitted events",
			"agents_offline", agentsOffline,
			"agents_online", agentsOnline,
			"nodes_offline", nodesOffline,
			"nodes_online", nodesOnline,
			"total", total,
		)
	}
}

// checkAgents emits agent.offline for stale agents and then agent.online for
// agents that were previously stale. It returns the number of events emitted
// per direction.
func (w *Watcher) checkAgents(ctx context.Context, cutoff, now time.Time, snaps map[string]Snapshot) (int, int) {
	if w.agents == nil {
		return 0, 0
	}

	offline, err := w.agents.FindOfflineAgents(ctx, cutoff)
	if err != nil {
		w.logger.Warnw("failed to list offline agents", "error", err)
		return 0, 0
	}

	offlineIDs := make(map[uint]struct{}, len(offline))
	emitted := 0
	for _, info := range offline {
		if info == nil {
			continue
		}
		offlineIDs[info.ID] = struct{}{}

		key := EntityKey("agent", info.ID)
		if w.reconnectAuthoritative(snaps, key, info.LastSeenAt, now) {
			continue
		}
		if !w.state.Transition(ctx, key, stateForEvent(EventAgentOffline)) {
			continue
		}

		detail := map[string]any{
			"id":           info.ID,
			"sid":          info.SID,
			"name":         info.Name,
			"last_seen_at": rfc3339(info.LastSeenAt),
			"reason":       reasonHeartbeatTimeout,
		}
		if ip := ipv4(info.PublicAddress); ip != "" {
			detail["public_ipv4"] = ip
		}

		w.notifier.Emit(ctx, Event{
			Event:  EventAgentOffline,
			Entity: Entity("agent", info.Name),
			TS:     now.Unix(),
			Detail: detail,
		})
		emitted++
	}

	return emitted, w.recoverAgents(ctx, offlineIDs, now)
}

// reconnectAuthoritative reports whether a recent WebSocket online edge should
// suppress this offline edge. last_seen_at is rate-limited in the database (at
// most one write per two minutes), so right after a reconnect the row can still
// hold the stale pre-disconnect value. A state recorded online after that value,
// and less than one full timeout old, is authoritative: the resource is known
// to be connected even though the row has not caught up yet.
func (w *Watcher) reconnectAuthoritative(snaps map[string]Snapshot, key string, lastSeen, now time.Time) bool {
	snap, ok := snaps[key]
	if !ok || snap.State != stateForEvent(EventAgentOnline) {
		return false
	}
	return snap.Since.After(lastSeen) && now.Sub(snap.Since) < shared.DefaultOnlineTimeout
}

// recoverAgents emits agent.online for recorded-offline agents that reported
// again after the moment they were marked offline.
func (w *Watcher) recoverAgents(ctx context.Context, offlineIDs map[uint]struct{}, now time.Time) int {
	pending := pendingRecoveries(w.state.Snapshot(ctx, "agent:"), "agent:", offlineIDs, w.logger)
	if len(pending) == 0 {
		return 0
	}

	ids := make([]uint, 0, len(pending))
	for id := range pending {
		ids = append(ids, id)
	}

	agents, err := w.agents.GetByIDs(ctx, ids)
	if err != nil {
		w.logger.Warnw("failed to load agents for online recovery", "error", err)
		return 0
	}

	emitted := 0
	for id, agent := range agents {
		since, ok := pending[id]
		if !ok || agent == nil || !agent.IsOnline() {
			continue
		}

		// A heartbeat sampled at or before the offline edge is not a recovery:
		// the socket may have closed while its last sample was still fresh.
		lastSeen := agent.LastSeenAt()
		if lastSeen == nil || !lastSeen.After(since) {
			continue
		}

		key := EntityKey("agent", id)
		if !w.state.Transition(ctx, key, stateForEvent(EventAgentOnline)) {
			continue
		}

		detail := map[string]any{
			"id":           id,
			"sid":          agent.SID(),
			"name":         agent.Name(),
			"last_seen_at": rfc3339(*lastSeen),
			"reason":       reasonHeartbeatResumed,
		}
		if ip := ipv4(agent.PublicAddress()); ip != "" {
			detail["public_ipv4"] = ip
		}

		w.notifier.Emit(ctx, Event{
			Event:  EventAgentOnline,
			Entity: Entity("agent", agent.Name()),
			TS:     now.Unix(),
			Detail: detail,
		})
		emitted++
	}

	return emitted
}

// checkNodes emits node.offline for stale nodes and then node.online for nodes
// that were previously stale. It returns the number of events emitted per
// direction.
func (w *Watcher) checkNodes(ctx context.Context, cutoff, now time.Time, snaps map[string]Snapshot) (int, int) {
	if w.nodes == nil {
		return 0, 0
	}

	offline, err := w.nodes.FindOfflineNodes(ctx, cutoff)
	if err != nil {
		w.logger.Warnw("failed to list offline nodes", "error", err)
		return 0, 0
	}

	offlineIDs := make(map[uint]struct{}, len(offline))
	emitted := 0
	for _, info := range offline {
		if info == nil {
			continue
		}
		offlineIDs[info.ID] = struct{}{}

		key := EntityKey("node", info.ID)
		if w.reconnectAuthoritative(snaps, key, info.LastSeenAt, now) {
			continue
		}
		if !w.state.Transition(ctx, key, stateForEvent(EventNodeOffline)) {
			continue
		}

		detail := map[string]any{
			"id":           info.ID,
			"sid":          info.SID,
			"name":         info.Name,
			"last_seen_at": rfc3339(info.LastSeenAt),
			"reason":       reasonHeartbeatTimeout,
		}
		if info.PublicIPv4 != nil {
			if ip := ipv4(*info.PublicIPv4); ip != "" {
				detail["public_ipv4"] = ip
			}
		}

		w.notifier.Emit(ctx, Event{
			Event:  EventNodeOffline,
			Entity: Entity("node", info.Name),
			TS:     now.Unix(),
			Detail: detail,
		})
		emitted++
	}

	return emitted, w.recoverNodes(ctx, offlineIDs, now)
}

// recoverNodes emits node.online for recorded-offline nodes that reported again
// after the moment they were marked offline.
func (w *Watcher) recoverNodes(ctx context.Context, offlineIDs map[uint]struct{}, now time.Time) int {
	pending := pendingRecoveries(w.state.Snapshot(ctx, "node:"), "node:", offlineIDs, w.logger)
	if len(pending) == 0 {
		return 0
	}

	ids := make([]uint, 0, len(pending))
	for id := range pending {
		ids = append(ids, id)
	}

	nodes, err := w.nodes.GetByIDs(ctx, ids)
	if err != nil {
		w.logger.Warnw("failed to load nodes for online recovery", "error", err)
		return 0
	}

	emitted := 0
	for _, n := range nodes {
		if n == nil {
			continue
		}
		since, ok := pending[n.ID()]
		if !ok || !shared.IsOnline(n.LastSeenAt()) {
			continue
		}

		// A heartbeat sampled at or before the offline edge is not a recovery:
		// the socket may have closed while its last sample was still fresh.
		lastSeen := n.LastSeenAt()
		if lastSeen == nil || !lastSeen.After(since) {
			continue
		}

		key := EntityKey("node", n.ID())
		if !w.state.Transition(ctx, key, stateForEvent(EventNodeOnline)) {
			continue
		}

		detail := map[string]any{
			"id":           n.ID(),
			"sid":          n.SID(),
			"name":         n.Name(),
			"last_seen_at": rfc3339(*lastSeen),
			"reason":       reasonHeartbeatResumed,
		}
		if ip := n.PublicIPv4(); ip != nil && *ip != "" {
			detail["public_ipv4"] = *ip
		}

		w.notifier.Emit(ctx, Event{
			Event:  EventNodeOnline,
			Entity: Entity("node", n.Name()),
			TS:     now.Unix(),
			Detail: detail,
		})
		emitted++
	}

	return emitted
}

// pendingRecoveries selects the entity keys recorded as offline that the cutoff
// query no longer reports stale. The result maps the entity id to the instant
// the offline state was entered, so callers can require a heartbeat newer than
// that edge before treating the entity as recovered. Malformed keys are logged
// and skipped so a single bad key cannot abort the pass.
func pendingRecoveries(
	snaps map[string]Snapshot,
	prefix string,
	stillOffline map[uint]struct{},
	log logger.Interface,
) map[uint]time.Time {
	offline := stateForEvent(EventAgentOffline)
	out := make(map[uint]time.Time, len(snaps))
	for key, snap := range snaps {
		if snap.State != offline {
			continue
		}
		raw := strings.TrimPrefix(key, prefix)
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			log.Warnw("ignoring malformed webhook state key", "key", key, "error", err)
			continue
		}
		id := uint(parsed)
		if _, ok := stillOffline[id]; ok {
			continue
		}
		out[id] = snap.Since
	}
	return out
}
