package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/orris-inc/orris/internal/domain/forward"
	"github.com/orris-inc/orris/internal/domain/node"
	vo "github.com/orris-inc/orris/internal/domain/node/valueobjects"
	"github.com/orris-inc/orris/internal/shared/config"
	"github.com/orris-inc/orris/internal/shared/logger"
)

// fakeAgentSource implements offlineAgentSource with an in-memory set of stale
// agents.
type fakeAgentSource struct {
	offline []*forward.OfflineAgentInfo
	byID    map[uint]*forward.ForwardAgent
	findErr error
	getErr  error
}

func (f *fakeAgentSource) FindOfflineAgents(_ context.Context, _ time.Time) ([]*forward.OfflineAgentInfo, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	return f.offline, nil
}

func (f *fakeAgentSource) GetByIDs(_ context.Context, ids []uint) (map[uint]*forward.ForwardAgent, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	out := make(map[uint]*forward.ForwardAgent, len(ids))
	for _, id := range ids {
		if agent, ok := f.byID[id]; ok {
			out[id] = agent
		}
	}
	return out, nil
}

// fakeNodeSource implements offlineNodeSource with an in-memory set of stale
// nodes.
type fakeNodeSource struct {
	offline []*node.OfflineNodeInfo
	byID    map[uint]*node.Node
	findErr error
	getErr  error
}

func (f *fakeNodeSource) FindOfflineNodes(_ context.Context, _ time.Time) ([]*node.OfflineNodeInfo, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	return f.offline, nil
}

func (f *fakeNodeSource) GetByIDs(_ context.Context, ids []uint) ([]*node.Node, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	out := make([]*node.Node, 0, len(ids))
	for _, id := range ids {
		if n, ok := f.byID[id]; ok {
			out = append(out, n)
		}
	}
	return out, nil
}

type watcherHarness struct {
	watcher *Watcher
	state   *StateStore
	capture *capture
	agents  *fakeAgentSource
	nodes   *fakeNodeSource
}

func newWatcherHarness(t *testing.T) *watcherHarness {
	t.Helper()

	cap := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.add(r)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	notifier := testNotifier(srv.URL, srv.Client())
	t.Cleanup(notifier.Close)

	agents := &fakeAgentSource{byID: map[uint]*forward.ForwardAgent{}}
	nodes := &fakeNodeSource{byID: map[uint]*node.Node{}}
	state := NewStateStore(nil, logger.NewLogger())

	return &watcherHarness{
		watcher: NewWatcher(agents, nodes, notifier, state, logger.NewLogger()),
		state:   state,
		capture: cap,
		agents:  agents,
		nodes:   nodes,
	}
}

func (h *watcherHarness) run() {
	h.watcher.Run(context.Background())
}

// waitEvents waits until want events have been delivered and decodes them.
func (h *watcherHarness) waitEvents(t *testing.T, want int) []Event {
	t.Helper()
	reqs := h.capture.waitFor(t, want)
	events := make([]Event, 0, len(reqs))
	for _, req := range reqs {
		var ev Event
		if err := json.Unmarshal(req.body, &ev); err != nil {
			t.Fatalf("invalid event body %q: %v", req.body, err)
		}
		events = append(events, ev)
	}
	return events
}

// assertNoNewEvents fails when any event is delivered beyond the given count.
func (h *watcherHarness) assertNoNewEvents(t *testing.T, before int) {
	t.Helper()
	time.Sleep(150 * time.Millisecond)
	if got := h.capture.count(); got != before {
		t.Fatalf("requests = %d, want %d (no new events)", got, before)
	}
}

func newTestAgent(t *testing.T, id uint, sid, name, publicAddress string, lastSeen *time.Time) *forward.ForwardAgent {
	t.Helper()
	now := time.Now().UTC()
	agent, err := forward.ReconstructForwardAgent(
		id,
		sid,
		name,
		"token-hash",
		"",
		forward.AgentStatusEnabled,
		publicAddress,
		"",
		"",
		nil, // groupIDs
		"",
		"",
		"",
		nil, // allowedPortRange
		nil, // blockedProtocols
		0,
		false,
		lastSeen,
		nil, // expiresAt
		nil, // costLabel
		now,
		now,
	)
	if err != nil {
		t.Fatalf("ReconstructForwardAgent: %v", err)
	}
	return agent
}

func newTestNode(t *testing.T, id uint, sid, name, publicIPv4 string, lastSeen *time.Time) *node.Node {
	t.Helper()

	addr, err := vo.NewServerAddress("10.0.0.1")
	if err != nil {
		t.Fatalf("NewServerAddress: %v", err)
	}
	enc, err := vo.NewEncryptionConfig(vo.MethodChacha20IETFPoly1305)
	if err != nil {
		t.Fatalf("NewEncryptionConfig: %v", err)
	}

	var ipv4 *string
	if publicIPv4 != "" {
		ipv4 = &publicIPv4
	}

	now := time.Now().UTC()
	n, err := node.ReconstructNode(
		id,
		sid,
		name,
		addr,
		8388,
		nil, // subscriptionPort
		vo.ProtocolShadowsocks,
		enc,
		nil, // pluginConfig
		nil, // trojanConfig
		nil, // vlessConfig
		nil, // vmessConfig
		nil, // hysteria2Config
		nil, // tuicConfig
		nil, // anytlsConfig
		vo.NodeStatusActive,
		vo.NewNodeMetadata("ap-east", nil, ""),
		nil, // groupIDs
		nil, // userID
		"token-hash",
		"",
		0,
		false,
		nil, // maintenanceReason
		nil, // routeConfig
		nil, // dnsConfig
		lastSeen,
		ipv4,
		nil, // publicIPv6
		nil, // agentVersion
		nil, // platform
		nil, // arch
		nil, // expiresAt
		nil, // costLabel
		1,
		now,
		now,
	)
	if err != nil {
		t.Fatalf("ReconstructNode: %v", err)
	}
	return n
}

func detailString(t *testing.T, ev Event, key string) string {
	t.Helper()
	value, ok := ev.Detail[key].(string)
	if !ok {
		t.Fatalf("detail[%q] = %#v, want string", key, ev.Detail[key])
	}
	return value
}

func detailID(t *testing.T, ev Event) uint {
	t.Helper()
	value, ok := ev.Detail["id"].(float64)
	if !ok {
		t.Fatalf("detail[id] = %#v, want number", ev.Detail["id"])
	}
	return uint(value)
}

func assertNoDetailKey(t *testing.T, ev Event, key string) {
	t.Helper()
	if value, ok := ev.Detail[key]; ok {
		t.Fatalf("detail[%q] = %#v, want absent", key, value)
	}
}

func TestWatcherAgentOfflineEmitsOnceAndDedupes(t *testing.T) {
	h := newWatcherHarness(t)

	lastSeen := time.Now().UTC().Add(-10 * time.Minute)
	agent := newTestAgent(t, 7, "fa_7", "edge-1", "203.0.113.7", &lastSeen)
	h.agents.byID[7] = agent
	h.agents.offline = []*forward.OfflineAgentInfo{
		{ID: 7, SID: "fa_7", Name: "edge-1", LastSeenAt: lastSeen},
	}

	h.run()

	events := h.waitEvents(t, 1)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.Event != EventAgentOffline {
		t.Fatalf("event = %q, want %q", ev.Event, EventAgentOffline)
	}
	if ev.Type != TypeOffline {
		t.Fatalf("type = %q, want %q", ev.Type, TypeOffline)
	}
	if ev.Source != SourceOrris {
		t.Fatalf("source = %q, want %q", ev.Source, SourceOrris)
	}
	if ev.Entity != Entity("agent", "edge-1") {
		t.Fatalf("entity = %q, want %q", ev.Entity, Entity("agent", "edge-1"))
	}
	if ev.TS == 0 {
		t.Fatal("ts must be set")
	}
	if got := detailID(t, ev); got != 7 {
		t.Fatalf("detail id = %d, want 7", got)
	}
	if got := detailString(t, ev, "sid"); got != "fa_7" {
		t.Fatalf("detail sid = %q, want fa_7", got)
	}
	if got := detailString(t, ev, "name"); got != "edge-1" {
		t.Fatalf("detail name = %q, want edge-1", got)
	}
	if got := detailString(t, ev, "reason"); got != reasonHeartbeatTimeout {
		t.Fatalf("detail reason = %q, want %q", got, reasonHeartbeatTimeout)
	}
	if got, want := detailString(t, ev, "last_seen_at"), lastSeen.UTC().Format(time.RFC3339); got != want {
		t.Fatalf("detail last_seen_at = %q, want %q", got, want)
	}
	assertNoDetailKey(t, ev, "public_ipv4")

	// The agent is still stale on the next pass: the StateStore dedupes it.
	h.run()
	h.assertNoNewEvents(t, 1)

	if got := h.state.State(context.Background(), EntityKey("agent", 7)); got != "offline" {
		t.Fatalf("state = %q, want offline", got)
	}
}

func TestWatcherAgentOnlineAfterHeartbeatResumes(t *testing.T) {
	h := newWatcherHarness(t)

	lastSeen := time.Now().UTC().Add(-10 * time.Minute)
	agent := newTestAgent(t, 9, "fa_9", "edge-9", "198.51.100.4", &lastSeen)
	h.agents.byID[9] = agent
	h.agents.offline = []*forward.OfflineAgentInfo{
		{ID: 9, SID: "fa_9", Name: "edge-9", LastSeenAt: lastSeen},
	}

	h.run()
	if got := h.capture.waitFor(t, 1); len(got) != 1 {
		t.Fatalf("first pass requests = %d, want 1", len(got))
	}

	// Heartbeat resumes while the socket may still be connected.
	time.Sleep(5 * time.Millisecond)
	agent.UpdateLastSeen(time.Now().UTC())
	h.agents.offline = nil

	h.run()
	events := h.waitEvents(t, 2)
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	ev := events[1]
	if ev.Event != EventAgentOnline {
		t.Fatalf("event = %q, want %q", ev.Event, EventAgentOnline)
	}
	if ev.Type != TypeOnline {
		t.Fatalf("type = %q, want %q", ev.Type, TypeOnline)
	}
	if ev.Entity != Entity("agent", "edge-9") {
		t.Fatalf("entity = %q, want %q", ev.Entity, Entity("agent", "edge-9"))
	}
	if got := detailID(t, ev); got != 9 {
		t.Fatalf("detail id = %d, want 9", got)
	}
	if got := detailString(t, ev, "sid"); got != "fa_9" {
		t.Fatalf("detail sid = %q, want fa_9", got)
	}
	if got := detailString(t, ev, "reason"); got != reasonHeartbeatResumed {
		t.Fatalf("detail reason = %q, want %q", got, reasonHeartbeatResumed)
	}
	if detailString(t, ev, "last_seen_at") == "" {
		t.Fatal("detail last_seen_at must be set")
	}
	if got := detailString(t, ev, "public_ipv4"); got != "198.51.100.4" {
		t.Fatalf("detail public_ipv4 = %q, want 198.51.100.4", got)
	}

	// A third pass must not repeat the online edge.
	h.run()
	h.assertNoNewEvents(t, 2)

	if got := h.state.State(context.Background(), EntityKey("agent", 9)); got != "online" {
		t.Fatalf("state = %q, want online", got)
	}
}

func TestWatcherRecoveryRequiresHeartbeatAfterOfflineEdge(t *testing.T) {
	h := newWatcherHarness(t)

	// A sample that is still within DefaultOnlineTimeout but predates the
	// offline edge: the socket may have just closed with a fresh heartbeat.
	lastSeen := time.Now().UTC().Add(-2 * time.Minute)
	agent := newTestAgent(t, 21, "fa_21", "edge-21", "", &lastSeen)
	h.agents.byID[21] = agent
	h.agents.offline = []*forward.OfflineAgentInfo{
		{ID: 21, SID: "fa_21", Name: "edge-21", LastSeenAt: lastSeen},
	}

	h.run()
	if got := h.capture.waitFor(t, 1); len(got) != 1 {
		t.Fatalf("first pass requests = %d, want 1", len(got))
	}

	// The cutoff query no longer reports the agent, but the recorded heartbeat
	// is older than the offline edge: no recovery may be emitted.
	h.agents.offline = nil
	h.run()
	h.assertNoNewEvents(t, 1)
	if got := h.state.State(context.Background(), EntityKey("agent", 21)); got != "offline" {
		t.Fatalf("state = %q, want offline to persist", got)
	}

	// A genuinely newer heartbeat recovers it.
	time.Sleep(5 * time.Millisecond)
	agent.UpdateLastSeen(time.Now().UTC())
	h.run()
	events := h.waitEvents(t, 2)
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	if events[1].Event != EventAgentOnline {
		t.Fatalf("event = %q, want %q", events[1].Event, EventAgentOnline)
	}

	// Same rule for nodes.
	nodeLastSeen := time.Now().UTC().Add(-2 * time.Minute)
	n := newTestNode(t, 22, "node_22", "edge-22", "", &nodeLastSeen)
	h.nodes.byID[22] = n
	h.nodes.offline = []*node.OfflineNodeInfo{
		{ID: 22, SID: "node_22", Name: "edge-22", LastSeenAt: nodeLastSeen},
	}

	h.run()
	events = h.waitEvents(t, 3)
	if events[2].Event != EventNodeOffline {
		t.Fatalf("event = %q, want %q", events[2].Event, EventNodeOffline)
	}

	h.nodes.offline = nil
	h.run()
	h.assertNoNewEvents(t, 3)
	if got := h.state.State(context.Background(), EntityKey("node", 22)); got != "offline" {
		t.Fatalf("state = %q, want offline to persist", got)
	}

	time.Sleep(5 * time.Millisecond)
	resumed := time.Now().UTC()
	h.nodes.byID[22] = newTestNode(t, 22, "node_22", "edge-22", "", &resumed)
	h.run()
	events = h.waitEvents(t, 4)
	if events[3].Event != EventNodeOnline {
		t.Fatalf("event = %q, want %q", events[3].Event, EventNodeOnline)
	}
}

func TestWatcherNodeOfflineAndOnline(t *testing.T) {
	h := newWatcherHarness(t)

	lastSeen := time.Now().UTC().Add(-10 * time.Minute)
	n := newTestNode(t, 3, "node_3", "edge-node", "203.0.113.9", &lastSeen)
	h.nodes.byID[3] = n
	h.nodes.offline = []*node.OfflineNodeInfo{
		{ID: 3, SID: "node_3", Name: "edge-node", LastSeenAt: lastSeen},
	}

	h.run()
	events := h.waitEvents(t, 1)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	offline := events[0]
	if offline.Event != EventNodeOffline {
		t.Fatalf("event = %q, want %q", offline.Event, EventNodeOffline)
	}
	if offline.Type != TypeOffline {
		t.Fatalf("type = %q, want %q", offline.Type, TypeOffline)
	}
	if offline.Entity != Entity("node", "edge-node") {
		t.Fatalf("entity = %q, want %q", offline.Entity, Entity("node", "edge-node"))
	}
	if got := detailID(t, offline); got != 3 {
		t.Fatalf("detail id = %d, want 3", got)
	}
	if got := detailString(t, offline, "sid"); got != "node_3" {
		t.Fatalf("detail sid = %q, want node_3", got)
	}
	if got := detailString(t, offline, "reason"); got != reasonHeartbeatTimeout {
		t.Fatalf("detail reason = %q, want %q", got, reasonHeartbeatTimeout)
	}
	if got, want := detailString(t, offline, "last_seen_at"), lastSeen.UTC().Format(time.RFC3339); got != want {
		t.Fatalf("detail last_seen_at = %q, want %q", got, want)
	}
	assertNoDetailKey(t, offline, "public_ipv4")

	// Consecutive stale pass emits nothing.
	h.run()
	h.assertNoNewEvents(t, 1)

	// The node reports again: the recorded offline edge recovers once.
	time.Sleep(5 * time.Millisecond)
	resumed := time.Now().UTC()
	recovered := newTestNode(t, 3, "node_3", "edge-node", "203.0.113.9", &resumed)
	h.nodes.byID[3] = recovered
	h.nodes.offline = nil

	h.run()
	events = h.waitEvents(t, 2)
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	online := events[1]
	if online.Event != EventNodeOnline {
		t.Fatalf("event = %q, want %q", online.Event, EventNodeOnline)
	}
	if online.Type != TypeOnline {
		t.Fatalf("type = %q, want %q", online.Type, TypeOnline)
	}
	if online.Entity != Entity("node", "edge-node") {
		t.Fatalf("entity = %q, want %q", online.Entity, Entity("node", "edge-node"))
	}
	if got := detailString(t, online, "reason"); got != reasonHeartbeatResumed {
		t.Fatalf("detail reason = %q, want %q", got, reasonHeartbeatResumed)
	}
	if got := detailString(t, online, "public_ipv4"); got != "203.0.113.9" {
		t.Fatalf("detail public_ipv4 = %q, want 203.0.113.9", got)
	}
	if detailString(t, online, "last_seen_at") == "" {
		t.Fatal("detail last_seen_at must be set")
	}

	h.run()
	h.assertNoNewEvents(t, 2)
}

func TestWatcherDisabledNotifierIsNoOp(t *testing.T) {
	lastSeen := time.Now().UTC().Add(-10 * time.Minute)
	agents := &fakeAgentSource{
		offline: []*forward.OfflineAgentInfo{
			{ID: 11, SID: "fa_11", Name: "edge-11", LastSeenAt: lastSeen},
		},
		byID: map[uint]*forward.ForwardAgent{},
	}
	state := NewStateStore(nil, logger.NewLogger())

	w := NewWatcher(agents, &fakeNodeSource{byID: map[uint]*node.Node{}}, NewNotifier(config.WebhookConfig{}, logger.NewLogger()), state, logger.NewLogger())
	w.Run(context.Background())

	if got := state.State(context.Background(), EntityKey("agent", 11)); got != "" {
		t.Fatalf("state = %q, want empty when the notifier is disabled", got)
	}
}

func TestWatcherNilStateOrNotifierIsNoOp(t *testing.T) {
	agents := &fakeAgentSource{byID: map[uint]*forward.ForwardAgent{}}

	NewWatcher(agents, &fakeNodeSource{byID: map[uint]*node.Node{}}, nil, NewStateStore(nil, logger.NewLogger()), nil).
		Run(context.Background())
	NewWatcher(agents, &fakeNodeSource{byID: map[uint]*node.Node{}}, nil, nil, nil).
		Run(context.Background())

	var nilWatcher *Watcher
	nilWatcher.Run(context.Background())
}

func TestWatcherFindOfflineFailureDoesNotBlockOtherHalf(t *testing.T) {
	h := newWatcherHarness(t)

	lastSeen := time.Now().UTC().Add(-10 * time.Minute)
	h.agents.findErr = errors.New("agent query failed")
	h.nodes.byID[5] = newTestNode(t, 5, "node_5", "edge-5", "", &lastSeen)
	h.nodes.offline = []*node.OfflineNodeInfo{
		{ID: 5, SID: "node_5", Name: "edge-5", LastSeenAt: lastSeen},
	}

	h.run()

	events := h.waitEvents(t, 1)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].Event != EventNodeOffline {
		t.Fatalf("event = %q, want %q", events[0].Event, EventNodeOffline)
	}
	assertNoDetailKey(t, events[0], "public_ipv4")
}

func TestWatcherMalformedStateKeyIsSkipped(t *testing.T) {
	h := newWatcherHarness(t)

	ctx := context.Background()
	if !h.state.Transition(ctx, "agent:not-a-number", "offline") {
		t.Fatal("failed to seed malformed state key")
	}

	h.run()

	h.assertNoNewEvents(t, 0)
	if got := h.state.State(ctx, "agent:not-a-number"); got != "offline" {
		t.Fatalf("state = %q, want offline (key must be left untouched)", got)
	}
}
