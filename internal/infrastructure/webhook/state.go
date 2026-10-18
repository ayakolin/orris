package webhook

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/orris-inc/orris/internal/shared/logger"
)

const (
	stateKeyPrefix = "nodewatch:state:"
	stateTTL       = 7 * 24 * time.Hour
)

// Snapshot is the recorded liveness state of one entity.
type Snapshot struct {
	State string
	Since time.Time
}

// StateStore tracks the last delivered liveness state per entity so that
// transitions (not samples) produce events. It is shared by the WebSocket
// callbacks and the heartbeat watcher, which both observe the same resources.
//
// Each entry records the state and the instant it was entered. The watcher uses
// Since to avoid reporting a recovery from a last_seen_at sample that predates
// the offline edge (a socket that just closed while its heartbeat was still
// fresh must not immediately look recovered).
//
// When Redis is unavailable the store falls back to an in-process map; in a
// multi-instance deployment that fallback can duplicate events, so Redis is the
// normal path.
type StateStore struct {
	client *redis.Client
	logger logger.Interface
	ttl    time.Duration
	now    func() time.Time

	mu  sync.Mutex
	mem map[string]memState
}

type memState struct {
	state   string
	since   time.Time
	members map[string]struct{}
	expires time.Time
}

// NewStateStore creates a store backed by Redis. A nil client selects the
// in-memory fallback (used by tests).
func NewStateStore(client *redis.Client, log logger.Interface) *StateStore {
	if log == nil {
		log = logger.NewLogger()
	}
	return &StateStore{
		client: client,
		logger: log,
		ttl:    stateTTL,
		now:    time.Now,
		mem:    make(map[string]memState),
	}
}

// Transition atomically moves key to state and reports whether this call was
// the one that changed it. Only the winning caller should emit an event.
// Re-entering the same state is a no-op, so repeated observations cannot
// produce duplicate events.
func (s *StateStore) Transition(ctx context.Context, key, state string) bool {
	if key == "" || state == "" {
		return false
	}
	fullKey := stateKeyPrefix + key
	now := s.now().UTC()

	if s.client == nil {
		return s.transitionMemory(fullKey, state, now)
	}

	// Compare-and-set so concurrent observers (hub callback and watcher) cannot
	// both emit the same edge.
	script := redis.NewScript(`
		local key = KEYS[1]
		local target = ARGV[1]
		local ts = ARGV[2]
		local ttl = tonumber(ARGV[3])
		local current = redis.call('HGET', key, 's')
		if current == target then
			return 0
		end
		redis.call('HSET', key, 's', target, 't', ts)
		redis.call('EXPIRE', key, ttl)
		return 1
	`)
	res, err := script.Run(ctx, s.client, []string{fullKey},
		state, strconv.FormatInt(now.Unix(), 10), int(s.ttl.Seconds())).Int()
	if err != nil {
		s.logger.Warnw("failed to transition webhook state", "key", key, "error", err)
		return false
	}
	return res == 1
}

// State returns the recorded state, or "" if unknown.
func (s *StateStore) State(ctx context.Context, key string) string {
	snap, ok := s.snapshotOne(ctx, stateKeyPrefix+key)
	if !ok {
		return ""
	}
	return snap.State
}

// snapshotOne returns the recorded state for one fully-qualified Redis key.
func (s *StateStore) snapshotOne(ctx context.Context, fullKey string) (Snapshot, bool) {
	if s.client == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		entry, ok := s.mem[fullKey]
		if !ok || !entry.expires.After(s.now()) {
			delete(s.mem, fullKey)
			return Snapshot{}, false
		}
		return Snapshot{State: entry.state, Since: entry.since}, true
	}

	values, err := s.client.HGetAll(ctx, fullKey).Result()
	if err != nil {
		s.logger.Warnw("failed to read webhook state", "key", fullKey, "error", err)
		return Snapshot{}, false
	}
	if len(values) == 0 {
		return Snapshot{}, false
	}
	since, _ := strconv.ParseInt(values["t"], 10, 64)
	return Snapshot{State: values["s"], Since: time.Unix(since, 0).UTC()}, true
}

// Snapshot returns the recorded states of entity keys whose name starts with
// prefix (e.g. "agent:"). Unknown keys are omitted.
func (s *StateStore) Snapshot(ctx context.Context, prefix string) map[string]Snapshot {
	fullPrefix := stateKeyPrefix + prefix
	out := make(map[string]Snapshot)

	if s.client == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		now := s.now()
		for key, entry := range s.mem {
			if !entry.expires.After(now) {
				delete(s.mem, key)
				continue
			}
			if strings.HasPrefix(key, fullPrefix) {
				out[strings.TrimPrefix(key, stateKeyPrefix)] = Snapshot{State: entry.state, Since: entry.since}
			}
		}
		return out
	}

	iter := s.client.Scan(ctx, 0, fullPrefix+"*", 100).Iterator()
	for iter.Next(ctx) {
		fullKey := iter.Val()
		if snap, ok := s.snapshotOne(ctx, fullKey); ok {
			out[strings.TrimPrefix(fullKey, stateKeyPrefix)] = snap
		}
	}
	if err := iter.Err(); err != nil {
		s.logger.Warnw("failed to scan webhook state", "prefix", prefix, "error", err)
	}
	return out
}

func (s *StateStore) transitionMemory(key, state string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.mem[key]; ok && entry.expires.After(now) && entry.state == state {
		return false
	}
	s.mem[key] = memState{state: state, since: now, expires: now.Add(s.ttl)}
	return true
}

// SetTransition adds (present=true) or removes (present=false) member in the
// set at key and reports whether this call moved the set between empty and
// non-empty. Rule-level events are aggregated this way: several agents report
// the same rule, and the rule is only "failed" while at least one of them is
// failing, so a healthy peer cannot flap the state each report cycle.
func (s *StateStore) SetTransition(ctx context.Context, key, member string, present bool) (becameNonEmpty, becameEmpty bool) {
	if key == "" || member == "" {
		return false, false
	}
	fullKey := stateKeyPrefix + key
	now := s.now().UTC()

	if s.client == nil {
		return s.setTransitionMemory(fullKey, member, present, now)
	}

	script := redis.NewScript(`
		local key = KEYS[1]
		local member = ARGV[1]
		local add = ARGV[2] == '1'
		local ttl = tonumber(ARGV[3])
		local before = redis.call('SCARD', key)
		if add then
			redis.call('SADD', key, member)
		else
			redis.call('SREM', key, member)
		end
		local after = redis.call('SCARD', key)
		if after > 0 then
			redis.call('EXPIRE', key, ttl)
		end
		return {before, after}
	`)
	raw, err := script.Run(ctx, s.client, []string{fullKey}, member, boolArg(present), int(s.ttl.Seconds())).Result()
	if err != nil {
		s.logger.Warnw("failed to transition webhook state set", "key", key, "error", err)
		return false, false
	}
	res, ok := raw.([]any)
	if !ok || len(res) != 2 {
		return false, false
	}
	before, _ := res[0].(int64)
	after, _ := res[1].(int64)
	return before == 0 && after > 0, before > 0 && after == 0
}

func boolArg(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func (s *StateStore) setTransitionMemory(key, member string, present bool, now time.Time) (bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.mem[key]
	if !ok || !entry.expires.After(now) {
		entry = memState{members: make(map[string]struct{}), expires: now.Add(s.ttl)}
	}
	if entry.members == nil {
		entry.members = make(map[string]struct{})
	}

	before := len(entry.members)
	if present {
		entry.members[member] = struct{}{}
	} else {
		delete(entry.members, member)
	}
	after := len(entry.members)

	entry.expires = now.Add(s.ttl)
	s.mem[key] = entry

	return before == 0 && after > 0, before > 0 && after == 0
}

// EntityKey formats the state store key for a resource kind and id.
func EntityKey(kind string, id uint) string {
	return kind + ":" + strconv.FormatUint(uint64(id), 10)
}
