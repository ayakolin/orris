# Node-Watch Webhook Events

Orris emits signed events for agent, node and forward-rule liveness plus node
subscription quota crossings. Events are POSTed to a single receiver endpoint
that is expected to react to them (the xboard plugin implements this contract).

Delivery is fire-and-forget: the panel never blocks on the receiver, and events
are not persisted. Losing events when the receiver or network is down for long
enough is expected.

## Configuration

```yaml
webhook:
  url: ""                       # ORRIS_WEBHOOK_URL (receiver endpoint, e.g. http://127.0.0.1:9787/event)
  secret: ""                    # ORRIS_WEBHOOK_SECRET (HMAC-SHA256 signing key shared with the receiver)
  traffic_threshold_percent: 90 # ORRIS_WEBHOOK_TRAFFIC_THRESHOLD_PERCENT (default 90; 0 disables traffic.threshold)
```

| Env var | Config key | Default | Meaning |
| --- | --- | --- | --- |
| `ORRIS_WEBHOOK_URL` | `webhook.url` | empty | Receiver endpoint, must be an absolute `http`/`https` URL. |
| `ORRIS_WEBHOOK_SECRET` | `webhook.secret` | empty | Shared HMAC-SHA256 key. |
| `ORRIS_WEBHOOK_TRAFFIC_THRESHOLD_PERCENT` | `webhook.traffic_threshold_percent` | `90` | Usage percentage of a plan/override limit that triggers `traffic.threshold`. `0` disables `traffic.threshold` entirely. |

Env vars override config values using the `ORRIS_<SECTION>_<KEY>` convention
(for example `ORRIS_WEBHOOK_URL`, `ORRIS_WEBHOOK_SECRET`,
`ORRIS_WEBHOOK_TRAFFIC_THRESHOLD_PERCENT`).

### Disabled semantics

The feature is active only when **both** `url` and `secret` are non-empty.

- Empty `url` or empty `secret`: the notifier is a no-op (`Enabled()` is false).
  No worker goroutine and no queue are created, `Emit` returns immediately, and
  every emitter (agent, node, rule, traffic) short-circuits. Nothing is sent and
  nothing is logged per event.
- Non-empty `url` and `secret`: one worker goroutine per process drains the
  queue. Restart/redeploy the panel to pick up config changes.

## Delivery semantics

Requests are asynchronous and best-effort.

- **Async queue.** `Emit` only enqueues and returns; it never blocks the caller
  or the WebSocket/HTTP path that triggered the event. A single worker goroutine
  delivers events in queue order.
- **Bounded queue.** The queue holds 256 events. When it is full the event is
  dropped and a warning is logged with the event and entity (never the secret);
  the caller is not notified.
- **Timeout.** 5 seconds per HTTP attempt.
- **Retries.** Up to 3 attempts in total for network errors and `5xx` responses,
  with a 1s then 4s backoff between attempts. Any other non-2xx status (for
  example `400`/`401`) is *not* retried. The timestamp and signature are
  regenerated for each attempt; the JSON body is serialized once.
- **Shutdown.** In-flight retries are aborted and queued events are discarded
  when the process stops.
- **Dedupe.** Liveness and rule events are edge-triggered: the shared
  `webhook.StateStore` records the last delivered state per entity and only the
  caller that actually changes it emits. The WebSocket hub callbacks and the
  1-minute heartbeat watcher observe the same resources through the same store,
  so one outage/resume produces exactly one event per entity (see
  [Operations notes](#operations-notes) for multi-instance behavior).

### Request format

```
POST <url>
Content-Type: application/json
X-NodeWatch-Timestamp: <unix seconds>
X-NodeWatch-Signature: sha256=<lowercase hex HMAC-SHA256(secret, "<timestamp>.<raw body>")>
X-NodeWatch-Event: <event name>
```

```json
{
  "source": "orris",
  "event": "agent.offline",
  "type": "offline",
  "entity": "agent:hk-01",
  "ts": 1760860260,
  "detail": {}
}
```

| Field | Description |
| --- | --- |
| `source` | Always `orris`. |
| `event` | Event name, identical to the `X-NodeWatch-Event` header. |
| `type` | `offline`, `online` or `alert`; derived from the event name. |
| `entity` | `<kind>:<name>` where kind is `agent`, `node` or `rule`. |
| `ts` | Unix seconds when the event was enqueued (per attempt for the header). |
| `detail` | Event-specific object; omitted when empty. |

## Event reference

| Event | Type | Entity | Emitted when | `detail` |
| --- | --- | --- | --- | --- |
| `agent.offline` | `offline` | `agent:<name>` | Agent WebSocket closed, or the heartbeat watcher sees `last_seen_at` older than 5 minutes while the socket is still open. | `id`, `sid`, `name`, `last_seen_at` (RFC3339 UTC), `public_ipv4` (only for a literal IPv4 public address), `reason` |
| `agent.online` | `online` | `agent:<name>` | Agent WebSocket connected, or the heartbeat watcher sees a fresh `last_seen_at` after a timeout. | same as `agent.offline`; during a reconnect, `last_seen_at` is the connection time because the persisted value is only refreshed by the next heartbeat |
| `node.offline` | `offline` | `node:<name>` | Node WebSocket closed, or the heartbeat watcher times the node out. | `id`, `sid`, `name`, `last_seen_at`, `public_ipv4` (when set), `reason` |
| `node.online` | `online` | `node:<name>` | Node WebSocket connected, or the heartbeat watcher sees it resume. | same as `node.offline`; `last_seen_at` follows the same connection-time rule as agents |
| `rule.failed` | `offline` | `rule:<name>` | Agent-reported rule status turns failed: `sync_status = failed`, or `run_status` is `error`/`stopped`. | `rule_id` (rule SID), `name`, `agent_id`, `sync_status`, `run_status`, `error_message`, `last_check_at` |
| `rule.recovered` | `online` | `rule:<name>` | Agent-reported rule status is healthy again: `sync_status = synced` **and** `run_status = running`. | same as `rule.failed` |
| `traffic.threshold` | `alert` | `node:<name>` | A node subscription's usage reaches `traffic_threshold_percent` of its plan/override limit (re-armed once usage drops below the threshold). | `id`, `sid`, `name`, `subscription_id`, `used_bytes`, `limit_bytes`, `percent`, `threshold_percent`, `last_check_at`, `public_ipv4` (when set) |

`reason` values for liveness events: `websocket_closed`, `websocket_connected`,
`heartbeat_timeout`, `heartbeat_resumed`.

Notes on the individual emitters:

- **Agent liveness.** Emitted from the forwarded-agent hub connect/disconnect
  callbacks and from the heartbeat watcher. Every minute the watcher looks for
  agents whose `last_seen_at` is older than 5 minutes and marks them offline even
  if the WebSocket is still open; a recorded offline state is cleared when a
  fresh heartbeat or a new connection arrives. Both observers share the state
  store, so a socket close and a simultaneous timeout do not double-emit.
- **Node liveness.** Same two sources and the same 5-minute timeout / 1-minute
  cadence as agents.
- **Forward rules.** Forward agents report per-rule status
  (`sync_status`/`run_status`) over WebSocket and REST; it is kept in Redis under
  `forward_agent:{agent_id}:rule_status`. Only the two decisive combinations
  above produce events, so transitional states such as `pending` or `starting`
  never flap. Every agent in a forwarding chain reports the same rule, so
  failures are tracked as a set of failing agents per rule: `rule.failed` is
  emitted when the first agent starts failing and `rule.recovered` only when the
  last failing agent reports healthy again. A healthy peer therefore cannot
  "recover" a rule that another agent still reports as broken. The detail's
  `last_check_at` is the time the panel processed the report.
- **Traffic.** Detected while processing node traffic reports. Forward agents and
  forward rules have no per-entity traffic quota in Orris — limits live on
  subscription plans — so `traffic.threshold` is emitted only for
  node-subscription quota crossings and is attributed to the node that reported
  the traffic. `percent` is `used_bytes / limit_bytes * 100`, rounded to two
  decimals; `limit_bytes = 0` (unlimited) is ignored. There is no recovery event:
  the threshold re-arms silently once usage falls below it, allowing a later
  crossing to emit again.

### Examples

Agent family (`agent.online` uses the same shape with `"type": "online"` and a
`heartbeat_resumed`/`websocket_connected` reason):

```json
{
  "source": "orris",
  "event": "agent.offline",
  "type": "offline",
  "entity": "agent:hk-01",
  "ts": 1760860260,
  "detail": {
    "id": 12,
    "sid": "fa_xK9mP2vL3nQ",
    "name": "hk-01",
    "last_seen_at": "2026-10-19T08:25:41Z",
    "public_ipv4": "203.0.113.7",
    "reason": "heartbeat_timeout"
  }
}
```

Node family:

```json
{
  "source": "orris",
  "event": "node.offline",
  "type": "offline",
  "entity": "node:jp-02",
  "ts": 1760860320,
  "detail": {
    "id": 4,
    "sid": "node_7YtRm4QpX2",
    "name": "jp-02",
    "last_seen_at": "2026-10-19T08:31:58Z",
    "public_ipv4": "198.51.100.23",
    "reason": "websocket_closed"
  }
}
```

Rule family:

```json
{
  "source": "orris",
  "event": "rule.failed",
  "type": "offline",
  "entity": "rule:HK -> JP relay",
  "ts": 1760860380,
  "detail": {
    "rule_id": "fr_xK9mP2vL3nQ",
    "name": "HK -> JP relay",
    "agent_id": 12,
    "sync_status": "synced",
    "run_status": "error",
    "error_message": "dial tcp 10.20.0.5:8443: connect: connection refused",
    "last_check_at": "2026-10-19T08:33:00Z"
  }
}
```

Traffic family:

```json
{
  "source": "orris",
  "event": "traffic.threshold",
  "type": "alert",
  "entity": "node:jp-02",
  "ts": 1760860440,
  "detail": {
    "id": 4,
    "sid": "node_7YtRm4QpX2",
    "name": "jp-02",
    "subscription_id": 8421,
    "used_bytes": 99000000000,
    "limit_bytes": 107374182400,
    "percent": 92.2,
    "threshold_percent": 90,
    "last_check_at": "2026-10-19T08:34:00Z",
    "public_ipv4": "198.51.100.23"
  }
}
```

## Signature verification

The signature covers the timestamp header and the **raw request body**:

```
sha256=<lowercase hex HMAC-SHA256(secret, "<timestamp>.<raw body>")>
```

Verify before parsing or acting on the event, read the body once, and compare in
constant time. Reject timestamps that are more than 300 seconds away from the
receiver's clock to block replays.

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

const maxSkew = 300 * time.Second

// verifyNodeWatch checks the signature headers against the raw body.
func verifyNodeWatch(secret string, r *http.Request, body []byte, now time.Time) error {
	tsRaw := r.Header.Get("X-NodeWatch-Timestamp")
	ts, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return errors.New("missing or invalid timestamp")
	}

	skew := now.Unix() - ts
	if skew < 0 {
		skew = -skew
	}
	if time.Duration(skew)*time.Second > maxSkew {
		return errors.New("stale timestamp")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%s.", tsRaw) // exact timestamp string from the header
	mac.Write(body)                // raw body, before any JSON decoding
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	// hmac.Equal is a constant-time comparison; do not use == on strings.
	if !hmac.Equal([]byte(want), []byte(r.Header.Get("X-NodeWatch-Signature"))) {
		return errors.New("bad signature")
	}
	return nil
}

// handle is the receiver entry point for node-watch events.
func handle(w http.ResponseWriter, r *http.Request, secret string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "cannot read body", http.StatusBadRequest)
		return
	}

	if err := verifyNodeWatch(secret, r, body, time.Now()); err != nil {
		// 401 signals a bad signature or a stale timestamp; the panel does
		// not retry 4xx responses.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var ev struct {
		Source string         `json:"source"`
		Event  string         `json:"event"`
		Type   string         `json:"type"`
		Entity string         `json:"entity"`
		TS     int64          `json:"ts"`
		Detail map[string]any `json:"detail"`
	}
	if err := json.Unmarshal(body, &ev); err != nil {
		// Body signature was valid but the JSON is malformed.
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// ... act on ev ...

	w.WriteHeader(http.StatusAccepted) // 202: accepted, no retry
}
```

The panel signs the decimal unix timestamp it writes to the header, so signing
the header string directly (as above) matches the panel byte for byte.

Receiver responses seen by the panel:

| Status | Meaning for the panel |
| --- | --- |
| `2xx` (expected `202`) | Accepted; the event is done. |
| `401` | Bad signature or stale timestamp; **not** retried. |
| `400` | Malformed JSON; **not** retried. |
| `5xx` | Retried, up to 3 attempts with 1s/4s backoff. |

## Operations notes

- **Secrets in logs.** The signing secret is never logged, and neither are the
  request body nor the full URL. Delivery failures log the event name, the
  entity, the attempt count, the status or error, and only the receiver *host*
  extracted from the URL (paths and query strings may embed credentials).
- **Receiver expectations.** Respond quickly; the panel reads and closes your
  response body but waits at most 5 seconds. Verify the signature before
  decoding, and be prepared for duplicate delivery: retries and multi-instance
  fallback (below) can produce the same event more than once, so handlers should
  be idempotent per `event`/`entity`/`ts`.
- **Multi-instance behavior.** Dedupe state lives in Redis under
  `nodewatch:state:<kind>:<id>` (`kind` is `agent`, `node`, `rule` or `traffic`;
  `id` is the numeric DB id for agents/nodes/subscriptions and the rule SID for
  rules), with a 7-day TTL. The compare-and-set transition runs in Redis, so with
  multiple panel instances only the instance that wins the transition emits the
  event. If Redis is unavailable the store falls back to an in-process map: the
  webhook keeps working, but each instance then tracks state independently and
  duplicate events for the same transition are possible.
- **Ordering.** Order is preserved within a single process queue; across
  instances, restarts or retries there is no global ordering guarantee.
- **Backpressure.** A burst larger than 256 pending events drops the excess
  (logged as warnings) rather than blocking the panel.
- **No replay.** Queued events are discarded on shutdown, and events emitted
  while the feature is disabled are gone permanently; keep monitoring aligned
  with the receiver rather than relying on the panel to backfill.
