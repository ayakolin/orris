# Admin API Token Documentation

Admin API tokens authenticate automated clients against the panel's admin API without a browser session. They are intended for scripts, CI jobs, and internal tooling that must call endpoints under `/admin` and `/forward-rules`.

## Base URL

All examples use:

```bash
BASE=https://panel.example.com/api
```

## 1. Token Format and Security Model

### Format

```
orr_<base64url(32 random bytes)>
```

- The `orr_` prefix identifies the credential as an admin API token before any parsing happens.
- The random part is 32 bytes (256 bits) from `crypto/rand`, encoded with unpadded base64url, so the value is 43 characters and safe to paste into a shell variable or an HTTP header.
- The display hint stored with the record is `orr_` plus the first 8 characters of the random part, for example `orr_AbCdEfGh`. The hint is not a secret and cannot authenticate anything.

### What is stored

Only a SHA-256 hex digest of the full token value is persisted, in `admin_api_tokens.token_hash`. Authentication hashes the presented value and looks it up through a unique index; the plaintext is never written to the database, logs, or the audit trail.

Because of this, the plaintext is returned exactly once, in the response body of the create call. It cannot be retrieved again. If it is lost, revoke the token and create a new one.

### What the token can do

A token authenticates **as the admin user who created it**, using that user's live role and status. It never grants more than that user currently has:

- The owner is re-read from the database on every request.
- If the owner is deleted, the token stops working immediately.
- If the owner is disabled or suspended, the token stops working immediately.
- If the owner is demoted from admin, the token stops working immediately.
- The token inherits the owner's current role, not the role at creation time.

Additional properties:

| Property | Behaviour |
| --- | --- |
| Expiry | Optional. `expires_at` must be in the future at creation time; `null` means no expiry. |
| Revocation | `POST /admin/api-tokens/:id/revoke` makes the token unusable immediately. Revocation is idempotent. |
| Deletion | `DELETE /admin/api-tokens/:id` removes the record permanently. |
| Scope | A token can only be seen and managed by its owner. Listing and reading are scoped to the caller. |
| `last_used_at` | Updated at most once per minute per token, so authentication does not write on every request. A failed update never fails the request. |
| Token management | A request authenticated by a token cannot create, list, read, revoke, or delete tokens, and is likewise rejected on every other credential, session, and account-management route. Those routes require an interactive cookie session (see "What a token cannot do"). |

Token record IDs use the `apt_` prefix (for example `apt_xK9mP2vL3nQ`); forward rule IDs use `fr_`, forward agent IDs use `fa_`.

## 2. Token Management Endpoints

All routes below require `RequireAuth` + admin role + an interactive session (`RequireSessionAuth`). They are registered under `/admin/api-tokens` and are not exempt from CSRF validation, so cookie-authenticated calls must send `X-CSRF-Token`.

| Method | Path | Body | Result |
| --- | --- | --- | --- |
| `POST` | `/admin/api-tokens` | `name` (required, max 100), `expires_at` (optional RFC 3339 timestamp) | `201` with the token record **and** `data.token` (plaintext, shown once) |
| `GET` | `/admin/api-tokens` | none | `200` with an array of token records owned by the caller |
| `GET` | `/admin/api-tokens/:id` | none | `200` with one token record, or `404` if it is not owned by the caller |
| `POST` | `/admin/api-tokens/:id/revoke` | none | `200`, no data. Revoking an already revoked token also succeeds |
| `DELETE` | `/admin/api-tokens/:id` | none | `204` with no body |

Token record fields:

| Field | Type | Notes |
| --- | --- | --- |
| `id` | string | Token record ID, `apt_...` |
| `name` | string | Human-readable label |
| `token_hint` | string | `orr_` plus 8 characters; safe to display |
| `created_by` | string | Owner user ID, `usr_...` |
| `last_used_at` | string \| null | Last successful authentication, throttled to one write per minute |
| `expires_at` | string \| null | `null` means no expiry |
| `revoked_at` | string \| null | `null` means active |
| `created_at` | string | Creation timestamp |
| `updated_at` | string | Last update timestamp |
| `token` | string | **Create response only.** Plaintext credential; never returned again |

Session requirement: a request authenticated by an API token receives `403` with the message below. The same guard protects every credential- and account-management route, not only token management; see "What a token cannot do" in section 4 for the full list and the resulting blast radius.

```
this endpoint requires an interactive session; admin API tokens cannot manage credentials
```

## 3. Walkthrough

### 3.1 Log in and keep a cookie jar

Login is exempt from CSRF validation. The response sets the `access_token` and `refresh_token` cookies (HttpOnly) and a readable `csrf_token` cookie.

```bash
BASE=https://panel.example.com/api
JAR=./.admin-cookies.txt

curl -sS -c "$JAR" -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "your-password",
    "remember_me": true
  }'
```

Extract the CSRF value from the jar for later mutating requests:

```bash
CSRF=$(awk '$6 == "csrf_token" {print $7}' "$JAR")
```

### 3.2 Create a token

`expires_at` is optional and must be in the future. Omit it for a token that does not expire.

```bash
curl -sS -b "$JAR" -c "$JAR" -X POST "$BASE/admin/api-tokens" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF" \
  -d '{
    "name": "deploy-bot",
    "expires_at": "2027-01-01T00:00:00Z"
  }'
```

Response (`201 Created`):

```json
{
  "success": true,
  "data": {
    "id": "apt_xK9mP2vL3nQ",
    "name": "deploy-bot",
    "token_hint": "orr_AbCdEfGh",
    "created_by": "usr_yL8nQ3wM4oR",
    "expires_at": "2027-01-01T00:00:00Z",
    "created_at": "2026-10-18T09:12:31Z",
    "updated_at": "2026-10-18T09:12:31Z",
    "token": "orr_pQ7rS2tU5vW8xY1zA4bC6dE9fG0hJ3kL5mN7oP2qR4s"
  },
  "message": "Admin API token created. Copy the token now: it will not be shown again."
}
```

`last_used_at` and `revoked_at` are omitted while they are `null`.

> **Warning**: `data.token` is unrecoverable. It is stored only as a SHA-256 hash. If you lose it, revoke the token and create another one. Do not paste it into shell history on shared hosts; capture it directly into a variable or a secret store.

Capture the token into a variable:

```bash
TOKEN=$(curl -sS -b "$JAR" -c "$JAR" -X POST "$BASE/admin/api-tokens" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF" \
  -d '{"name":"deploy-bot"}' | jq -r '.data.token')
```

### 3.3 List tokens

```bash
curl -sS -b "$JAR" "$BASE/admin/api-tokens"
```

The `data` field is an array of token records. No plaintext token is present.

```json
{
  "success": true,
  "data": [
    {
      "id": "apt_xK9mP2vL3nQ",
      "name": "deploy-bot",
      "token_hint": "orr_AbCdEfGh",
      "created_by": "usr_yL8nQ3wM4oR",
      "last_used_at": "2026-10-18T10:03:00Z",
      "created_at": "2026-10-18T09:12:31Z",
      "updated_at": "2026-10-18T10:03:00Z"
    }
  ],
  "message": "success"
}
```

### 3.4 Get one token

```bash
curl -sS -b "$JAR" "$BASE/admin/api-tokens/apt_xK9mP2vL3nQ"
```

### 3.5 Revoke a token

Revocation takes effect on the next request. The record stays visible with `revoked_at` set.

```bash
curl -sS -b "$JAR" -c "$JAR" -X POST "$BASE/admin/api-tokens/apt_xK9mP2vL3nQ/revoke" \
  -H "X-CSRF-Token: $CSRF"
```

```json
{
  "success": true,
  "message": "Admin API token revoked successfully"
}
```

### 3.6 Delete a token

Deletion removes the record permanently.

```bash
curl -sS -b "$JAR" -c "$JAR" -X DELETE "$BASE/admin/api-tokens/apt_xK9mP2vL3nQ" \
  -H "X-CSRF-Token: $CSRF" \
  -i
```

Response: `204 No Content`, empty body.

## 4. Using the Token

Send the token as a bearer credential. Nothing else is required.

```bash
curl -sS "$BASE/forward-rules?page=1&page_size=20" \
  -H "Authorization: Bearer $TOKEN"
```

- No cookies are needed. Do not send a cookie jar with the request.
- No `X-CSRF-Token` header is needed.
- No cookie refresh happens. There is no session and no sliding expiry; only `expires_at`, revocation, or the owner's state can end access.
- An explicit `Bearer orr_...` header takes precedence over any cookies on the same request: the request is authenticated by the token, not by the session. Do not mix them anyway — carrying a cookie makes the CSRF check apply again (see section 5), so send either a cookie session or a bearer token.

A request with a token that is unknown, revoked, expired, or owned by a deleted user returns `401` with `"invalid or expired token"`. A token owned by a disabled or demoted user returns `403` with the same message.

### What a token cannot do

A token authenticates as its owning admin on every non-credential admin route: forward rules, forward agents, nodes, resources, and most `/admin` endpoints (subscriptions, resource groups, traffic stats, settings, dashboard). On that surface it carries the same authority and role as that admin's cookie session, subject only to the CSRF difference described in section 5.

Credential, session, and account-management routes are **session-only**. A token is rejected there with `403` before the handler runs. The guarded routes are:

- token management: `POST`/`GET /admin/api-tokens`, `GET /admin/api-tokens/:id`, `POST /admin/api-tokens/:id/revoke`, `DELETE /admin/api-tokens/:id`
- passkey registration: `POST /auth/passkey/register/start`, `POST /auth/passkey/register/finish`
- account management: `POST /users`, `PATCH /users/me`, `PUT /users/me/password`, `GET /users/me/passkeys`, `DELETE /users/me/passkeys/:id`, `PATCH /users/:id`, `DELETE /users/:id`, `PATCH /users/:id/password`

Read-only user routes (`GET /users`, `GET /users/:id`, `GET /users/email/:email`, `GET /users/me/dashboard`, `GET /auth/me`) and every forward/agent/node/rule route still accept tokens.

The body is a normal error envelope:

```bash
curl -sS -X PUT "$BASE/users/me/password" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"old_password":"old-password","new_password":"new-password"}'
```

```json
{
  "success": false,
  "error": {
    "type": "error",
    "message": "this endpoint requires an interactive session; admin API tokens cannot manage credentials"
  }
}
```

So a leaked token can act as that admin everywhere else — create, edit, and delete forward rules and agents, retarget landing addresses, and read or change the rest of the admin surface — but its blast radius stops short of credential minting: it cannot create new credentials, change passwords, register passkeys, or alter roles.

If a token leaks, revoke it immediately with `POST /admin/api-tokens/:id/revoke` using a cookie session. Resetting the owner's password or deleting the owner also revokes their tokens; see below.

### Owner-triggered revocation

Some account operations revoke the target user's admin API tokens as part of the operation, through `RevokeByUserID` on the token repository:

- `PATCH /users/:id/password` (admin password reset) revokes every active token owned by that user after invalidating their sessions. A reset is a remediation action, so tokens must not outlive it.
- `DELETE /users/:id` revokes the user's tokens before deleting the account.

Both are best-effort: sessions are cleared and the password/account change proceeds even if the token revocation write fails, because the token of a deleted, disabled, or demoted user fails authentication anyway (the owner is re-read on every request). The revocation is what makes the failure explicit in the token record rather than only at authentication time.

Resetting or deleting a user does not affect tokens owned by other admins.

### Logout does not apply to tokens

Token authentication is stateless: it creates no session, so `POST /auth/logout` is not meaningful for a token. The handler requires a `session_id` in the request context, which only a cookie session provides; a token request therefore returns `401` with `"session not found"`, clears nothing, and leaves the token valid.

To end a token's access, use `POST /admin/api-tokens/:id/revoke` (immediate, idempotent) or `DELETE /admin/api-tokens/:id` (permanent) with an interactive cookie session. Do not call logout to retire a token.

## 5. CSRF Behaviour

CSRF protection uses the double-submit cookie pattern: for `POST`, `PUT`, `PATCH`, and `DELETE`, the `csrf_token` cookie must match the `X-CSRF-Token` header. `GET`, `HEAD`, and `OPTIONS` are always skipped. So are a fixed set of unauthenticated exact paths (`/auth/login`, `/auth/register`, `/auth/verify-email`, `/auth/forgot-password`, `/auth/reset-password`, `/auth/refresh`, `/auth/logout`, `/payments/callback`) and prefixes (`/auth/oauth/`, `/auth/passkey/login/`, `/auth/passkey/signup/`, `/webhooks/`, `/agents/`, `/forward-agent-api/`, `/ws/`). The admin token management routes are not on either list.

There is one additional skip, and its rule is exact:

> The CSRF check is skipped **only** when the `Authorization` header carries a bearer credential whose value starts with `orr_`, **and** the request carries neither an `access_token` cookie nor a `refresh_token` cookie. The scheme must be exactly `Bearer`, with a single space before the credential; the match is case-sensitive and mirrors `RequireAuth`, which parses the header the same way.

An empty or non-bearer `Authorization` header does not qualify, and neither does a value with a different prefix. A `Bearer orr_...` header with either auth cookie present still goes through the normal double-submit check. A header that is not exactly `Bearer orr_...` — for example `bearer orr_...` or `Bearer  orr_...` (two spaces) — is not skipped: on a write it is rejected by the normal double-submit check (or by `RequireAuth` when no cookie is present).

### Why this is safe

- **A browser cannot produce a cookie-less cross-site request.** A cross-site form post or fetch always attaches the target site's cookies. If either auth cookie is present, the request falls through to the normal check, so cookie sessions keep exactly the protection they had before.
- **The skip never authenticates anything.** This middleware runs before `RequireAuth`, and the skip only inspects the request shape. `RequireAuth` still validates the token: hash lookup, revocation, expiry, and an active admin owner. An invalid token gets `401`; the skip alone never grants access.
- **Forging the request requires possessing the secret.** Without cookies, an authenticated request is only possible if the caller already holds the token, which is not something a third-party site can supply on a victim's behalf.
- **Cookie sessions are unchanged.** No cookie name, attribute, or CSRF rule for sessions was altered. A token-authenticated request simply skips a check that exists to protect cookies it does not use.

## 6. Forward Rule List Filters

`GET /forward-rules` accepts the existing filters and two target-related ones. The pre-existing filters (`name`, `protocol`, `status`, `include_user_rules`, pagination, and ordering) behave exactly as before; `agent_id` and `target_address` are additions.

| Query parameter | Match | Notes |
| --- | --- | --- |
| `agent_id` | exact | Forward agent ID (`fa_...`). An invalid prefix returns `400`. |
| `target_address` | exact | Static target address. Node-linked rules have no static address and do not match. |
| `name` | partial | Rule name |
| `protocol` | exact | Rule protocol |
| `status` | exact | `enabled` or `disabled` |
| `include_user_rules` | boolean string | `true` includes user-owned rules |
| `page`, `page_size` | numbers | Defaults apply; `page_size` is capped by the server |
| `order_by`, `order` | strings | Sort column and direction |

An `agent_id` that is well-formed but refers to no existing agent returns an empty page rather than an error.

Filter by agent:

```bash
curl -sS "$BASE/forward-rules?agent_id=fa_xK9mP2vL3nQ&page=1&page_size=50" \
  -H "Authorization: Bearer $TOKEN"
```

Filter by static target address (URL-encode the value; `--data-urlencode` handles IPv6 and special characters):

```bash
curl -sS --get "$BASE/forward-rules" \
  --data-urlencode "target_address=203.0.113.10" \
  --data-urlencode "page=1" \
  --data-urlencode "page_size=50" \
  -H "Authorization: Bearer $TOKEN"
```

The result is the usual paginated envelope:

```json
{
  "success": true,
  "data": {
    "items": [
      {
        "id": "fr_xK9mP2vL3nQ",
        "name": "mysql-primary",
        "agent_id": "fa_yL8nQ3wM4oR",
        "rule_type": "direct",
        "target_address": "203.0.113.10",
        "target_port": 3306,
        "status": "enabled"
      }
    ],
    "total": 1,
    "page": 1,
    "page_size": 50,
    "total_pages": 1
  }
}
```

Combine filters freely; they are ANDed.

```bash
curl -sS --get "$BASE/forward-rules" \
  --data-urlencode "agent_id=fa_xK9mP2vL3nQ" \
  --data-urlencode "target_address=203.0.113.10" \
  --data-urlencode "status=enabled" \
  -H "Authorization: Bearer $TOKEN"
```

## 7. Batch Update of Static Targets

`PATCH /forward-rules/batch` updates up to 100 rules and supports `target_address` and `target_port` in each item.

```bash
curl -sS -X PATCH "$BASE/forward-rules/batch" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "updates": [
      {
        "rule_id": "fr_xK9mP2vL3nQ",
        "target_address": "203.0.113.20",
        "target_port": 8443
      },
      {
        "rule_id": "fr_aB3cD4eF5gH6",
        "target_address": "203.0.113.21"
      }
    ]
  }'
```

Request body:

| Field | Type | Notes |
| --- | --- | --- |
| `updates` | array | Required, 1 to 100 items |
| `updates[].rule_id` | string | Required, `fr_...`; an invalid prefix fails the whole request with `400` |
| `updates[].target_address` | string | Optional. IP address or RFC 1123 hostname |
| `updates[].target_port` | integer | Optional, 1 to 65535 |
| `updates[].name` | string | Optional |
| `updates[].remark` | string | Optional |
| `updates[].sort_order` | integer | Optional |
| `updates[].agent_id` | string | Optional, entry agent `fa_...` |
| `updates[].exit_agent_id` | string | Optional, exit agent `fa_...` for entry rules |

Target semantics:

- `target_address` and `target_port` go through the same update path as `PUT /forward-rules/:id`, so validation is identical: the address must be a valid IP or an RFC 1123 hostname, and the port must be non-zero. Setting either field clears `target_node_id`, because a rule cannot use a static target and a node link at the same time.
- Setting `target_address` without `target_port` keeps the rule's current port.
- `chain_agent_ids` is not supported in batch update; use a single `PUT /forward-rules/:id` for that.
- All updates run in one transaction. If any update fails, the whole batch is rolled back and `succeeded` is returned empty.
- Configuration is pushed to the affected forward agents and the affected nodes' subscriptions are re-synced only after the transaction commits. Both kinds of work are collected during the transaction and dispatched after it, so nothing is sent for a batch that rolled back. A rollback therefore produces no agent push and no node re-sync.

Response:

```json
{
  "success": true,
  "data": {
    "succeeded": [
      "fr_xK9mP2vL3nQ",
      "fr_aB3cD4eF5gH6"
    ]
  },
  "message": "Batch update completed"
}
```

`failed` is omitted when empty. Failure modes:

- Malformed JSON, an invalid `rule_id`/`agent_id`/`exit_agent_id` prefix, or an out-of-range `target_port` returns `400` and changes nothing.
- Per-rule failures are reported with HTTP `200` and a `failed` array; the batch is still all-or-nothing:
  - A rule that does not exist (or is not visible to the caller) is reported in `failed` with a `reason`, `succeeded` is empty, and no rule is changed.
  - A failure inside the transaction rolls everything back: `succeeded` is empty and `failed` carries the reason for the rule that aborted the batch.

## 8. Retargeting Rules to a New Address

`POST /forward-rules/retarget` moves every rule that points at one static landing address to another address, optionally changing the port. Use it when a backend moves to a new IP and you do not want to edit rules one by one.

### Request

```bash
curl -sS -X POST "$BASE/forward-rules/retarget" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "from_address": "203.0.113.10",
    "to_address": "203.0.113.20",
    "to_port": 8443,
    "rule_ids": ["fr_xK9mP2vL3nQ", "fr_aB3cD4eF5gH6"],
    "dry_run": true
  }'
```

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `from_address` | string | yes | Current static target address. Must be a valid IP or RFC 1123 hostname |
| `to_address` | string | yes | New static target address. Same validation |
| `to_port` | integer | no | New port, `1` to `65535`. Omit to keep each rule's current port |
| `rule_ids` | array of strings | no | Restricts the operation to these rules. Maximum 100 entries, each `fr_...` |
| `dry_run` | boolean | no | When `true`, validates and reports without writing. Defaults to `false` |

### Semantics

- Matches rules whose static `target_address` equals `from_address` **exactly**. Hostnames are compared as strings, not resolved.
- Node-linked rules are always excluded: a rule with `target_node_id` set has no static target of its own.
- `rule_ids`, when present, further restricts the set. Rule IDs outside the matched set are ignored; invalid prefixes fail the request with `400`.
- A rule whose effective target would not change is skipped: if the rule already holds `to_address` at the port the request would give it, it is not a candidate and is absent from `affected`.
- `from_address == to_address` is rejected with `400` in two cases:
  - `to_port` is omitted — the request cannot change anything.
  - `to_port` is supplied but no matched rule would actually change its port, because every matched rule already sits at `to_address` on that port. The message ends with `nothing to retarget`.
- A same-address request is accepted only when at least one matched rule's current port differs from `to_port`.
- All updates are applied in one transaction, so a validation error or write failure on any rule rolls back every rule in the batch: all or nothing.
- Matching rules are updated through the same validation path as a single `PUT`, so each new target is validated and each rule's `target_node_id` is cleared.
- After the commit, configuration is pushed for affected rules and their nodes' subscriptions are re-synced. Disabled rules are reported with `will_sync: false` and are not pushed.

### Concurrent changes

Selection happens before the transaction, so the selected rules are revalidated inside it under a row lock (`SELECT ... FOR UPDATE`). If any selected rule no longer matches what the request was planned against, the whole request fails with `409 Conflict` and nothing is written or pushed. The conditions are:

- the rule was deleted;
- the rule was re-pointed to another static address;
- the rule was linked to a node (`target_node_id` set), so it no longer has a static target;
- the rule's port changed to something other than the planned old port.

Retry the request after re-reading the current rules; a fresh dry run shows the new state. The error details carry the `fr_...` ID of the rule that conflicted.

Node subscription re-syncs are deferred until after commit, exactly like forward-agent pushes, so no node ever receives a snapshot built from uncommitted state. A conflict aborts before either kind of push is dispatched.

### Response

```json
{
  "success": true,
  "data": {
    "dry_run": true,
    "from_address": "203.0.113.10",
    "to_address": "203.0.113.20",
    "to_port": 8443,
    "matched": 2,
    "affected": [
      {
        "id": "fr_xK9mP2vL3nQ",
        "name": "mysql-primary",
        "agent_id": "fa_yL8nQ3wM4oR",
        "old_target": "203.0.113.10:3306",
        "new_target": "203.0.113.20:8443",
        "status": "enabled",
        "will_sync": true
      },
      {
        "id": "fr_aB3cD4eF5gH6",
        "name": "mysql-replica",
        "agent_id": "fa_yL8nQ3wM4oR",
        "old_target": "203.0.113.10:3307",
        "new_target": "203.0.113.20:8443",
        "status": "disabled",
        "will_sync": false
      }
    ]
  },
  "message": "Retarget dry run"
}
```

`message` is `"Retarget dry run"` for `dry_run: true` and `"Retarget completed"` otherwise. `to_port` is omitted when it was not supplied. Targets are rendered as `host:port`, with IPv6 literals bracketed (for example `[2001:db8::1]:443`). `matched` equals the number of `affected` entries; when nothing matches, `matched` is `0` and `affected` is an empty array.

In a real run, `status` and `will_sync` describe the row state read under the transaction's row lock at apply time, not the pre-selection snapshot. `status` is the status the update was actually applied with, and `will_sync` is `true` exactly when that locked row was enabled — which is also the condition under which the push was dispatched. A rule another admin enabled or disabled between selection and commit is therefore reported as it was at apply time: a rule disabled then is retargeted in the database but not pushed (`will_sync: false`). A dry run opens no transaction, so its `affected` list is the projection from the selection read.

### Operations playbook

1. **Discover.** List candidates before changing anything:

   ```bash
   curl -sS --get "$BASE/forward-rules" \
     --data-urlencode "target_address=203.0.113.10" \
     -H "Authorization: Bearer $TOKEN"
   ```

2. **Dry run.** Send the exact body you intend to apply with `"dry_run": true`. Confirm `matched`, every `old_target` and `new_target`, and which entries have `will_sync: true`.
3. **Narrow if needed.** If the dry run matches more than intended, add `rule_ids` and dry run again. Do not rely on a second pass to fix a wrong first pass.
4. **Apply.** Repeat the same request with `"dry_run": false` (or omit the field). Re-check the response: the `affected` list must match the dry run.
5. **Verify.** Re-run the list filter for both addresses; the old one should return no rules.

> **Service impact**: each affected enabled rule is re-pushed to its forward agent, and the agent restarts that rule's forwarder. Connections through that rule's listen port are dropped briefly while the listener restarts. Disabled rules (`will_sync: false`) are not pushed and have no impact. Schedule the change accordingly.

## 9. Database Migration

The feature is backed by `internal/infrastructure/migration/scripts/060_add_admin_api_tokens.sql`, a goose migration that creates the `admin_api_tokens` table with a unique index on `sid`, a unique index on `token_hash`, and indexes on `created_by` and `expires_at`. The `Down` section drops the table.

Apply it with the normal migration command:

```bash
./bin/orris migrate up
```

or, equivalently:

```bash
make migrate-up
```

Check status with `./bin/orris migrate status`. Nothing else needs to be run; the table is not seeded.

## 10. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `401` with `"invalid or expired token"` on a token request | Token value is unknown, mistyped, or was truncated | Re-copy the full `orr_...` value. If it is lost, create a new token |
| `401` with `"invalid or expired token"` after it worked before | Token was revoked, or it passed `expires_at` | Check `revoked_at` and `expires_at` with `GET /admin/api-tokens/:id`, then create a new token |
| `401` with `"invalid or expired token"` and the owner was deleted | The owner is re-read on every request and no longer exists | Create a token under an existing admin |
| `403` with `"invalid or expired token"` | The owner is disabled/suspended, or was demoted from admin | Re-enable the owner or restore the admin role. The token cannot exceed the owner's current role |
| `403` with `"this endpoint requires an interactive session; admin API tokens cannot manage credentials"` | A token was used against a session-only route: token management (`/admin/api-tokens/*`), passkey registration (`POST /auth/passkey/register/start` and `/finish`), or account management (`POST /users`, `PATCH /users/me`, `PUT /users/me/password`, `GET` and `DELETE /users/me/passkeys`, `PATCH` and `DELETE /users/:id`, `PATCH /users/:id/password`) | Use a cookie session for these routes. This is intentional: a leaked token cannot create new credentials, change passwords, register passkeys, or alter roles. Everything else still accepts the token |
| `403` with `"missing CSRF token"`, `"missing CSRF token header"`, or `"invalid CSRF token"` | A cookie session was used for a mutating request without a matching `X-CSRF-Token` header | Send `X-CSRF-Token` equal to the `csrf_token` cookie. Do not attach cookies when you intend to use a bearer token |
| `403` with `"admin access required"` on a normal endpoint | A cookie session for a non-admin user was used. An API token whose owner is not an admin fails earlier, with `"invalid or expired token"` | Use an admin-owned token or an admin session |
| `404` on `GET`/`revoke`/`delete` of a token ID | The token belongs to another admin, or the ID is wrong | IDs are scoped to the caller; use the ID returned by your own list call |
| `400` on `POST /forward-rules/retarget` with `"from_address and to_address are identical and no to_port change was requested"` | Same address and no port change | Supply a `to_port`, or pick a different `to_address` |
| `400` on `POST /forward-rules/retarget` with `"... nothing to retarget"` | Same address and a `to_port` was supplied, but every matched rule already uses that port | Re-check the current port of the matched rules with `GET /forward-rules?target_address=...`. Nothing would change, so the request is rejected instead of reporting a successful no-op |
| `409` on `POST /forward-rules/retarget` | A selected rule was deleted, re-pointed to another address, linked to a node, or had its port changed between selection and commit | Re-run the dry run to see the current state, then repeat the request. Nothing was written or pushed |
| `401` with `"session not found"` on `POST /auth/logout` while using a token | Token auth is stateless and has no session; logout needs a `session_id` from a cookie session | Do not call logout for a token. Use `POST /admin/api-tokens/:id/revoke` or `DELETE /admin/api-tokens/:id` with a cookie session |
| `400` on `GET /forward-rules?agent_id=...` | Malformed agent ID | Use an `fa_...` value from `GET /forward-agents` |

## 11. Limitations

- **Rollback coverage.** The batch-update and retarget rollback tests prove control flow, not storage rollback: they assert that a failed transaction suppresses every post-commit side effect and reports nothing as succeeded. Restoring rows after a real rollback is the database's responsibility, and the unit tests use a mock repository with no transactional storage.
- **Post-commit node re-sync is best effort.** If `SyncSubscriptionsToNode` fails after the transaction commits, the failure is logged and not retried, the same as a single `PUT /forward-rules/:id`. The rule change is committed either way, and the node keeps the previous subscription snapshot until some later change re-syncs it. There is no endpoint to force a re-sync; updating any rule in the same resource groups or targeting the same node triggers one.
- **Concurrent rule insertions are not detected.** Retarget revalidates only the rules it selected, under row locks. A rule inserted with a matching `from_address` after selection is not seen by the retarget and keeps pointing at the old address. Re-run the list filter for `from_address` afterwards to catch stragglers.
- **Unrestricted retargets lock every matching row.** `rule_ids` is capped at 100 entries, but omitting it is not capped: every rule whose static target equals `from_address` is selected, locked, and updated in one transaction. On a large table this is a long transaction and a long lock set. Use `rule_ids` or narrow the address when the set is large.
