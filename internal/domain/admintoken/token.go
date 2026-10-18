// Package admintoken contains the admin API token aggregate.
//
// An admin API token is a bearer credential that authenticates as the admin user
// who created it. Only the SHA-256 hash of the token value is persisted; the
// plaintext is shown to the caller once, at creation time.
package admintoken

import (
	"fmt"
	"time"

	"github.com/orris-inc/orris/internal/shared/biztime"
)

// MaxNameLength is the maximum length of a token name.
const MaxNameLength = 100

// Token is the admin API token aggregate.
type Token struct {
	id         uint
	sid        string
	name       string
	tokenHash  string
	tokenHint  string
	createdBy  uint
	lastUsedAt *time.Time
	expiresAt  *time.Time
	revokedAt  *time.Time
	createdAt  time.Time
	updatedAt  time.Time
}

// SIDGenerator is a function that generates a Stripe-style ID.
type SIDGenerator func() (string, error)

// NewToken creates a new admin API token.
// tokenHash must be the hex-encoded SHA-256 digest of the plaintext token; the
// plaintext itself is never passed to the aggregate.
func NewToken(
	name string,
	tokenHash string,
	tokenHint string,
	createdBy uint,
	expiresAt *time.Time,
	sidGenerator SIDGenerator,
) (*Token, error) {
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if len(name) > MaxNameLength {
		return nil, fmt.Errorf("name exceeds maximum length of %d characters", MaxNameLength)
	}
	if tokenHash == "" {
		return nil, fmt.Errorf("token hash is required")
	}
	if createdBy == 0 {
		return nil, fmt.Errorf("created_by is required")
	}
	if sidGenerator == nil {
		return nil, fmt.Errorf("SID generator is required")
	}
	if expiresAt != nil && !expiresAt.After(biztime.NowUTC()) {
		return nil, fmt.Errorf("expires_at must be in the future")
	}

	sid, err := sidGenerator()
	if err != nil {
		return nil, fmt.Errorf("failed to generate SID: %w", err)
	}

	now := biztime.NowUTC()
	return &Token{
		sid:       sid,
		name:      name,
		tokenHash: tokenHash,
		tokenHint: tokenHint,
		createdBy: createdBy,
		expiresAt: expiresAt,
		createdAt: now,
		updatedAt: now,
	}, nil
}

// ReconstructToken rebuilds a token from persistence.
func ReconstructToken(
	id uint,
	sid string,
	name string,
	tokenHash string,
	tokenHint string,
	createdBy uint,
	lastUsedAt *time.Time,
	expiresAt *time.Time,
	revokedAt *time.Time,
	createdAt time.Time,
	updatedAt time.Time,
) (*Token, error) {
	if id == 0 {
		return nil, fmt.Errorf("token ID cannot be zero")
	}
	if sid == "" {
		return nil, fmt.Errorf("token SID cannot be empty")
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if tokenHash == "" {
		return nil, fmt.Errorf("token hash is required")
	}
	if createdBy == 0 {
		return nil, fmt.Errorf("created_by is required")
	}

	return &Token{
		id:         id,
		sid:        sid,
		name:       name,
		tokenHash:  tokenHash,
		tokenHint:  tokenHint,
		createdBy:  createdBy,
		lastUsedAt: lastUsedAt,
		expiresAt:  expiresAt,
		revokedAt:  revokedAt,
		createdAt:  createdAt,
		updatedAt:  updatedAt,
	}, nil
}

// ID returns the internal ID.
func (t *Token) ID() uint { return t.id }

// SID returns the Stripe-style external ID (apt_xxx).
func (t *Token) SID() string { return t.sid }

// Name returns the human-readable token name.
func (t *Token) Name() string { return t.name }

// TokenHash returns the SHA-256 hex digest of the token value.
func (t *Token) TokenHash() string { return t.tokenHash }

// TokenHint returns a non-secret display hint (for example "orr_AbCdEfGh").
func (t *Token) TokenHint() string { return t.tokenHint }

// CreatedBy returns the internal ID of the admin user who created the token.
func (t *Token) CreatedBy() uint { return t.createdBy }

// LastUsedAt returns the last successful authentication time, if any.
func (t *Token) LastUsedAt() *time.Time { return t.lastUsedAt }

// ExpiresAt returns the expiry time, or nil for a non-expiring token.
func (t *Token) ExpiresAt() *time.Time { return t.expiresAt }

// RevokedAt returns the revocation time, or nil when the token is not revoked.
func (t *Token) RevokedAt() *time.Time { return t.revokedAt }

// CreatedAt returns the creation time.
func (t *Token) CreatedAt() time.Time { return t.createdAt }

// UpdatedAt returns the last update time.
func (t *Token) UpdatedAt() time.Time { return t.updatedAt }

// IsRevoked reports whether the token has been revoked.
func (t *Token) IsRevoked() bool { return t.revokedAt != nil }

// IsExpired reports whether the token is expired at the given time.
func (t *Token) IsExpired(now time.Time) bool {
	return t.expiresAt != nil && !now.Before(*t.expiresAt)
}

// IsUsable reports whether the token may authenticate a request at the given time.
func (t *Token) IsUsable(now time.Time) bool {
	return !t.IsRevoked() && !t.IsExpired(now)
}

// Revoke marks the token as revoked. Revoking an already revoked token is a no-op.
func (t *Token) Revoke(now time.Time) {
	if t.revokedAt != nil {
		return
	}
	revokedAt := now
	t.revokedAt = &revokedAt
	t.updatedAt = now
}

// TouchLastUsed records a successful use at the given time.
func (t *Token) TouchLastUsed(now time.Time) {
	lastUsedAt := now
	t.lastUsedAt = &lastUsedAt
}

// SetID assigns the internal ID after the token has been persisted.
func (t *Token) SetID(id uint) error {
	if t.id != 0 {
		return fmt.Errorf("token ID is already set")
	}
	if id == 0 {
		return fmt.Errorf("token ID cannot be zero")
	}
	t.id = id
	return nil
}
