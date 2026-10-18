package admintoken

import (
	"context"
	"time"
)

// Repository defines persistence operations for admin API tokens.
type Repository interface {
	// Create persists a new token and assigns its internal ID.
	Create(ctx context.Context, token *Token) error

	// GetByID retrieves a token by internal ID. Returns nil when not found.
	GetByID(ctx context.Context, id uint) (*Token, error)

	// GetBySID retrieves a token by its Stripe-style ID. Returns nil when not found.
	GetBySID(ctx context.Context, sid string) (*Token, error)

	// GetByTokenHash retrieves a token by its SHA-256 hex digest.
	// Returns nil when not found. Lookup by unique hash index is the
	// authentication path and avoids any in-memory secret comparison.
	GetByTokenHash(ctx context.Context, tokenHash string) (*Token, error)

	// List returns tokens created by createdBy (0 means all creators), newest first.
	List(ctx context.Context, createdBy uint) ([]*Token, error)

	// Revoke marks a token as revoked. Returns false when the token does not exist.
	Revoke(ctx context.Context, id uint, revokedAt time.Time) (bool, error)

	// UpdateLastUsed records the last successful use. Returns false when the token
	// does not exist. Implementations should only move last_used_at forward.
	UpdateLastUsed(ctx context.Context, id uint, lastUsedAt time.Time) (bool, error)

	// RevokeByUserID revokes every active token owned by userID and returns how
	// many were revoked. Used when the owner's credentials are reset or the owner
	// is deleted, so a leaked token does not survive the remediation.
	RevokeByUserID(ctx context.Context, userID uint, revokedAt time.Time) (int64, error)

	// Delete permanently removes a token. Returns false when the token does not exist.
	Delete(ctx context.Context, id uint) (bool, error)
}
