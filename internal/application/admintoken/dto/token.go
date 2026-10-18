// Package dto provides data transfer objects for admin API token operations.
package dto

import "time"

// CreateTokenRequest is the request body for creating an admin API token.
type CreateTokenRequest struct {
	Name      string     `json:"name" binding:"required,max=100"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// TokenResponse describes a token record. It never contains the plaintext token
// or its hash, only a non-secret display hint.
type TokenResponse struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	TokenHint  string     `json:"token_hint,omitempty"`
	CreatedBy  string     `json:"created_by,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// CreateTokenResponse is returned exactly once by the create endpoint and is the
// only response that ever carries the plaintext token.
type CreateTokenResponse struct {
	TokenResponse
	// Token is the plaintext bearer credential. It cannot be retrieved again.
	Token string `json:"token"`
}
