package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	// AdminAPITokenPrefix is the literal prefix of every admin API token value.
	// It lets the auth middleware distinguish an API token from a JWT before
	// attempting any parsing.
	AdminAPITokenPrefix = "orr_"

	// adminAPITokenRandomBytes is the amount of entropy per token (256 bits).
	adminAPITokenRandomBytes = 32

	// adminAPITokenHintChars is how many characters of the random part are kept
	// for display. The hint is not secret and is never sufficient to authenticate.
	adminAPITokenHintChars = 8
)

// AdminAPITokenGenerator generates and hashes admin API tokens.
// Tokens have the format "orr_<base64url(32 random bytes)>" and are only ever
// persisted as a SHA-256 hex digest.
type AdminAPITokenGenerator struct{}

// NewAdminAPITokenGenerator creates a new AdminAPITokenGenerator.
func NewAdminAPITokenGenerator() *AdminAPITokenGenerator {
	return &AdminAPITokenGenerator{}
}

// Generate creates a new token and returns the plaintext value, its hash and a
// short display hint. The plaintext must be returned to the caller exactly once.
func (g *AdminAPITokenGenerator) Generate() (plainToken, tokenHash, hint string, err error) {
	randomBytes := make([]byte, adminAPITokenRandomBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// RawURLEncoding is URL-safe and has no padding, so the token can be used
	// verbatim in shell scripts and HTTP headers.
	encoded := base64.RawURLEncoding.EncodeToString(randomBytes)
	plainToken = AdminAPITokenPrefix + encoded

	return plainToken, g.Hash(plainToken), AdminAPITokenPrefix + encoded[:adminAPITokenHintChars], nil
}

// Hash returns the hex-encoded SHA-256 digest of a token value.
func (g *AdminAPITokenGenerator) Hash(plainToken string) string {
	sum := sha256.Sum256([]byte(plainToken))
	return hex.EncodeToString(sum[:])
}

// Verify reports whether plainToken hashes to tokenHash in constant time.
// Lookups should be done by hash in the database; this helper exists for tests
// and for in-memory comparisons.
func (g *AdminAPITokenGenerator) Verify(plainToken, tokenHash string) bool {
	computed := g.Hash(plainToken)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(tokenHash)) == 1
}

// IsAdminAPIToken reports whether a bearer value is syntactically an admin API
// token. It deliberately only checks the prefix: validation always happens
// against the database.
func IsAdminAPIToken(value string) bool {
	return strings.HasPrefix(value, AdminAPITokenPrefix)
}
