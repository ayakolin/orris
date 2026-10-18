package admintoken

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestSIDGenerator(sid string) SIDGenerator {
	return func() (string, error) {
		return sid, nil
	}
}

func TestNewToken(t *testing.T) {
	expiresAt := time.Now().UTC().Add(24 * time.Hour)

	tests := []struct {
		name          string
		tokenName     string
		tokenHash     string
		createdBy     uint
		expiresAt     *time.Time
		sidGenerator  SIDGenerator
		wantErr       bool
		wantSID       string
		wantErrSubstr string
	}{
		{
			name:         "valid input",
			tokenName:    "deploy bot",
			tokenHash:    strings.Repeat("a", 64),
			createdBy:    42,
			expiresAt:    &expiresAt,
			sidGenerator: newTestSIDGenerator("apt_123"),
			wantSID:      "apt_123",
		},
		{
			name:         "valid input without expiry",
			tokenName:    "no expiry",
			tokenHash:    strings.Repeat("b", 64),
			createdBy:    1,
			sidGenerator: newTestSIDGenerator("apt_456"),
			wantSID:      "apt_456",
		},
		{
			name:         "valid input with max length name",
			tokenName:    strings.Repeat("n", MaxNameLength),
			tokenHash:    strings.Repeat("c", 64),
			createdBy:    7,
			sidGenerator: newTestSIDGenerator("apt_789"),
			wantSID:      "apt_789",
		},
		{
			name:         "empty name",
			tokenName:    "",
			tokenHash:    strings.Repeat("a", 64),
			createdBy:    1,
			sidGenerator: newTestSIDGenerator("apt_123"),
			wantErr:      true,
		},
		{
			name:         "name too long",
			tokenName:    strings.Repeat("n", MaxNameLength+1),
			tokenHash:    strings.Repeat("a", 64),
			createdBy:    1,
			sidGenerator: newTestSIDGenerator("apt_123"),
			wantErr:      true,
		},
		{
			name:         "empty hash",
			tokenName:    "name",
			tokenHash:    "",
			createdBy:    1,
			sidGenerator: newTestSIDGenerator("apt_123"),
			wantErr:      true,
		},
		{
			name:         "zero createdBy",
			tokenName:    "name",
			tokenHash:    strings.Repeat("a", 64),
			createdBy:    0,
			sidGenerator: newTestSIDGenerator("apt_123"),
			wantErr:      true,
		},
		{
			name:         "nil generator",
			tokenName:    "name",
			tokenHash:    strings.Repeat("a", 64),
			createdBy:    1,
			sidGenerator: nil,
			wantErr:      true,
		},
		{
			name:         "past expiresAt",
			tokenName:    "name",
			tokenHash:    strings.Repeat("a", 64),
			createdBy:    1,
			expiresAt:    timePtr(time.Now().UTC().Add(-time.Hour)),
			sidGenerator: newTestSIDGenerator("apt_123"),
			wantErr:      true,
		},
		{
			name:         "generator error",
			tokenName:    "name",
			tokenHash:    strings.Repeat("a", 64),
			createdBy:    1,
			sidGenerator: func() (string, error) { return "", errors.New("boom") },
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := time.Now().UTC()

			tok, err := NewToken(tt.tokenName, tt.tokenHash, "orr_hint", tt.createdBy, tt.expiresAt, tt.sidGenerator)

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, tok)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, tok)

			assert.Equal(t, tt.wantSID, tok.SID())
			assert.Equal(t, tt.tokenName, tok.Name())
			assert.Equal(t, tt.tokenHash, tok.TokenHash())
			assert.Equal(t, "orr_hint", tok.TokenHint())
			assert.Equal(t, tt.createdBy, tok.CreatedBy())
			assert.Equal(t, tt.expiresAt, tok.ExpiresAt())

			assert.Zero(t, tok.ID())
			assert.Nil(t, tok.LastUsedAt())
			assert.Nil(t, tok.RevokedAt())

			assert.False(t, tok.CreatedAt().IsZero())
			assert.False(t, tok.CreatedAt().Before(before))
			assert.False(t, tok.CreatedAt().After(time.Now().UTC()))
			assert.Equal(t, tok.CreatedAt(), tok.UpdatedAt())
		})
	}
}

func timePtr(t time.Time) *time.Time { return &t }

func TestReconstructToken(t *testing.T) {
	createdAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updatedAt := createdAt.Add(time.Hour)
	lastUsedAt := createdAt.Add(2 * time.Hour)
	expiresAt := createdAt.Add(24 * time.Hour)
	revokedAt := createdAt.Add(3 * time.Hour)

	tests := []struct {
		name    string
		mutate  func(*reconstructArgs)
		wantErr bool
	}{
		{name: "valid full", mutate: func(*reconstructArgs) {}},
		{name: "valid without optional times", mutate: func(a *reconstructArgs) {
			a.lastUsedAt = nil
			a.expiresAt = nil
			a.revokedAt = nil
		}},
		{name: "zero id", mutate: func(a *reconstructArgs) { a.id = 0 }, wantErr: true},
		{name: "empty sid", mutate: func(a *reconstructArgs) { a.sid = "" }, wantErr: true},
		{name: "empty name", mutate: func(a *reconstructArgs) { a.name = "" }, wantErr: true},
		{name: "empty hash", mutate: func(a *reconstructArgs) { a.tokenHash = "" }, wantErr: true},
		{name: "zero createdBy", mutate: func(a *reconstructArgs) { a.createdBy = 0 }, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := reconstructArgs{
				id:         7,
				sid:        "apt_abc",
				name:       "ci token",
				tokenHash:  strings.Repeat("d", 64),
				tokenHint:  "orr_abcdefgh",
				createdBy:  3,
				lastUsedAt: &lastUsedAt,
				expiresAt:  &expiresAt,
				revokedAt:  &revokedAt,
				createdAt:  createdAt,
				updatedAt:  updatedAt,
			}
			tt.mutate(&args)

			tok, err := ReconstructToken(
				args.id,
				args.sid,
				args.name,
				args.tokenHash,
				args.tokenHint,
				args.createdBy,
				args.lastUsedAt,
				args.expiresAt,
				args.revokedAt,
				args.createdAt,
				args.updatedAt,
			)

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, tok)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, tok)

			assert.Equal(t, args.id, tok.ID())
			assert.Equal(t, args.sid, tok.SID())
			assert.Equal(t, args.name, tok.Name())
			assert.Equal(t, args.tokenHash, tok.TokenHash())
			assert.Equal(t, args.tokenHint, tok.TokenHint())
			assert.Equal(t, args.createdBy, tok.CreatedBy())
			assert.Equal(t, args.createdAt, tok.CreatedAt())
			assert.Equal(t, args.updatedAt, tok.UpdatedAt())

			require.Same(t, args.lastUsedAt, tok.LastUsedAt())
			require.Same(t, args.expiresAt, tok.ExpiresAt())
			require.Same(t, args.revokedAt, tok.RevokedAt())
		})
	}
}

type reconstructArgs struct {
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

func TestToken_IsRevokedIsExpiredIsUsable(t *testing.T) {
	now := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	tests := []struct {
		name       string
		expiresAt  *time.Time
		revokedAt  *time.Time
		wantRevoke bool
		wantExpire bool
		wantUsable bool
	}{
		{
			name:       "no expiry never expires",
			wantExpire: false,
			wantUsable: true,
		},
		{
			name:       "expiry in future is usable",
			expiresAt:  &future,
			wantExpire: false,
			wantUsable: true,
		},
		{
			name:       "expiry equal to now is expired",
			expiresAt:  &now,
			wantExpire: true,
			wantUsable: false,
		},
		{
			name:       "expiry in past is expired",
			expiresAt:  &past,
			wantExpire: true,
			wantUsable: false,
		},
		{
			name:       "revoked without expiry",
			revokedAt:  &now,
			wantRevoke: true,
			wantExpire: false,
			wantUsable: false,
		},
		{
			name:       "revoked with future expiry",
			expiresAt:  &future,
			revokedAt:  &past,
			wantRevoke: true,
			wantExpire: false,
			wantUsable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, err := ReconstructToken(1, "apt_x", "name", strings.Repeat("e", 64), "orr_x", 1, nil, tt.expiresAt, tt.revokedAt, now, now)
			require.NoError(t, err)

			assert.Equal(t, tt.wantRevoke, tok.IsRevoked())
			assert.Equal(t, tt.wantExpire, tok.IsExpired(now))
			assert.Equal(t, tt.wantUsable, tok.IsUsable(now))
		})
	}
}

func TestToken_Revoke_Idempotent(t *testing.T) {
	createdAt := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	first := createdAt.Add(time.Hour)
	second := createdAt.Add(2 * time.Hour)

	tok, err := ReconstructToken(1, "apt_x", "name", strings.Repeat("f", 64), "orr_x", 1, nil, nil, nil, createdAt, createdAt)
	require.NoError(t, err)

	require.False(t, tok.IsRevoked())

	tok.Revoke(first)
	require.True(t, tok.IsRevoked())
	require.NotNil(t, tok.RevokedAt())
	assert.Equal(t, first, *tok.RevokedAt())
	assert.Equal(t, first, tok.UpdatedAt())
	assert.True(t, tok.IsExpired(first.Add(24*time.Hour)) == false)
	assert.False(t, tok.IsUsable(first))

	tok.Revoke(second)
	require.True(t, tok.IsRevoked())
	assert.Equal(t, first, *tok.RevokedAt(), "second revoke must not overwrite the first timestamp")
	assert.Equal(t, first, tok.UpdatedAt(), "second revoke must not touch updated_at")
}

func TestToken_TouchLastUsed(t *testing.T) {
	createdAt := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	usedAt := createdAt.Add(30 * time.Minute)

	tok, err := ReconstructToken(1, "apt_x", "name", strings.Repeat("a", 64), "orr_x", 1, nil, nil, nil, createdAt, createdAt)
	require.NoError(t, err)
	require.Nil(t, tok.LastUsedAt())

	tok.TouchLastUsed(usedAt)
	require.NotNil(t, tok.LastUsedAt())
	assert.Equal(t, usedAt, *tok.LastUsedAt())

	later := usedAt.Add(time.Hour)
	tok.TouchLastUsed(later)
	require.NotNil(t, tok.LastUsedAt())
	assert.Equal(t, later, *tok.LastUsedAt())
}

func TestToken_SetID(t *testing.T) {
	newToken := func(t *testing.T) *Token {
		t.Helper()
		tok, err := NewToken("name", strings.Repeat("a", 64), "orr_x", 1, nil, newTestSIDGenerator("apt_y"))
		require.NoError(t, err)
		return tok
	}

	t.Run("sets id once", func(t *testing.T) {
		tok := newToken(t)
		require.Zero(t, tok.ID())

		require.NoError(t, tok.SetID(11))
		assert.Equal(t, uint(11), tok.ID())
	})

	t.Run("rejects zero id", func(t *testing.T) {
		tok := newToken(t)

		err := tok.SetID(0)
		require.Error(t, err)
		assert.Zero(t, tok.ID())
	})

	t.Run("rejects second call", func(t *testing.T) {
		tok := newToken(t)
		require.NoError(t, tok.SetID(11))

		err := tok.SetID(12)
		require.Error(t, err)
		assert.Equal(t, uint(11), tok.ID(), "existing id must be preserved")
	})
}
