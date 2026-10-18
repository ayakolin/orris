package token

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdminAPITokenGenerator_Generate(t *testing.T) {
	g := NewAdminAPITokenGenerator()

	plainToken, tokenHash, hint, err := g.Generate()
	require.NoError(t, err)

	t.Run("plain token has prefix", func(t *testing.T) {
		assert.True(t, strings.HasPrefix(plainToken, AdminAPITokenPrefix), "token %q must start with %q", plainToken, AdminAPITokenPrefix)
	})

	t.Run("plain token is url safe", func(t *testing.T) {
		assert.NotContains(t, plainToken, "+")
		assert.NotContains(t, plainToken, "/")
		assert.NotContains(t, plainToken, "=")
	})

	t.Run("plain token decodes to 32 random bytes", func(t *testing.T) {
		encoded := strings.TrimPrefix(plainToken, AdminAPITokenPrefix)
		require.NotEmpty(t, encoded)

		randomBytes, decodeErr := base64.RawURLEncoding.DecodeString(encoded)
		require.NoError(t, decodeErr)
		assert.Len(t, randomBytes, 32)
	})

	t.Run("hash is 64 lowercase hex chars", func(t *testing.T) {
		require.Len(t, tokenHash, 64)
		for _, r := range tokenHash {
			assert.True(t, (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f'), "unexpected character %q in hash %q", r, tokenHash)
		}
	})

	t.Run("hash is not the plaintext", func(t *testing.T) {
		assert.NotEqual(t, plainToken, tokenHash)
	})

	t.Run("hint is prefix plus eight characters", func(t *testing.T) {
		assert.True(t, strings.HasPrefix(hint, AdminAPITokenPrefix), "hint %q must start with %q", hint, AdminAPITokenPrefix)
		assert.Len(t, hint, 12)
		assert.Equal(t, AdminAPITokenPrefix+strings.TrimPrefix(plainToken, AdminAPITokenPrefix)[:8], hint)
	})
}

func TestAdminAPITokenGenerator_Generate_Unique(t *testing.T) {
	g := NewAdminAPITokenGenerator()

	const iterations = 100

	plainTokens := make(map[string]struct{}, iterations)
	hashes := make(map[string]struct{}, iterations)

	var previousPlain, previousHash string

	for i := range iterations {
		plainToken, tokenHash, _, err := g.Generate()
		require.NoError(t, err)

		if i > 0 {
			assert.NotEqual(t, previousPlain, plainToken)
			assert.NotEqual(t, previousHash, tokenHash)
		}

		assert.NotContains(t, plainTokens, plainToken)
		assert.NotContains(t, hashes, tokenHash)

		plainTokens[plainToken] = struct{}{}
		hashes[tokenHash] = struct{}{}

		previousPlain, previousHash = plainToken, tokenHash
	}

	assert.Len(t, plainTokens, iterations)
	assert.Len(t, hashes, iterations)
}

func TestAdminAPITokenGenerator_Hash(t *testing.T) {
	g := NewAdminAPITokenGenerator()

	tests := []struct {
		name       string
		plainToken string
	}{
		{name: "typical token", plainToken: "orr_abcdefghijklmnopqrstuvwxyz012345"},
		{name: "empty token", plainToken: ""},
		{name: "unicode token", plainToken: "orr_令牌"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sum := sha256.Sum256([]byte(tt.plainToken))
			want := hex.EncodeToString(sum[:])

			got := g.Hash(tt.plainToken)
			assert.Equal(t, want, got)

			// Deterministic.
			assert.Equal(t, got, g.Hash(tt.plainToken))
		})
	}
}

func TestAdminAPITokenGenerator_Verify(t *testing.T) {
	g := NewAdminAPITokenGenerator()

	plainToken, tokenHash, _, err := g.Generate()
	require.NoError(t, err)

	otherPlain, _, _, err := g.Generate()
	require.NoError(t, err)

	tests := []struct {
		name       string
		plainToken string
		tokenHash  string
		want       bool
	}{
		{name: "matching pair", plainToken: plainToken, tokenHash: tokenHash, want: true},
		{name: "wrong token", plainToken: otherPlain, tokenHash: tokenHash, want: false},
		{name: "wrong hash content", plainToken: plainToken, tokenHash: strings.Repeat("0", 64), want: false},
		{name: "hash too short", plainToken: plainToken, tokenHash: tokenHash[:63], want: false},
		{name: "hash too long", plainToken: plainToken, tokenHash: tokenHash + "0", want: false},
		{name: "empty hash", plainToken: plainToken, tokenHash: "", want: false},
		{name: "uppercase hash", plainToken: plainToken, tokenHash: strings.ToUpper(tokenHash), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, g.Verify(tt.plainToken, tt.tokenHash))
		})
	}
}

func TestIsAdminAPIToken(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "prefixed token", value: "orr_abc", want: true},
		{name: "prefix only", value: "orr_", want: true},
		{name: "empty", value: "", want: false},
		{name: "bearer with token", value: "Bearer orr_x", want: false},
		{name: "jwt", value: "eyJhbGci", want: false},
		{name: "uppercase prefix", value: "ORR_abc", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsAdminAPIToken(tt.value))
		})
	}
}
