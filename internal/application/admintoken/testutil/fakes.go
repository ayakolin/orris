// Package testutil provides in-memory fakes for admin API token tests.
package testutil

import (
	"context"
	"sync"
	"time"

	"github.com/orris-inc/orris/internal/domain/admintoken"
	"github.com/orris-inc/orris/internal/domain/user"
)

// FakeAdminAPITokenRepository is an in-memory admintoken.Repository.
// It is mutex-protected and safe for concurrent use by the auth middleware tests.
type FakeAdminAPITokenRepository struct {
	mu        sync.RWMutex
	tokens    map[uint]*admintoken.Token
	nextID    uint
	createErr error
	lookupErr error
	listErr   error
	revokeErr error
	updateErr error
	deleteErr error
}

// NewFakeAdminAPITokenRepository creates an empty fake repository.
func NewFakeAdminAPITokenRepository() *FakeAdminAPITokenRepository {
	return &FakeAdminAPITokenRepository{tokens: make(map[uint]*admintoken.Token)}
}

func (f *FakeAdminAPITokenRepository) Create(_ context.Context, token *admintoken.Token) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return f.createErr
	}
	f.nextID++
	if err := token.SetID(f.nextID); err != nil {
		return err
	}
	f.tokens[token.ID()] = token
	return nil
}

func (f *FakeAdminAPITokenRepository) GetByID(_ context.Context, id uint) (*admintoken.Token, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.lookupErr != nil {
		return nil, f.lookupErr
	}
	return f.tokens[id], nil
}

func (f *FakeAdminAPITokenRepository) GetBySID(_ context.Context, sid string) (*admintoken.Token, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.lookupErr != nil {
		return nil, f.lookupErr
	}
	for _, token := range f.tokens {
		if token.SID() == sid {
			return token, nil
		}
	}
	return nil, nil
}

func (f *FakeAdminAPITokenRepository) GetByTokenHash(_ context.Context, tokenHash string) (*admintoken.Token, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.lookupErr != nil {
		return nil, f.lookupErr
	}
	for _, token := range f.tokens {
		if token.TokenHash() == tokenHash {
			return token, nil
		}
	}
	return nil, nil
}

func (f *FakeAdminAPITokenRepository) List(_ context.Context, createdBy uint) ([]*admintoken.Token, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	result := make([]*admintoken.Token, 0, len(f.tokens))
	for _, token := range f.tokens {
		if createdBy != 0 && token.CreatedBy() != createdBy {
			continue
		}
		result = append(result, token)
	}
	return result, nil
}

func (f *FakeAdminAPITokenRepository) Revoke(_ context.Context, id uint, revokedAt time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revokeErr != nil {
		return false, f.revokeErr
	}
	token, ok := f.tokens[id]
	if !ok {
		return false, nil
	}
	token.Revoke(revokedAt)
	return true, nil
}

func (f *FakeAdminAPITokenRepository) RevokeByUserID(_ context.Context, userID uint, revokedAt time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revokeErr != nil {
		return 0, f.revokeErr
	}
	var revoked int64
	for _, token := range f.tokens {
		if token.CreatedBy() != userID || token.IsRevoked() {
			continue
		}
		token.Revoke(revokedAt)
		revoked++
	}
	return revoked, nil
}

func (f *FakeAdminAPITokenRepository) UpdateLastUsed(_ context.Context, id uint, lastUsedAt time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.updateErr != nil {
		return false, f.updateErr
	}
	token, ok := f.tokens[id]
	if !ok {
		return false, nil
	}
	token.TouchLastUsed(lastUsedAt)
	return true, nil
}

func (f *FakeAdminAPITokenRepository) Delete(_ context.Context, id uint) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return false, f.deleteErr
	}
	if _, ok := f.tokens[id]; !ok {
		return false, nil
	}
	delete(f.tokens, id)
	return true, nil
}

// Add inserts a token directly, bypassing ID generation.
func (f *FakeAdminAPITokenRepository) Add(token *admintoken.Token) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if token.ID() > f.nextID {
		f.nextID = token.ID()
	}
	f.tokens[token.ID()] = token
}

// Tokens returns a snapshot of stored tokens.
func (f *FakeAdminAPITokenRepository) Tokens() []*admintoken.Token {
	f.mu.RLock()
	defer f.mu.RUnlock()
	result := make([]*admintoken.Token, 0, len(f.tokens))
	for _, token := range f.tokens {
		result = append(result, token)
	}
	return result
}

// SetLookupError injects an error for lookup operations.
func (f *FakeAdminAPITokenRepository) SetLookupError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookupErr = err
}

// FakeUserRepository is an in-memory lookup for token owners.
type FakeUserRepository struct {
	mu    sync.RWMutex
	users map[uint]*user.User
	err   error
}

// NewFakeUserRepository creates an empty fake user repository.
func NewFakeUserRepository() *FakeUserRepository {
	return &FakeUserRepository{users: make(map[uint]*user.User)}
}

// Add stores a user.
func (f *FakeUserRepository) Add(u *user.User) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[u.ID()] = u
}

// SetError injects a lookup error.
func (f *FakeUserRepository) SetError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// GetByID implements the narrow lookup used by the admin token use cases.
func (f *FakeUserRepository) GetByID(_ context.Context, id uint) (*user.User, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.users[id], nil
}

// GetBySID returns the user whose SID matches.
func (f *FakeUserRepository) GetBySID(_ context.Context, sid string) (*user.User, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.err != nil {
		return nil, f.err
	}
	for _, u := range f.users {
		if u.SID() == sid {
			return u, nil
		}
	}
	return nil, nil
}
