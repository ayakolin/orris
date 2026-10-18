package user

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	domainUser "github.com/orris-inc/orris/internal/domain/user"
	uvo "github.com/orris-inc/orris/internal/domain/user/valueobjects"
	"github.com/orris-inc/orris/internal/shared/authorization"
	"github.com/orris-inc/orris/internal/shared/logger"
)

type deleteTestUserRepo struct {
	domainUser.Repository
	u       *domainUser.User
	deleted string
}

func (r *deleteTestUserRepo) GetBySID(context.Context, string) (*domainUser.User, error) {
	return r.u, nil
}
func (r *deleteTestUserRepo) DeleteBySID(_ context.Context, sid string) error {
	r.deleted = sid
	return nil
}

type deleteTestRevoker struct {
	userIDs []uint
	err     error
}

func (r *deleteTestRevoker) RevokeByUserID(_ context.Context, userID uint, _ time.Time) (int64, error) {
	if r.err != nil {
		return 0, r.err
	}
	r.userIDs = append(r.userIDs, userID)
	return 1, nil
}

// TestDeleteUserRevokesAdminAPITokens is the regression guard for user removal:
// deleting an account must retire its admin API tokens, not only the account row.
func TestDeleteUserRevokesAdminAPITokens(t *testing.T) {
	email, _ := uvo.NewEmail("u@example.com")
	name, _ := uvo.NewName("Test User")
	now := time.Now().UTC()
	u, err := domainUser.ReconstructUser(5, "usr_aaaaaaaaaaaa", email, name, authorization.RoleAdmin, uvo.StatusActive, now, now, 1)
	require.NoError(t, err)

	repo := &deleteTestUserRepo{u: u}
	svc := NewServiceDDD(repo, nil, nil, logger.NewLogger())
	revoker := &deleteTestRevoker{}
	svc.SetAdminTokenRevoker(revoker)

	require.NoError(t, svc.DeleteUser(context.Background(), "usr_aaaaaaaaaaaa"))
	require.Equal(t, []uint{5}, revoker.userIDs)
	require.Equal(t, "usr_aaaaaaaaaaaa", repo.deleted)
}

// TestDeleteUserRevocationFailureStillDeletes documents the best-effort contract.
func TestDeleteUserRevocationFailureStillDeletes(t *testing.T) {
	email, _ := uvo.NewEmail("u@example.com")
	name, _ := uvo.NewName("Test User")
	now := time.Now().UTC()
	u, err := domainUser.ReconstructUser(6, "usr_bbbbbbbbbbbb", email, name,
		authorization.RoleAdmin, uvo.StatusActive, now, now, 1)
	require.NoError(t, err)

	repo := &deleteTestUserRepo{u: u}
	svc := NewServiceDDD(repo, nil, nil, logger.NewLogger())
	svc.SetAdminTokenRevoker(&deleteTestRevoker{err: context.DeadlineExceeded})

	require.NoError(t, svc.DeleteUser(context.Background(), "usr_bbbbbbbbbbbb"))
	require.Equal(t, "usr_bbbbbbbbbbbb", repo.deleted)
}
