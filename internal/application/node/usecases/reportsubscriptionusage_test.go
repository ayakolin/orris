package usecases

import (
	"context"
	"testing"

	"github.com/orris-inc/orris/internal/application/node/dto"
	"github.com/orris-inc/orris/internal/domain/subscription"
	svo "github.com/orris-inc/orris/internal/domain/subscription/valueobjects"
	"github.com/orris-inc/orris/internal/shared/logger"
)

type stubUsageRecorder struct {
	recorded []SubscriptionUsageItem
}

func (s *stubUsageRecorder) RecordSubscriptionUsage(context.Context, uint, uint, int64, int64) error {
	return nil
}

func (s *stubUsageRecorder) BatchRecordSubscriptionUsage(_ context.Context, _ uint, items []SubscriptionUsageItem) error {
	s.recorded = append(s.recorded, items...)
	return nil
}

type stubResolver struct {
	mapping map[string]uint
}

func (s *stubResolver) GetIDBySID(_ context.Context, sid string) (uint, error) {
	return s.mapping[sid], nil
}

func (s *stubResolver) GetIDsBySIDs(_ context.Context, _ []string) (map[string]uint, error) {
	return s.mapping, nil
}

type stubAuthorizer struct {
	subs []*subscription.Subscription
}

func (s *stubAuthorizer) GetActiveSubscriptionsByNodeID(context.Context, uint) ([]*subscription.Subscription, error) {
	return s.subs, nil
}

func mustSubscription(t *testing.T, id uint) *subscription.Subscription {
	t.Helper()
	sub, err := subscription.ReconstructSubscriptionWithParams(subscription.SubscriptionReconstructParams{
		ID:          id,
		SID:         "sub_aaaaaaaaaaaa",
		UUID:        "uuid-1",
		LinkToken:   "link-1",
		SubjectType: "user",
		SubjectID:   1,
		UserID:      1,
		PlanID:      1,
		Status:      svo.StatusActive,
	})
	if err != nil {
		t.Fatalf("reconstruct subscription: %v", err)
	}
	return sub
}

// A node must not be able to record usage for a subscription it is not authorized
// to serve; only the authorized subscription's usage is persisted.
func TestReportSubscriptionUsage_DropsUnauthorizedSubscription(t *testing.T) {
	const authorizedID = uint(100)
	const evilID = uint(999)

	const authorizedSID = "sub_aaaaaaaaaaaa"
	const evilSID = "sub_bbbbbbbbbbbb"

	recorder := &stubUsageRecorder{}
	resolver := &stubResolver{mapping: map[string]uint{
		authorizedSID: authorizedID,
		evilSID:       evilID,
	}}
	authorizer := &stubAuthorizer{subs: []*subscription.Subscription{mustSubscription(t, authorizedID)}}

	uc := NewReportSubscriptionUsageUseCase(recorder, resolver, authorizer, logger.NewLogger())

	res, err := uc.Execute(context.Background(), ReportSubscriptionUsageCommand{
		NodeID: 7,
		Subscriptions: []dto.SubscriptionUsageItem{
			{SubscriptionSID: authorizedSID, Upload: 10, Download: 20},
			{SubscriptionSID: evilSID, Upload: 1 << 40, Download: 1 << 40},
		},
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	if res.SubscriptionsUpdated != 1 {
		t.Fatalf("expected 1 authorized subscription recorded, got %d", res.SubscriptionsUpdated)
	}
	if len(recorder.recorded) != 1 || recorder.recorded[0].SubscriptionID != authorizedID {
		t.Fatalf("expected only authorized subscription %d recorded, got %+v", authorizedID, recorder.recorded)
	}
}
