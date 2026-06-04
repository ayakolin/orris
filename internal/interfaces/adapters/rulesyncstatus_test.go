package adapters

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/orris-inc/orris/internal/application/forward/dto"
	"github.com/orris-inc/orris/internal/application/forward/testutil"
)

func TestRuleSyncStatusAdapterPreservesListenIP(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run() error = %v", err)
	}
	defer mr.Close()

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()

	adapter := NewRuleSyncStatusAdapter(client, testutil.NewMockLogger())
	ctx := context.Background()

	err = adapter.UpdateRuleStatus(ctx, 1, []dto.RuleSyncStatusItem{
		{
			RuleID:      "fr_listen_ip",
			SyncStatus:  "synced",
			RunStatus:   "running",
			ListenPort:  13306,
			ListenIP:    "127.0.0.1",
			Connections: 3,
			SyncedAt:    123,
		},
	})
	if err != nil {
		t.Fatalf("UpdateRuleStatus() error = %v", err)
	}

	got, err := adapter.GetRuleStatus(ctx, 1)
	if err != nil {
		t.Fatalf("GetRuleStatus() error = %v", err)
	}
	if len(got.Rules) != 1 {
		t.Fatalf("GetRuleStatus() rules length = %d, want 1", len(got.Rules))
	}
	if got.Rules[0].ListenIP != "127.0.0.1" {
		t.Fatalf("ListenIP = %q, want 127.0.0.1", got.Rules[0].ListenIP)
	}
}
