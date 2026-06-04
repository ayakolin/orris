package usecases

import (
	"testing"

	"github.com/orris-inc/orris/internal/application/forward/dto"
)

func TestBuildAgentStatusesIncludesListenIP(t *testing.T) {
	rule := mustTestRule(t, "fr_listen_ip", 1, 13306, "127.0.0.1")
	uc := &GetRuleOverallStatusUseCase{}

	statuses := uc.buildAgentStatuses(
		rule,
		[]uint{1},
		map[uint]*dto.RuleSyncStatusQueryResult{
			1: {
				Rules: []dto.RuleSyncStatusItem{
					{
						RuleID:      rule.SID(),
						SyncStatus:  "synced",
						RunStatus:   "running",
						ListenPort:  13306,
						ListenIP:    "127.0.0.1",
						Connections: 2,
						SyncedAt:    123,
					},
				},
			},
		},
		map[uint]string{1: "fa_entry"},
		map[uint]string{1: "Entry Agent"},
	)

	if len(statuses) != 1 {
		t.Fatalf("statuses length = %d, want 1", len(statuses))
	}
	if statuses[0].ListenIP != "127.0.0.1" {
		t.Fatalf("ListenIP = %q, want 127.0.0.1", statuses[0].ListenIP)
	}
}
