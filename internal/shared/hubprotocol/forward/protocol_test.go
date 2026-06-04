package forward

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRuleSyncDataSerializesListenIP(t *testing.T) {
	data := RuleSyncData{
		ID:         "fr_test",
		RuleType:   "direct",
		ListenIP:   "127.0.0.1",
		ListenPort: 18080,
		Protocol:   "tcp",
	}

	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("failed to marshal RuleSyncData: %v", err)
	}
	if !strings.Contains(string(encoded), `"listen_ip":"127.0.0.1"`) {
		t.Fatalf("encoded RuleSyncData missing listen_ip: %s", encoded)
	}
}
