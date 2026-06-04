package usecases

import (
	"context"
	"strings"
	"testing"

	forwardtestutil "github.com/orris-inc/orris/internal/application/forward/testutil"
	"github.com/orris-inc/orris/internal/domain/forward"
)

func TestGenerateInstallScriptUsesAgentSIDAsDefaultInstanceName(t *testing.T) {
	agent := mustForwardAgent(t, "fa_123456789abc", "stored-token")
	repo := forwardtestutil.NewMockForwardAgentRepository()
	repo.AddAgent(agent)

	uc := NewGenerateInstallScriptUseCase(repo, forwardtestutil.NewMockLogger())
	result, err := uc.Execute(context.Background(), GenerateInstallScriptQuery{
		ShortID:   agent.SID(),
		ServerURL: "https://orris.example.com",
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	want := "curl -fsSL " + InstallScriptURL + " | sudo bash -s -- -s 'https://orris.example.com' -t 'stored-token' -n 'fa_123456789abc' -W 0 -T 0"
	if result.InstallCommand != want {
		t.Fatalf("InstallCommand mismatch\nwant: %s\n got: %s", want, result.InstallCommand)
	}
	if !strings.Contains(result.UninstallCommand, "-n 'fa_123456789abc'") {
		t.Fatalf("UninstallCommand should target default SID instance, got: %s", result.UninstallCommand)
	}
}

func TestGenerateInstallScriptKeepsLegacyDefaultWhenRequested(t *testing.T) {
	agent := mustForwardAgent(t, "fa_123456789abc", "stored-token")
	repo := forwardtestutil.NewMockForwardAgentRepository()
	repo.AddAgent(agent)

	uc := NewGenerateInstallScriptUseCase(repo, forwardtestutil.NewMockLogger())
	result, err := uc.Execute(context.Background(), GenerateInstallScriptQuery{
		ShortID:   agent.SID(),
		ServerURL: "https://orris.example.com",
		Name:      "default",
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	want := "curl -fsSL " + InstallScriptURL + " | sudo bash -s -- -s 'https://orris.example.com' -t 'stored-token'"
	if result.InstallCommand != want {
		t.Fatalf("InstallCommand mismatch\nwant: %s\n got: %s", want, result.InstallCommand)
	}
	if strings.Contains(result.UninstallCommand, "-n") {
		t.Fatalf("legacy default uninstall should not target a named instance, got: %s", result.UninstallCommand)
	}
}

func TestGenerateInstallScriptRejectsNamesUnsupportedByClientInstaller(t *testing.T) {
	agent := mustForwardAgent(t, "fa_123456789abc", "stored-token")
	repo := forwardtestutil.NewMockForwardAgentRepository()
	repo.AddAgent(agent)

	uc := NewGenerateInstallScriptUseCase(repo, forwardtestutil.NewMockLogger())
	_, err := uc.Execute(context.Background(), GenerateInstallScriptQuery{
		ShortID:   agent.SID(),
		ServerURL: "https://orris.example.com",
		Name:      "agent.v1",
	})
	if err == nil {
		t.Fatal("expected error for instance name unsupported by orris-client install.sh")
	}
}

func mustForwardAgent(t *testing.T, sid, token string) *forward.ForwardAgent {
	t.Helper()

	agent, err := forward.NewForwardAgent(
		"agent",
		"",
		"",
		"",
		func() (string, error) { return sid, nil },
		func(string) (string, string) { return token, "token-hash" },
	)
	if err != nil {
		t.Fatalf("NewForwardAgent returned error: %v", err)
	}
	return agent
}
