package usecases

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/orris-inc/orris/internal/domain/forward"
)

func isPortInUseByAgentListenIP(ctx context.Context, repo forward.Repository, agent *forward.ForwardAgent, port uint16, listenIP string, excludeRuleID uint) (bool, error) {
	if agent == nil {
		return false, errors.New("agent is required for port usage check")
	}
	targetListenIP, err := normalizeListenIPForPortUsage(listenIP)
	if err != nil {
		return false, err
	}

	usages, err := repo.ListPortUsagesByAgent(ctx, agent.ID(), port, excludeRuleID)
	if err != nil {
		return false, err
	}
	if len(usages) == 0 {
		return false, nil
	}

	for _, usage := range usages {
		usageListenIP := ""
		if usage.AgentID() == agent.ID() && usage.ListenPort() == port {
			usageListenIP = usage.ListenIP()
		}
		if listenIPsOverlap(targetListenIP, usageListenIP) {
			return true, nil
		}
	}

	return false, nil
}

func normalizeListenIPForPortUsage(listenIP string) (string, error) {
	listenIP = strings.TrimSpace(listenIP)
	if listenIP == "" {
		return "", nil
	}

	ip := net.ParseIP(listenIP)
	if ip == nil {
		return "", fmt.Errorf("invalid listen IP address: %s", listenIP)
	}
	if ip.IsUnspecified() {
		return "", nil
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4.String(), nil
	}
	return strings.ToLower(ip.String()), nil
}

func listenIPsOverlap(a, b string) bool {
	a, _ = normalizeListenIPForPortUsage(a)
	b, _ = normalizeListenIPForPortUsage(b)
	return a == "" || b == "" || a == b
}
