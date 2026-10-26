package dto

// ShouldSendListenIP reports whether a rule's ListenIP is meaningful to the
// agent playing the given role.
//
// The hub push path (RuleSyncData) and the agent pull path (ForwardRuleDTO)
// must apply exactly the same predicate: the agent compares ListenIP verbatim
// between the two sources and restarts the forwarder on any difference.
//
// listenPort is the port the agent actually listens on for this role, so a
// role that does not listen at all never receives a ListenIP.
func ShouldSendListenIP(ruleType, role, hopMode, inboundMode string, listenPort uint16) bool {
	if listenPort == 0 {
		return false
	}

	switch ruleType {
	case "direct":
		return true
	case "entry":
		return role == "entry"
	case "chain":
		return role == "entry" || hopMode == "direct" || inboundMode == "direct"
	case "direct_chain":
		return true
	default:
		return role == "entry"
	}
}
