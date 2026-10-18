package constants

const (
	// Default pagination
	DefaultPage     = 1
	DefaultPageSize = 20
	MaxPageSize     = 100

	// Context keys
	ContextKeyUserID     = "user_id"
	ContextKeyUserRole   = "user_role"
	ContextKeyAuthMethod = "auth_method"
	ContextKeyAPITokenID = "api_token_id" // SID of the admin API token used for authentication

	// Authentication methods recorded in the gin context by RequireAuth
	AuthMethodSession  = "session"   // cookie session or JWT bearer token
	AuthMethodAPIToken = "api_token" // admin API token (orr_...)

	// User status
	UserStatusActive   = "active"
	UserStatusInactive = "inactive"
	UserStatusPending  = "pending"

	// User roles
	RoleAdmin        = "admin"
	RoleUser         = "user"
	RoleSupportAgent = "support_agent"

	// Database table names
	TableUsers                  = "users"
	TableNodes                  = "nodes"
	TableNodeShadowsocksConfigs = "node_shadowsocks_configs"
	TableNodeTrojanConfigs      = "node_trojan_configs"
	TableNodeHysteria2Configs   = "node_hysteria2_configs"
	TableNodeTUICConfigs        = "node_tuic_configs"
	TableNodeVLESSConfigs       = "node_vless_configs"
	TableNodeVMessConfigs       = "node_vmess_configs"
	TablePlans                  = "plans"
	TablePlanPricings           = "plan_pricings"
	TableSubscriptions          = "subscriptions"
	TableSubscriptionTokens     = "subscription_tokens"
	TableSubscriptionUsages     = "subscription_usages"
	TablePayments               = "payments"
	TableNotifications          = "notifications"
	TableNotificationTemplates  = "notification_templates"
	TableAnnouncements          = "announcements"
	TableAdminAPITokens         = "admin_api_tokens"
	TableTickets                = "tickets"
	TableTicketComments         = "ticket_comments"
	TableForwardRules           = "forward_rules"
	TableForwardAgents          = "forward_agents"
	TableResourceGroups         = "resource_groups"
	TableSubscriptionUsageStats = "subscription_usage_stats"
	TableExternalForwardRules   = "external_forward_rules"
	TablePasskeyCredentials     = "passkey_credentials"
	TableUSDTAmountSuffixes     = "usdt_amount_suffixes"
	TableUserAnnouncementReads  = "user_announcement_reads"
	TableNodeAnyTLSConfigs      = "node_anytls_configs"

	// Default values
	DefaultCurrency = "CNY"
)
