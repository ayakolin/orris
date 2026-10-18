-- +goose Up
-- +goose StatementBegin
CREATE TABLE admin_api_tokens (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    sid VARCHAR(50) NOT NULL COMMENT 'Stripe-style ID: apt_xxxxxxxxxxxx',
    name VARCHAR(100) NOT NULL COMMENT 'Human-readable token name',
    token_hash CHAR(64) NOT NULL COMMENT 'SHA-256 hex digest of the token value; plaintext is never stored',
    token_hint VARCHAR(32) NOT NULL DEFAULT '' COMMENT 'Non-secret display hint, e.g. orr_AbCdEfGh',
    created_by BIGINT UNSIGNED NOT NULL COMMENT 'users.id of the admin who owns the token',
    last_used_at TIMESTAMP NULL DEFAULT NULL COMMENT 'Last successful authentication',
    expires_at TIMESTAMP NULL DEFAULT NULL COMMENT 'Optional expiry; NULL means no expiry',
    revoked_at TIMESTAMP NULL DEFAULT NULL COMMENT 'Revocation time; NULL means active',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE INDEX idx_admin_api_tokens_sid (sid),
    UNIQUE INDEX idx_admin_api_tokens_token_hash (token_hash),
    INDEX idx_admin_api_tokens_created_by (created_by),
    INDEX idx_admin_api_tokens_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS admin_api_tokens;
-- +goose StatementEnd
