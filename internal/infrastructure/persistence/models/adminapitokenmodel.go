package models

import (
	"time"

	"github.com/orris-inc/orris/internal/shared/constants"
)

// AdminAPITokenModel is the persistence model for admin API tokens.
type AdminAPITokenModel struct {
	ID         uint       `gorm:"primaryKey"`
	SID        string     `gorm:"column:sid;size:50;not null;uniqueIndex:idx_admin_api_tokens_sid"`
	Name       string     `gorm:"size:100;not null"`
	TokenHash  string     `gorm:"column:token_hash;size:64;not null;uniqueIndex:idx_admin_api_tokens_token_hash"`
	TokenHint  string     `gorm:"column:token_hint;size:32;not null;default:''"`
	CreatedBy  uint       `gorm:"column:created_by;not null;index:idx_admin_api_tokens_created_by"`
	LastUsedAt *time.Time `gorm:"column:last_used_at"`
	ExpiresAt  *time.Time `gorm:"column:expires_at;index:idx_admin_api_tokens_expires_at"`
	RevokedAt  *time.Time `gorm:"column:revoked_at"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// TableName specifies the table name for GORM.
func (AdminAPITokenModel) TableName() string {
	return constants.TableAdminAPITokens
}
