package repository

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/orris-inc/orris/internal/shared/errors"
)

// classifyOptimisticUpdate interprets a versioned Update whose RowsAffected was 0.
//
// A zero RowsAffected on a `WHERE id = ? AND version = ?` update can mean one of
// three things:
//   - the row still exists at the expected version but the update changed no
//     columns (an idempotent no-op) — not an error;
//   - the row exists at a different version — a concurrent modification;
//   - the row no longer exists — not found.
//
// tx must be the same *gorm.DB (or transaction handle) used for the Update, and
// model a pointer to the GORM model type (e.g. &models.PaymentModel{}).
func classifyOptimisticUpdate(tx *gorm.DB, model interface{}, id uint, expectedVersion int, entityName string) error {
	var atExpected int64
	if err := tx.Model(model).Where("id = ? AND version = ?", id, expectedVersion).Count(&atExpected).Error; err != nil {
		return fmt.Errorf("failed to verify %s version: %w", entityName, err)
	}
	if atExpected > 0 {
		// Row present and unchanged at the expected version: idempotent update.
		return nil
	}

	var exists int64
	if err := tx.Model(model).Where("id = ?", id).Count(&exists).Error; err != nil {
		return fmt.Errorf("failed to check %s existence: %w", entityName, err)
	}
	if exists > 0 {
		return errors.NewConflictError(entityName + " was modified by another request, please retry")
	}
	return errors.NewNotFoundError(entityName+" not found", fmt.Sprintf("id=%d", id))
}
