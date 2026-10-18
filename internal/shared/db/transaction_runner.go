package db

import "context"

// TransactionRunner runs a function inside a database transaction.
// It is implemented by TransactionManager and lets application code (and tests)
// substitute a transaction boundary without depending on GORM.
type TransactionRunner interface {
	RunInTransaction(ctx context.Context, fn func(ctx context.Context) error) error
}
