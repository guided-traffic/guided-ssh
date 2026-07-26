package store

import (
	"context"
	"fmt"
)

// CreateCertificateWithAudit persists the certificate metadata and the
// associated audit event in one transaction: either both entries land in
// the database or neither does (phase-2 guarantee: every signature
// produces both synchronously).
func (s *Store) CreateCertificateWithAudit(ctx context.Context, c *Certificate, e *AuditEvent) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	// Rollback after a successful commit is a no-op.
	defer func() { _ = tx.Rollback(ctx) }()

	if err := insertCertificate(ctx, tx, c); err != nil {
		return fmt.Errorf("persist certificate: %w", err)
	}
	if err := insertAuditEvent(ctx, tx, e); err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}
