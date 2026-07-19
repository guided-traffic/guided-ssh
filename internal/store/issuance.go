package store

import (
	"context"
	"fmt"
)

// CreateCertificateWithAudit persistiert Zertifikats-Metadaten und das
// zugehörige Audit-Event in einer Transaktion: entweder landen beide
// Einträge in der Datenbank oder keiner (Phase-2-Garantie: jede Signatur
// erzeugt synchron beides).
func (s *Store) CreateCertificateWithAudit(ctx context.Context, c *Certificate, e *AuditEvent) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("transaktion starten: %w", err)
	}
	// Rollback nach erfolgreichem Commit ist ein No-op.
	defer func() { _ = tx.Rollback(ctx) }()

	if err := insertCertificate(ctx, tx, c); err != nil {
		return fmt.Errorf("zertifikat persistieren: %w", err)
	}
	if err := insertAuditEvent(ctx, tx, e); err != nil {
		return fmt.Errorf("audit-event schreiben: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("transaktion abschließen: %w", err)
	}
	return nil
}
