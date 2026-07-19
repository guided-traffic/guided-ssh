package store

import (
	"context"
)

// NextCertificateSerial vergibt die nächste Zertifikats-Seriennummer.
func (s *Store) NextCertificateSerial(ctx context.Context) (int64, error) {
	var serial int64
	err := s.pool.QueryRow(ctx, `SELECT nextval('certificate_serial_seq')`).Scan(&serial)
	return serial, err
}

// insertCertificate persistiert die Metadaten eines ausgestellten Zertifikats
// über den gegebenen querier (Pool oder Transaktion). Nil-IssuerContext wird zu {}.
func insertCertificate(ctx context.Context, q querier, c *Certificate) error {
	created, err := queryOne[Certificate](ctx, q, `
		INSERT INTO certificates
			(serial, key_id, cert_type, public_key, principals, valid_after, valid_before,
			 ca_key_id, user_id, service_account_id, host_id, issuer_context)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, COALESCE($12, '{}'::jsonb))
		RETURNING *`,
		c.Serial, c.KeyID, c.CertType, c.PublicKey, c.Principals, c.ValidAfter, c.ValidBefore,
		c.CAKeyID, c.UserID, c.ServiceAccountID, c.HostID, c.IssuerContext)
	if err != nil {
		return err
	}
	*c = *created
	return nil
}

// CreateCertificate persistiert die Metadaten eines ausgestellten Zertifikats
// und füllt ID und Zeitstempel.
func (s *Store) CreateCertificate(ctx context.Context, c *Certificate) error {
	return insertCertificate(ctx, s.pool, c)
}

// GetCertificateBySerial liefert ein Zertifikat per Seriennummer.
func (s *Store) GetCertificateBySerial(ctx context.Context, serial int64) (*Certificate, error) {
	return queryOne[Certificate](ctx, s.pool, `SELECT * FROM certificates WHERE serial = $1`, serial)
}

// ListCertificates liefert Zertifikate, neueste zuerst. limit 0 ⇒ alle.
func (s *Store) ListCertificates(ctx context.Context, limit int) ([]Certificate, error) {
	return queryAll[Certificate](ctx, s.pool, `
		SELECT * FROM certificates
		ORDER BY created_at DESC, serial DESC
		LIMIT NULLIF($1, 0)`, limit)
}
