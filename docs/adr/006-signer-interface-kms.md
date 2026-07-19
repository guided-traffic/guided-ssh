# ADR-006: Signer-Interface — Software-Key zuerst, KMS/HSM später

- Status: akzeptiert
- Datum: 2026-07-19

## Kontext

Der CA-Schlüssel ist das wertvollste Asset (siehe Bedrohungsmodell). Produktionsreife
verlangt KMS/HSM; für Entwicklung und frühe Phasen wäre das unverhältnismäßig schwer.

## Entscheidung

Signieren läuft ausschließlich über ein Interface
(`Sign(ctx, CertRequest) (*ssh.Certificate, error)`). Erste Implementierung:
Software-Signer mit Ed25519-Key, verschlüsselt at rest (Schlüssel aus K8s-Secret).
Später (Phase 10): PKCS#11-Signer (deckt HSM und SoftHSM-Tests ab), Cloud-KMS nach Bedarf.
Benutzer- und Host-CA verwenden getrennte Schlüssel.

## Konsequenzen

- Backend-Wechsel ohne Umbau der CA-Logik; Policy- und Audit-Pfad identisch für alle Signer.
- Jede Signatur-Operation wird unabhängig vom Backend auditiert.
- Software-Signer bleibt dauerhaft für Entwicklung/Tests; Produktions-Deployments
  konfigurieren das Backend über Helm-Values.
