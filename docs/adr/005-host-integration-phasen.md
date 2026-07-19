# ADR-005: Host-Integration — sshd-nativ zuerst, NSS/PAM später

- Status: akzeptiert
- Datum: 2026-07-19

## Kontext

Zugriffssteuerung auf dem Host kann über sshd-Bordmittel
(`TrustedUserCAKeys`, `AuthorizedPrincipalsCommand`) oder tiefer über NSS-/PAM-Module
(zentrale Konten, sudo-Audit) erfolgen. NSS/PAM bedeutet C-Interop, heikle
Fehlerpfade im Login-Stack und deutlich mehr Testaufwand.

## Entscheidung

Stufe 1 (MVP): Zertifikats-Authentifizierung rein über sshd-Mechanik —
`TrustedUserCAKeys`, `HostCertificate`, `AuthorizedPrincipalsCommand` gegen den
lokalen Host-Agent (Unix-Socket, Cache, fail-closed).
Stufe 2 (Phase 9, nach MVP-Erfahrung): PAM für Session-/sudo-Audit, optional NSS
für zentrale Konten (UID/GID aus IdP).

## Konsequenzen

- MVP ohne C-Code, geringes Risiko im Login-Pfad; lokale Konten müssen zunächst
  über bestehendes Provisioning des Betreibers existieren.
- Offboarding wirkt über Host-ACL (Principals) trotzdem sofort innerhalb Cache-TTL.
- Session-/sudo-Audit auf dem Host kommt erst mit Stufe 2; bis dahin nur
  Ausstellungs-Audit (serverseitig) und sshd-Logs.
- Stufe 2 umgesetzt (Phase 9): `pam_exec` statt C-Modul, Serial-Korrelation über
  sshd-Tokens `%s`/`%i`, host-lokales Opt-in — Details in ADR-021. NSS bleibt offen.
