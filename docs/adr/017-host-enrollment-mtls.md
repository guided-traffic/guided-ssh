# ADR-017: Host-Enrollment mit Einmal-Token, eigene mTLS-Mini-PKI, Fail-closed-Principals

- Status: akzeptiert
- Datum: 2026-07-19

## Kontext

Phase 5 braucht: Host-Enrollment (Vertrauens-Bootstrap), einen Host-Agenten
(`gssh-agentd`) für Zertifikatserneuerung und CA-Bundle-Pflege sowie den
`AuthorizedPrincipalsCommand`-Pfad mit Fail-closed-Verhalten. ADR-008 setzt
mTLS für Host-Agenten.

## Entscheidung

- **Enrollment-Token**: einmalig, per `gssh-server enroll-token` erzeugt
  (direkter DB-Zugriff — es gibt noch keine Admin-API). In der DB liegt nur
  der SHA-256-Hash; Verbrauch ist ein einzelnes transaktionales UPDATE
  (Single-Use auch bei parallelen Versuchen). Tokens tragen optional eine
  Hostnamen-Bindung und Host-Tags; ein falsch eingesetztes gebundenes Token
  ist bewusst verbrannt. Re-Enrollment (neues Token, gleicher Name)
  aktualisiert den Host statt zu duplizieren.
- **mTLS-Mini-PKI**: eigene X.509-CA (Ed25519) in `ca_keys` (purpose `mtls`,
  Private Key AES-GCM-verschlüsselt wie die SSH-CAs, ADR-014). Beim
  Enrollment schickt der Agent einen CSR; der Server setzt den CommonName
  auf die Host-UUID — Identität kommt nie aus dem CSR. Der Agent-Listener
  (`-agent-listen`) terminiert TLS mit einem bei jedem Start neu
  ausgestellten Server-Zertifikat aus derselben CA (SANs via
  `GSSH_AGENT_TLS_NAMES`) und verlangt Client-Zertifikate
  (`RequireAndVerifyClientCert`). Enrollment selbst läuft über den
  öffentlichen Listener (Henne-Ei), optional mit SPKI-Pinning (`--pin`,
  ADR-016). Client-Zertifikate: 1 Jahr; Rotation ist Phase 10.
- **Host-Zertifikate**: 30 Tage (Policy-Maximum), Principals = voller Name +
  Kurzname; der Agent erneuert bei 2/3 der Laufzeit und führt optional ein
  `reload_command` aus (sshd liest `HostCertificate` nur beim Start).
- **Principals-Pfad**: sshd → `AuthorizedPrincipalsCommand gssh-agentd
  principals` → Unix-Socket des Daemons → Cache/API. Antwort = Identitäts-
  Principals (Username, E-Mail) aller aktiven Mitglieder von Gruppen, deren
  Grant den lokalen Benutzer als Ziel-Principal enthält und deren
  Tag-Selektor auf die Host-Tags passt (Selektor ⊆ Tags; die volle
  Grant-Verwaltung folgt in Phase 6). Fail-closed: liefert die API keinen
  Wert und ist der Cache älter als `cache_ttl`, gibt der Helper nichts aus
  und sshd verweigert. Cache wird auf Platte persistiert (übersteht
  Neustarts).
- **sshd-Integration**: Enrollment schreibt idempotent
  `sshd_config.d/guided-ssh.conf` (TrustedUserCAKeys, HostCertificate,
  AuthorizedPrincipalsCommand), das Host-Zertifikat neben den vorhandenen
  Host-Key und das User-CA-Bundle. Der vorhandene sshd-Host-Key wird
  weiterverwendet (kein neues Schlüsselmaterial auf dem Host).
- **Paketierung**: nfpm (deb/rpm) + systemd-Unit + Install-Skript; der
  Dienst startet erst nach explizitem Enrollment.

## Konsequenzen

- Sicherheit des Enrollments hängt am Token (einmalig, ablaufend, gehasht,
  optional namensgebunden) und an TLS des öffentlichen Listeners.
- Die Agent-API ist ohne gültiges Client-Zertifikat nicht erreichbar;
  Host-Identität steckt im Zertifikat (CN = Host-UUID), nicht in Requests.
- Offboarding wirkt auf Hosts über den Principals-Pfad innerhalb der
  Cache-TTL (Default 5 m) — konsistent mit dem Gruppen-Sync aus ADR-015.
- Wenn `AuthorizedPrincipalsCommand` konfiguriert ist, zählt bei sshd nur
  noch dessen Ausgabe (kein Username-Fallback) — Logins brauchen ab dann
  zwingend passende Grants; das ist gewollt (zentrale Steuerung).
- Getestet end-to-end im Integrationstest: Container-sshd, Enrollment,
  Login per Benutzerzertifikat (Principal- und Grant-Pfad), Ablehnung ohne
  Grant.
