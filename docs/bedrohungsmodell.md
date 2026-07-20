# Bedrohungsmodell (Skizze)

Status: initiale Skizze aus Phase 0. Vertiefung (Security-Review, Fuzzing,
KMS/HSM) in Phase 10. Diese Datei wird bei Architekturänderungen fortgeschrieben.

## Schutzgüter

1. **CA-Privatschlüssel** (Benutzer- und Host-CA — getrennt): Kompromittierung
   erlaubt beliebige SSH-Zertifikate für alle verwalteten Hosts. Kronjuwel.
2. **OIDC-Tokens** (IdP-ID-Tokens, GitLab-Job-Tokens): tauschen sich gegen Zertifikate.
3. **mTLS-Client-Zertifikate der Host-Agenten**: Zugriff auf Host-API (ACLs, CA-Bundle).
4. **Enrollment-Tokens**: erlauben Registrierung neuer Hosts.
5. **Audit-Log-Integrität**: Nachvollziehbarkeit ist Kernversprechen der Plattform.
6. **Grants/Policies in der DB**: definieren, wer wohin darf.

## Vertrauensgrenzen

- CLI ↔ API: OIDC (Authorization Code + PKCE), TLS
- Browser ↔ API: server-seitiger OIDC-Login (BFF); HttpOnly-Session-Cookie
  (AES-GCM, Schlüssel per HKDF aus dem CA-Master-Key), SameSite=Lax +
  X-Requested-With gegen CSRF; Tokens verlassen den Server nie
- Host-Agent ↔ API: mTLS mit host-gebundenem Client-Zertifikat
- CI-Job ↔ API: GitLab-OIDC-Token, Validierung gegen GitLab-JWKS
- API ↔ Postgres: interner Cluster-Verkehr, NetworkPolicy, eigene DB-Rollen
- API ↔ IdP/GitLab: TLS, gepinnte Issuer-URLs, JWKS-Cache

## Angriffsflächen und Gegenmaßnahmen

| Angriffsfläche | Bedrohung | Gegenmaßnahmen (Phase) |
|---|---|---|
| CA-Key | Exfiltration aus DB/Secret; Missbrauch durch kompromittierte API | verschlüsselt at rest (2); getrennte User-/Host-CA (2); jede Signatur synchron auditiert (2); Key-Rotation (2); KMS/HSM — Key verlässt Modul nie (10) |
| Token-Diebstahl | gestohlenes ID-/Job-Token wird gegen Zertifikat getauscht; Replay; Audience-Confusion | kurze Token- und Zertifikatslaufzeiten (2/3); strikte `iss`/`aud`/`exp`/Signatur-Prüfung mit JWKS (3/7); PKCE gegen Code-Interception (3); begrenztes Clock-Skew-Fenster (10); Rate-Limiting (10); Audit jeder Ausstellung (2) |
| Host-Agent kompromittiert | mTLS-Identität missbraucht: fremde ACLs abfragen, Principals manipulieren | Client-Zertifikat host-gebunden, API liefert nur Daten des eigenen Hosts (5); minimale API-Rechte (5); mTLS-Rotation (10); Kompromittierung begrenzt auf diesen Host — CA und andere Hosts bleiben unberührt |
| Kompromittierter CI-Runner | Runner-Token missbraucht für breiten Zugriff | Zertifikat pipeline-gebunden, Laufzeit ≤ 1 h (7); Principals durch CI-Grants eingeschränkt (7); `ref_protected`-Bedingungen (7); KeyID macht Pipeline im Audit identifizierbar (7) |
| Audit-Log | nachträgliche Manipulation/Löschung durch Angreifer oder Innentäter | append-only: DB-Rolle ohne UPDATE/DELETE + Schutz-Trigger (1); Export/Streaming an SIEM als externe Kopie (8) |
| Enrollment | geleaktes Enrollment-Token registriert Angreifer-Host | Token einmalig + kurzlebig (5); Enrollment auditiert (5); Host-Deaktivierung via API |
| Sign-Endpoints | Brute-Force, DoS, manipulierte Requests | AuthN vor jeder Policy-Auswertung (3/7); Policy-Engine begrenzt Laufzeit/Principals/Extensions (2); Rate-Limiting (10); Fuzzing/Negativtests (10) |
| Web-UI/Admin | Rechteausweitung, unbemerkte Grant-Änderungen | Rollen aus Token-Claims (8); jede Admin-Änderung erzeugt Audit-Event (8); Grants deklarativ via GitOps reviewbar (12) |

## Annahmen

- IdP und GitLab-Instanz sind vertrauenswürdig und selbst abgesichert (deren
  Kompromittierung ⇒ Identitäten nicht mehr verlässlich; außerhalb unseres Scopes).
- Kubernetes-Cluster-Admins gelten als vertrauenswürdig (sie erreichen Secrets;
  Härtung dagegen erst mit KMS/HSM in Phase 10).
- Root-Kompromittierung eines verwalteten Hosts = dieser Host ist verloren; das
  Design begrenzt den Schaden auf den Host (kurze Zertifikate, host-gebundene mTLS-Identität).
- Revocation primär über kurze Laufzeiten; `RevokedKeys`-Verteilung als Notfallweg (10).

## Offene Punkte (→ Phase 10)

- Formales Review des Token-Austauschs (Replay-Fenster, Clock-Skew-Grenzwerte)
- KMS/PKCS#11-Auswahl und SoftHSM-Testaufbau
- Bedrohungen durch bösartige `CertRequest`-Inhalte (Fuzzing-Plan)
