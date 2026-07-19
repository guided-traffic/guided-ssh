# ADR-018: Grant-Modell — additiv, Identitäts-Principals im Zertifikat, deklarativer Abgleich

- Status: akzeptiert
- Datum: 2026-07-19

## Kontext

Phase 6 braucht die volle Zugriffssteuerung: ein Grant verknüpft eine
IdP-Gruppe über einen Tag-Selektor mit Ziel-Principals (lokale Benutzer wie
`deploy`, `root`), einem sudo-Flag und einer maximalen Zertifikatslaufzeit.
Die Auswertung passiert an zwei Stellen — bei der Ausstellung und auf dem
Host (ADR-017: `AuthorizedPrincipalsCommand`, fail-closed). Offen waren:
Konfliktregeln, was Grants im Zertifikat bewirken, und wie Grants gepflegt
werden.

## Entscheidung

- **Nur additive Grants, kein deny.** Jeder Grant erweitert Zugriff; es gibt
  keine Regel, die Zugriff entzieht. Entzug passiert ausschließlich über das
  Entfernen von Grants oder Gruppenmitgliedschaften (IdP-Sync, ADR-015).
  Damit sind Konflikte unmöglich: die Wirkung mehrerer Grants ist die
  Vereinigung ihrer Wirkungen. Konkret: Laufzeit = Maximum der
  `max_validity` über die Grants des Benutzers; sudo = wahr, sobald ein
  passender Grant es setzt.
- **Zertifikate tragen weiterhin nur Identitäts-Principals** (Username,
  E-Mail) — keine Ziel-Principals wie `deploy`. Welche lokalen Benutzer eine
  Identität erreicht, entscheidet der Host zur Login-Zeit über den
  Principals-Pfad (Grant-Auswertung serverseitig, Cache-TTL Default 5 m).
  Stünden Ziel-Principals im Zertifikat, würde ein Grant-Entzug erst mit dem
  Zertifikatsablauf wirken und Hosts ohne `AuthorizedPrincipalsCommand`
  würden das Zertifikat direkt akzeptieren.
- **Auswertung bei der Ausstellung** (`POST /v1/sign/user`): ohne mindestens
  einen Grant (über die Gruppen des Benutzers) wird kein Zertifikat
  ausgestellt (403) — wer nirgends Zugriff hat, bekommt gar kein Zertifikat.
  Die gewünschte Laufzeit wird auf das Grant-Maximum gekappt (nicht
  abgelehnt, damit der Default überall funktioniert); die globale Policy
  (ADR: 16 h für Benutzer) greift zusätzlich.
- **Verwaltung über eine Admin-API** (`/v1/admin/grants…`): CRUD plus
  deklarativer Abgleich (`POST /v1/admin/grants/apply`). Autorisierung über
  dieselbe OIDC-Validierung wie der Sign-Endpoint plus Mitgliedschaft in
  einer konfigurierten Admin-Gruppe (`GSSH_ADMIN_GROUP`; unkonfiguriert ⇒
  Admin-API deaktiviert, fail-closed). Jede Mutation schreibt transaktional
  ein Audit-Event (`grant.created/updated/deleted`) mit dem Admin als Actor.
- **CLI `gssh-admin`**: `grant list/create/update/delete` und
  `apply -f grants.yaml`. Der Apply ist ein Vollabgleich (GitOps): die Datei
  ist der Zielzustand; Grants werden über (Issuer, Gruppe, Tag-Selektor)
  identifiziert — neue angelegt, abweichende aktualisiert, nicht mehr
  deklarierte gelöscht. Unbekannte Gruppen werden angelegt und vom IdP-Sync
  später mit Mitgliedern verknüpft.

## Konsequenzen

- Keine Konfliktauflösung nötig; Reviews von `grants.yaml` beantworten
  „wer darf was" vollständig, weil nichts anderes Zugriff gewähren kann.
- Ein restriktiver Grant kann großzügigere nicht einschränken (max statt
  min bei der Laufzeit) — wer kürzere Laufzeiten erzwingen will, entfernt
  die großzügigeren Grants.
- Grant-Entzug wirkt auf Hosts innerhalb der Cache-TTL, auf die Ausstellung
  beim nächsten Login mit frischem Token; bereits ausgestellte Zertifikate
  bleiben bis zum Ablauf gültig (kurze Laufzeiten bleiben deshalb wichtig).
- Das sudo-Flag wird gespeichert und über die Admin-API gepflegt; die
  Durchsetzung auf dem Host (sudoers/PAM) folgt in Phase 9.
- CI-Grants (Projekt × Branch-Bedingung, Phase 7) bauen auf demselben
  additiven Modell auf.
