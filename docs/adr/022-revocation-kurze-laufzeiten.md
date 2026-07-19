# ADR-022: Revocation — kurze Laufzeiten primär, RevokedKeys als Notfallweg

## Status

Akzeptiert (Phase 10).

## Kontext

SSH-Zertifikate haben keine Online-Statusprüfung (kein OCSP/CRL-Protokoll wie
bei X.509/TLS). sshd kennt als einzigen Entzugsmechanismus die
`RevokedKeys`-Direktive (KRL-Datei oder authorized_keys-Liste), die auf jedem
Host liegen und aktuell gehalten werden muss. Für guided-ssh stellt sich die
Frage: Wie wird ein kompromittierter Schlüssel oder ein ausgeschiedener
Benutzer wirksam ausgesperrt — und wie schnell?

## Entscheidung

1. **Kurze Laufzeiten sind der primäre Mechanismus.** Die Policy deckelt
   Benutzer-Zertifikate auf 16 h, CI-Zertifikate auf 1 h (zusätzlich auf den
   Token-Ablauf = Job-Timeout gedeckelt). Ein entwendetes Zertifikat ist damit
   von selbst binnen Stunden wertlos; es gibt keinen langlebigen
   Client-Credential-Bestand, der verwaltet werden müsste.

2. **Der schnelle Entzugshebel ist die Principals-Auskunft, nicht das
   Zertifikat.** Hosts entscheiden jeden Login über den
   `AuthorizedPrincipalsCommand`-Helfer (fail-closed, Cache-TTL 5 min) anhand
   der Grants. Grant-Entzug, Deaktivieren eines Benutzers oder
   Gruppen-Entfernung im IdP (Sync-Intervall 5 min) wirken damit unabhängig
   von der Restlaufzeit bereits ausgestellter Zertifikate — in der Regel
   innerhalb von ~10 Minuten auf jedem erreichbaren Host. Neue Zertifikate
   bekommt der Benutzer ab sofort keine mehr (kein Grant ⇒ keine Ausstellung).

3. **mTLS-Agent-Zertifikate: Entzug über den Host-Datensatz.** Die Agent-API
   löst die Identität bei jedem Request über den Host-Datensatz auf
   (CN = Host-UUID). Wird ein Host gelöscht, sind sein mTLS-Zertifikat und
   damit Renew/Principals/Sessions sofort wirkungslos — unabhängig von der
   Zertifikatslaufzeit (1 Jahr, Rotation bei 2/3, siehe Phase 10).

4. **`RevokedKeys`-Verteilung über den Host-Agent als Notfallweg
   (Ausbaustufe).** Für den Fall „Zertifikat kompromittiert und Restlaufzeit
   nicht akzeptabel" ist die Verteilung einer zentral gepflegten Sperrliste
   vorgesehen: Serial-basierte KRL auf dem Server, Abruf durch den Agenten
   analog zum CA-Bundle (`/v1/agent/…`, stündlich), `RevokedKeys`-Direktive im
   generierten sshd-Snippet. Bewusst **noch nicht implementiert** — die Fälle,
   die sie abdeckt, sind durch (1)–(3) auf ein Restfenster von Stunden
   begrenzt, und eine halb verteilte Sperrliste (nicht erreichbare Hosts)
   darf nicht als verlässlich verkauft werden.

5. **Nuklearoption: CA-Rotation.** Bei Kompromittierung des CA-Keys selbst
   wird ein neuer CA-Key ausgerollt (Agenten ziehen das Bundle stündlich) und
   der alte aus `TrustedUserCAKeys` entfernt; alle Alt-Zertifikate werden
   damit auf einen Schlag ungültig. Das Verfahren existiert durch die
   Bundle-Verteilung bereits, kostet aber eine Neuausstellung für alle
   aktiven Nutzer.

## Konsequenzen

- Das maximale Restrisiko-Fenster eines gestohlenen Benutzer-Zertifikats ist
  seine Restlaufzeit (≤ 16 h) — aber nur auf Hosts, deren Grants den
  zugehörigen Benutzer weiterhin autorisieren. Entzug der Grants schließt
  auch dieses Fenster bis auf die Principals-Cache-TTL (5 min).
- Offline-/nicht erreichbare Hosts lernen Entzüge erst beim nächsten
  API-Kontakt; der Principals-Cache antwortet dort maximal `cache_ttl`
  (Default 5 min) aus dem Cache und ist danach fail-closed.
- Die KRL-Verteilung (4) ist als Folgeschritt geschnitten: Store-Tabelle für
  gesperrte Serials, Admin-Endpoint/CLI, Agent-Abruf, Snippet-Erweiterung.
  Bis dahin ist die dokumentierte Notfallmaßnahme: Grants/Benutzer entziehen
  (sofort wirksam via Principals) und bei CA-Verdacht rotieren (5).
