# guided-ssh

## Orientierung im Projekt

Ich (Claude) nutze graphify selbst, um mich schnell im Projekt zurechtzufinden — nicht
nur auf Zuruf. Vorgehen:

- **Zu Session-Beginn / bei unbekanntem Code**: zuerst den vorhandenen Knowledge-Graph
  in `graphify-out/` konsultieren (`GRAPH_REPORT.md` für God-Nodes/Communities,
  `graph.json` für Details) statt blind Dateien zu durchsuchen. Gezielt fragen:
  `/graphify query "<frage>"`, `/graphify path "<A>" "<B>"`, `/graphify explain "<node>"`.
- **Graph fehlt oder ist veraltet**: `/graphify .` (voller Aufbau) bzw. `/graphify . --update`
  (nur geänderte Dateien; bei reinen Code-Änderungen ohne LLM). Nach größeren Änderungen
  aktuell halten.
- `graphify-out/` ist Arbeitsartefakt (nicht committen, sofern nicht anders gewünscht).

## Projektkontext

- Plan und Fortschritt: `INITIAL_PROJECT_PLAN.md` (Phasen mit abhakbaren Steps — dort abhaken, was erledigt ist)
- Wenn du einen Task abgeschlossen hast, gib zusätzlich eine kurzen conventional commit message aus
