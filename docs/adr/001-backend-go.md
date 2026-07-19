# ADR-001: Backend in Go

- Status: akzeptiert
- Datum: 2026-07-19

## Kontext

Die Plattform besteht aus API-Server/CA, Benutzer-CLI (`gssh`), Admin-CLI
(`gssh-admin`) und Host-Agent (`gssh-agentd`). Host-Agent und CLIs müssen auf
heterogenen Zielsystemen ohne Laufzeitabhängigkeiten laufen; das Herzstück ist
SSH-Zertifikatslogik.

## Entscheidung

Alle Serverkomponenten, CLIs und der Host-Agent werden in Go implementiert.

## Konsequenzen

- `golang.org/x/crypto/ssh` deckt SSH-Zertifikate (Bau, Signatur, Parsing) nativ ab.
- Statische Binaries (`CGO_ENABLED=0`) für Host-Agent/CLI — Installation per Paket
  ohne Abhängigkeiten; einfaches Cross-Compiling (linux/amd64, linux/arm64, darwin/arm64).
- Ein Sprachstack für Server, CLI und Agent — geteilter Code (API-Typen, Client).
- NSS-/PAM-Module (Phase 9) benötigen ggf. C-Interop; bewusst nach hinten geschoben
  (siehe ADR-005).
