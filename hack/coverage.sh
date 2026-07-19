#!/usr/bin/env bash
# Erzwingt die minimale Gesamt-Testabdeckung über allen Go-Code (Coverage-Gate).
# Aufruf: hack/coverage.sh [coverage-profil] [minimum-prozent]
set -euo pipefail

profile="${1:-coverage.out}"
min="${2:-80}"

if [[ ! -f "$profile" ]]; then
  echo "FEHLER: Coverage-Profil '$profile' nicht gefunden (erst 'make cover' bzw. 'go test -coverprofile' laufen lassen)" >&2
  exit 1
fi

total="$(go tool cover -func="$profile" | awk '/^total:/ { sub(/%/, "", $3); print $3 }')"

echo "Gesamtabdeckung: ${total}% (Minimum: ${min}%)"
if awk -v t="$total" -v m="$min" 'BEGIN { exit !(t + 0 < m + 0) }'; then
  echo "FEHLER: Testabdeckung ${total}% unterschreitet das Gate von ${min}%" >&2
  exit 1
fi
