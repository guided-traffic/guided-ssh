#!/usr/bin/env bash
# Enforces the minimum overall test coverage across all Go code (coverage gate).
# Usage: hack/coverage.sh [coverage-profile] [minimum-percent]
set -euo pipefail

profile="${1:-coverage.out}"
min="${2:-80}"

if [[ ! -f "$profile" ]]; then
  echo "ERROR: coverage profile '$profile' not found (run 'make cover' or 'go test -coverprofile' first)" >&2
  exit 1
fi

total="$(go tool cover -func="$profile" | awk '/^total:/ { sub(/%/, "", $3); print $3 }')"

echo "Total coverage: ${total}% (minimum: ${min}%)"
if awk -v t="$total" -v m="$min" 'BEGIN { exit !(t + 0 < m + 0) }'; then
  echo "ERROR: test coverage ${total}% is below the ${min}% gate" >&2
  exit 1
fi
