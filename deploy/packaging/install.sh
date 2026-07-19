#!/bin/sh
# Install-Skript für Hosts ohne deb/rpm: lädt das passende gssh-agentd-Binary
# aus einem GitHub-Release und installiert die systemd-Unit.
#
#   curl -fsSL https://raw.githubusercontent.com/guided-traffic/guided-ssh/main/deploy/packaging/install.sh \
#     | sh -s -- v0.3.0
#
# Danach: gssh-agentd enroll --server … --agent-url … --token …
set -eu

VERSION="${1:?aufruf: install.sh <version, z. B. v0.3.0>}"
REPO="guided-traffic/guided-ssh"

case "$(uname -m)" in
    x86_64)  ARCH=amd64 ;;
    aarch64) ARCH=arm64 ;;
    *) echo "nicht unterstützte architektur: $(uname -m)" >&2; exit 1 ;;
esac

URL="https://github.com/${REPO}/releases/download/${VERSION}/gssh-agentd-linux-${ARCH}"
echo "lade ${URL}"
curl -fsSL -o /usr/bin/gssh-agentd "${URL}"
chmod 755 /usr/bin/gssh-agentd

UNIT_URL="https://raw.githubusercontent.com/${REPO}/${VERSION}/deploy/packaging/gssh-agentd.service"
curl -fsSL -o /lib/systemd/system/gssh-agentd.service "${UNIT_URL}"

mkdir -p /var/lib/guided-ssh
chmod 700 /var/lib/guided-ssh
command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload

echo "installiert: $(gssh-agentd version)"
echo "nächste schritte:"
echo "  1. gssh-agentd enroll --server <url> --agent-url <url> --token <token>"
echo "  2. systemctl enable --now gssh-agentd"
