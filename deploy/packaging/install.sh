#!/bin/sh
# Install script for hosts without deb/rpm: downloads the matching gssh-agentd
# binary from a GitHub release and installs the systemd unit.
#
#   curl -fsSL https://raw.githubusercontent.com/guided-traffic/guided-ssh/main/deploy/packaging/install.sh \
#     | sh -s -- v0.3.0
#
# After that: gssh-agentd enroll --server … --agent-url … --token …
set -eu

VERSION="${1:?usage: install.sh <version, e.g. v0.3.0>}"
REPO="guided-traffic/guided-ssh"

case "$(uname -m)" in
    x86_64)  ARCH=amd64 ;;
    aarch64) ARCH=arm64 ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

URL="https://github.com/${REPO}/releases/download/${VERSION}/gssh-agentd-linux-${ARCH}"
echo "downloading ${URL}"
curl -fsSL -o /usr/bin/gssh-agentd "${URL}"
chmod 755 /usr/bin/gssh-agentd

UNIT_URL="https://raw.githubusercontent.com/${REPO}/${VERSION}/internal/agentdist/gssh-agentd.service"
curl -fsSL -o /lib/systemd/system/gssh-agentd.service "${UNIT_URL}"

mkdir -p /var/lib/guided-ssh
chmod 700 /var/lib/guided-ssh
command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload

echo "installed: $(gssh-agentd version)"
echo "next steps:"
echo "  1. gssh-agentd enroll --server <url> --agent-url <url> --token <token>"
echo "  2. systemctl enable --now gssh-agentd"
