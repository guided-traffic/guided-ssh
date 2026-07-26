#!/bin/sh
# postinstall for gssh-agentd (deb/rpm): state directory + systemd reload.
# The service is deliberately NOT started automatically — only after
# enrollment: gssh-agentd enroll --server … --agent-url … --token …
set -e

mkdir -p /var/lib/guided-ssh
chmod 700 /var/lib/guided-ssh

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    echo "gssh-agentd installed. Next steps:"
    echo "  1. gssh-agentd enroll --server <url> --agent-url <url> --token <token>"
    echo "  2. systemctl enable --now gssh-agentd"
fi
