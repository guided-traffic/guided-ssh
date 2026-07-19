#!/bin/sh
# postinstall für gssh-agentd (deb/rpm): State-Verzeichnis + systemd-Reload.
# Der Dienst wird bewusst NICHT automatisch gestartet — erst nach dem
# Enrollment: gssh-agentd enroll --server … --agent-url … --token …
set -e

mkdir -p /var/lib/guided-ssh
chmod 700 /var/lib/guided-ssh

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    echo "gssh-agentd installiert. Nächste Schritte:"
    echo "  1. gssh-agentd enroll --server <url> --agent-url <url> --token <token>"
    echo "  2. systemctl enable --now gssh-agentd"
fi
