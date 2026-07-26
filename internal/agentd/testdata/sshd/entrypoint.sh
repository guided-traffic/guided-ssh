#!/bin/bash
# Wartet auf das Enrollment (der Test führt `gssh-agentd enroll` per Exec aus),
# startet dann den Agenten und sshd.
set -e
echo "entrypoint ready"

while [ ! -f /var/lib/guided-ssh/config.yaml ]; do sleep 0.2; done
echo "enrollment erkannt — starte agentd"

# Der Test kopiert das Binary nach /usr/local/bin; das install.sh des
# One-Command-Installs legt es nach /usr/bin.
AGENTD=/usr/local/bin/gssh-agentd
[ -x "$AGENTD" ] || AGENTD=/usr/bin/gssh-agentd

"$AGENTD" run &

while [ ! -S /var/lib/guided-ssh/agentd.sock ]; do sleep 0.2; done
echo "agentd bereit — starte sshd"

exec /usr/sbin/sshd -D -e
