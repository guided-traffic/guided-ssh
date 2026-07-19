#!/bin/bash
# Wartet auf das Enrollment (der Test führt `gssh-agentd enroll` per Exec aus),
# startet dann den Agenten und sshd.
set -e
echo "entrypoint ready"

while [ ! -f /var/lib/guided-ssh/config.yaml ]; do sleep 0.2; done
echo "enrollment erkannt — starte agentd"

/usr/local/bin/gssh-agentd run &

while [ ! -S /var/lib/guided-ssh/agentd.sock ]; do sleep 0.2; done
echo "agentd bereit — starte sshd"

exec /usr/sbin/sshd -D -e
