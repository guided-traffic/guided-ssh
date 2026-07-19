#!/bin/bash
# Wartet auf das Enrollment (die E2E-Suite führt `gssh-agentd enroll` per
# kubectl exec aus, passt die Agent-Konfiguration an und setzt .e2e-ready),
# startet dann den Agenten und sshd. Host-Keys pro Pod frisch erzeugen,
# damit beide Testhosts unterschiedliche Schlüssel haben.
set -e
ssh-keygen -A
echo "entrypoint ready"

while [ ! -f /var/lib/guided-ssh/.e2e-ready ]; do sleep 0.2; done
echo "enrollment erkannt — starte agentd"

/usr/local/bin/gssh-agentd run &

while [ ! -S /var/lib/guided-ssh/agentd.sock ]; do sleep 0.2; done
echo "agentd bereit — starte sshd"

exec /usr/sbin/sshd -D -e
