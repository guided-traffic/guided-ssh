#!/bin/bash
# Waits for enrollment (the E2E suite runs `gssh-agentd enroll` via
# kubectl exec, adjusts the agent configuration, and sets .e2e-ready),
# then starts the agent and sshd. Generate fresh host keys per pod so
# both test hosts have different keys.
set -e
ssh-keygen -A
echo "entrypoint ready"

while [ ! -f /var/lib/guided-ssh/.e2e-ready ]; do sleep 0.2; done
echo "enrollment detected — starting agentd"

/usr/local/bin/gssh-agentd run &

while [ ! -S /var/lib/guided-ssh/agentd.sock ]; do sleep 0.2; done
echo "agentd ready — starting sshd"

exec /usr/sbin/sshd -D -e
