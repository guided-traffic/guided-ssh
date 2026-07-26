#!/bin/bash
# Waits for enrollment (the test runs `gssh-agentd enroll` via exec), then
# starts the agent and sshd.
set -e
echo "entrypoint ready"

while [ ! -f /var/lib/guided-ssh/config.yaml ]; do sleep 0.2; done
echo "enrollment detected — starting agentd"

# The test copies the binary to /usr/local/bin; the one-command install's
# install.sh places it in /usr/bin.
AGENTD=/usr/local/bin/gssh-agentd
[ -x "$AGENTD" ] || AGENTD=/usr/bin/gssh-agentd

"$AGENTD" run &

while [ ! -S /var/lib/guided-ssh/agentd.sock ]; do sleep 0.2; done
echo "agentd ready — starting sshd"

exec /usr/sbin/sshd -D -e
