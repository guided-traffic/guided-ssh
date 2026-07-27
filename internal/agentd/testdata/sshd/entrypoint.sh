#!/bin/bash
# sshd starts *before* enrollment — that is the real-world case and the one
# that used to fail silently: a listener has parsed its configuration once, at
# startup, and never sees the guided-ssh snippet unless enrollment reloads it.
# The agent follows as soon as enrollment has written its state.
set -e

/usr/sbin/sshd -D -e &
# Only report readiness once the listener exists: enrollment derives its
# reload command from the pid file.
while [ ! -f /run/sshd.pid ]; do sleep 0.1; done
echo "entrypoint ready"

while [ ! -f /var/lib/guided-ssh/config.yaml ]; do sleep 0.2; done
echo "enrollment detected — starting agentd"

# The test copies the binary to /usr/local/bin; the one-command install's
# install.sh places it in /usr/bin.
AGENTD=/usr/local/bin/gssh-agentd
[ -x "$AGENTD" ] || AGENTD=/usr/bin/gssh-agentd

exec "$AGENTD" run
