#!/bin/sh
set -e
ssh-agent -a /tmp/agent.sock >/dev/null
echo "workstation ready"
exec sleep infinity
