# ADR-004: Ansible only as reference playbooks

- Status: accepted
- Date: 2026-07-19

## Context

A core requirement is that GitLab pipelines can provision hosts via Ansible —
without static SSH keys. Handling host enrollment itself through Ansible was
also conceivable.

## Decision

Ansible is documented exclusively as a reference for CI provisioning (example
playbook + inventory pattern, Phase 7). Host enrollment and installation go
through packages (deb/rpm) and the host agent's install script — not through
Ansible.

## Consequences

- No Ansible knowledge is needed to connect hosts; one path instead of two.
- Ansible automatically uses the CI job's `ssh-agent` — no special integration needed.
- Operators with their own Ansible landscape can trivially wrap the package
  install into their own roles; that remains their tooling choice, though.
