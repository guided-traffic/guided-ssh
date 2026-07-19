# ADR-004: Ansible nur als Referenz-Playbooks

- Status: akzeptiert
- Datum: 2026-07-19

## Kontext

Kernanforderung ist, dass GitLab-Pipelines Hosts via Ansible provisionieren können —
ohne statische SSH-Keys. Denkbar wäre auch, Host-Enrollment selbst über Ansible
abzuwickeln.

## Entscheidung

Ansible wird ausschließlich als Referenz für das CI-Provisioning dokumentiert
(Beispiel-Playbook + Inventory-Muster, Phase 7). Host-Enrollment und -Installation
laufen über Pakete (deb/rpm) und Install-Skript des Host-Agents — nicht über Ansible.

## Konsequenzen

- Kein Ansible-Wissen nötig, um Hosts anzubinden; ein Weg statt zwei.
- Ansible nutzt den `ssh-agent` des CI-Jobs automatisch — keine Sonderintegration.
- Betreiber mit eigener Ansible-Landschaft können den Paket-Install trivial in
  eigene Rollen wickeln; das bleibt aber deren Werkzeugwahl.
