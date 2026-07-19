# Zugriffssteuerung (Grants)

Ein **Grant** verknüpft eine IdP-Gruppe über einen Tag-Selektor mit
Ziel-Principals auf den Hosts:

> Gruppe × Tag-Selektor → Ziel-Principals (z. B. `deploy`, `root`), sudo
> ja/nein, maximale Zertifikatslaufzeit

Entscheidungsgrundlage: [ADR-018](adr/018-grants-additiv.md).

## Auswertung an zwei Stellen

1. **Bei der Zertifikatsausstellung** (`POST /v1/sign/user`): Benutzer ohne
   mindestens einen Grant (über ihre Gruppen) bekommen kein Zertifikat (403).
   Die gewünschte Laufzeit wird auf das Maximum über alle Grants des
   Benutzers gekappt; zusätzlich gilt das Policy-Maximum des Servers (16 h).
   Die Zertifikats-Principals bleiben Identitäts-Principals (Username,
   E-Mail).
2. **Auf dem Host** (`AuthorizedPrincipalsCommand`, fail-closed, ADR-017):
   Für den lokalen Benutzer `%u` liefert der Server die Identitäts-Principals
   aller aktiven Mitglieder von Gruppen, deren Grant `%u` als Ziel-Principal
   enthält und deren Tag-Selektor auf die Host-Tags passt
   (Selektor ⊆ Tags; leerer Selektor = alle Hosts).

## Konfliktregeln: additiv, kein deny

Es gibt **keine deny-Regeln**. Jeder Grant erweitert Zugriff; die Wirkung
mehrerer Grants ist die Vereinigung:

- Zugriff: erlaubt, sobald **ein** Grant passt.
- Laufzeit: **Maximum** der `max_validity` über die Grants des Benutzers.
- sudo: wahr, sobald **ein** passender Grant es setzt (Durchsetzung Phase 9).

Entzug funktioniert ausschließlich über das Entfernen von Grants oder
Gruppenmitgliedschaften (IdP-Sync). Wirkung: Ausstellung beim nächsten Login,
Host-ACLs innerhalb der Cache-TTL (Default 5 m); bereits ausgestellte
Zertifikate laufen regulär ab.

## Verwaltung: gssh-admin

Voraussetzung auf dem Server: `GSSH_ADMIN_GROUP` (IdP-Gruppe der Admins;
unkonfiguriert ⇒ Admin-API deaktiviert). `gssh-admin` nutzt dieselbe
Konfigurationsdatei wie `gssh` (`~/.config/guided-ssh/config.yaml`) und
authentifiziert per OIDC (Browser, `--device`, oder Token via
`--token`/`GSSH_ID_TOKEN`, z. B. in CI).

```console
gssh-admin grant list
gssh-admin grant create --group deployers --tags env=prod \
    --principals deploy --max-validity 8h
gssh-admin grant update <id> --principals deploy,root --sudo=true
gssh-admin grant delete <id>
```

Jede Änderung erzeugt ein Audit-Event (`grant.created/updated/deleted`) mit
dem Admin als Actor.

## Deklarative Pflege (GitOps)

`gssh-admin apply -f grants.yaml` gleicht den Bestand vollständig mit der
Datei ab — sie ist der Zielzustand. Grants werden über (Issuer, Gruppe,
Tag-Selektor) identifiziert: neue werden angelegt, abweichende aktualisiert,
**nicht mehr deklarierte gelöscht**. Unbekannte Gruppen werden angelegt; der
IdP-Sync verknüpft Mitglieder, sobald die Gruppe dort existiert.

```yaml
# grants.yaml — Zielzustand aller Zugriffsregeln
grants:
  - group: deployers
    tags:            # Selektor ⊆ Host-Tags; weglassen = alle Hosts
      env: prod
    principals: [deploy]
    max_validity: 8h
  - group: admins
    principals: [root]
    sudo: true
    max_validity: 4h
    # issuer: https://idp.example/realms/x   # optional, Default: Token-Issuer
```

Empfohlener Workflow: `grants.yaml` im Git-Repository pflegen, Änderungen per
Review mergen, `gssh-admin apply` in der Pipeline (Token via `GSSH_ID_TOKEN`).

## Bastion-Muster (ProxyJump)

Bastion und Ziel-Hosts sind gewöhnliche enrollte Hosts; der Zugriff wird
**getrennt** gesteuert, weil sshd auf jedem Hop eigenständig autorisiert:

1. Bastion mit eigenem Tag enrollen (z. B. `role=bastion`), Ziel-Hosts mit
   ihren Tags (z. B. `env=prod`).
2. Zwei Grants vergeben — der Bastion-Grant gewährt bewusst nur einen
   unprivilegierten Login:

```yaml
grants:
  - group: deployers
    tags: {role: bastion}
    principals: [jump]      # unprivilegierter Benutzer auf der Bastion
    max_validity: 8h
  - group: deployers
    tags: {env: prod}
    principals: [deploy]
    max_validity: 8h
```

3. Client-Seite (`~/.ssh/config`); dasselbe Zertifikat authentifiziert beide
   Hops, der ssh-agent wird nicht weitergereicht:

```ssh-config
Host bastion.example.com
  User jump

Host *.prod.example.com
  User deploy
  ProxyJump bastion.example.com
```

Wer die Bastion-Berechtigung verliert, verliert damit auch den Weg zu den
Zielen — unabhängig vom Ziel-Grant. Ein `ForwardAgent` ist nicht nötig
(ProxyJump tunnelt die TCP-Verbindung, der Agent bleibt lokal).
