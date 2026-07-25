# GitOps mit FluxCD — Referenz-Setup für guided-ssh

Dieses Verzeichnis ist die Vorlage für ein eigenständiges GitOps-Repo, das
guided-ssh mit FluxCD betreibt: Helm-Release aus dem GitHub-Pages-Helm-Repo,
Kustomize-Overlays pro Umgebung, SOPS-verschlüsselte Secrets und deklarative
Zugriffsregeln (`grants.yaml`) mit periodischem Abgleich. Alle Images kommen
aus `docker.io/guidedtraffic`.

## Repo-Struktur

```
.
├── .sops.yaml                      # SOPS-Regel: secrets.yaml → age-verschlüsselt
├── clusters/
│   ├── production/guided-ssh.yaml  # Flux-Kustomization → apps/overlays/production
│   └── staging/guided-ssh.yaml     # Flux-Kustomization → apps/overlays/staging
└── apps/
    ├── base/guided-ssh/
    │   ├── namespace.yaml
    │   ├── helmrepository.yaml     # https://guided-traffic.github.io/guided-ssh
    │   ├── helmrelease.yaml        # Chart guided-ssh, Version gepinnt
    │   ├── sync-config.yaml        # gssh-admin-Konfiguration (api_url, issuer)
    │   └── grants-sync-cronjob.yaml# gssh-admin apply alle 15 min
    └── overlays/
        ├── staging/                # Version-Range, Staging-IdP/-Ingress
        │   ├── grants.yaml         # Zielzustand der Zugriffsregeln
        │   └── secrets.yaml        # SOPS-verschlüsselt committen!
        └── production/             # exakter Pin, Prod-Werte, 2 Replikas
```

`HelmRepository` zeigt auf das GitHub-Pages-Helm-Repo, das der
`chart-release`-Workflow bei jedem Chart-Version-Bump aktualisiert
(siehe `deploy/helm/guided-ssh/README.md`). Die `HelmRelease` referenziert
es; Umgebungsunterschiede sind reine Kustomize-Patches auf `values`.

## Bootstrap

Flux in den Cluster bootstrappen und auf das GitOps-Repo zeigen lassen —
dabei entsteht die `GitRepository` `flux-system`, auf die die
Cluster-Kustomizationen verweisen:

```sh
flux bootstrap github \
  --owner=<org> --repository=<gitops-repo> \
  --branch=main --path=clusters/production
```

Die Datei `clusters/production/guided-ssh.yaml` liegt im Bootstrap-Pfad und
wird damit automatisch angewendet; sie synct `apps/overlays/production` mit
`prune: true` (gelöschte Manifeste verschwinden auch im Cluster) und
`wait: true` (Kustomization wird erst ready, wenn das HelmRelease ready ist).

## Secrets mit SOPS (age)

Einmalig einen age-Key erzeugen und den **privaten** Schlüssel als Secret in
den Cluster legen — nur Flux (kustomize-controller) kann damit entschlüsseln:

```sh
age-keygen -o age.agekey            # public key notieren, private key sichern
kubectl -n flux-system create secret generic sops-age \
  --from-file=age.agekey=age.agekey
```

Den Public-Key in `.sops.yaml` eintragen (der eingetragene Wert ist ein
Beispiel). Danach werden alle `secrets.yaml` vor dem Commit verschlüsselt:

```sh
sops --encrypt --in-place apps/overlays/production/secrets.yaml
```

`encrypted_regex: ^(data|stringData)$` lässt Metadaten lesbar — Diffs bleiben
reviewbar. Die Cluster-Kustomization entschlüsselt beim Apply
(`decryption.provider: sops`, `secretRef: sops-age`). Die hier eingecheckten
`secrets.yaml` sind Platzhalter-Beispiele; im echten Repo niemals Klartext
committen. Das Chart selbst erzeugt keine Secrets, es referenziert nur
existierende Secrets (`secrets.db.existingSecret` mit den einzelnen
Postgres-Verbindungsdaten, `secrets.ca.existingSecret` mit dem CA-Master-Key,
optional `secrets.ca.selfManaged.existingSecret` mit den CA-Keys)
— SOPS und external-secrets sind damit gleichwertig austauschbar.

## Self-managed CA-Keys

Im Default-Modus (`secrets.ca.mode: managed`) erzeugt der Server die
CA-Private-Keys beim ersten Start und legt sie verschlüsselt in der Datenbank
ab — die Datenbank ist damit der Trust-Anchor und lässt sich nicht per Git
verwalten. Mit `self-managed` kommen alle drei CAs (Benutzer-CA, Host-CA,
Agent-mTLS-CA) aus einem gemounteten Secret; die Datenbank hält nur noch die
öffentlichen Metadaten, und **dieses Repo wird die Quelle der Wahrheit für die
CA**. Hintergrund, Fehlerbilder und Startup-Fehlermeldungen:
[docs/self-managed-ca.md](../../docs/self-managed-ca.md).

### Einmalige Erzeugung

```sh
ssh-keygen -t ed25519 -f user-ca -N '' -C 'guided-ssh user ca'
ssh-keygen -t ed25519 -f host-ca -N '' -C 'guided-ssh host ca'
gssh-server gen-mtls-ca -out mtls-ca      # erzeugt mtls-ca.key (0600) + mtls-ca.crt
```

Ins Secret gehören nur die **privaten** Dateien (`user-ca`, `host-ca`,
`mtls-ca.key`) plus das Zertifikat `mtls-ca.crt` — **nicht** die
`.pub`-Dateien; die öffentlichen Schlüssel leitet der Server selbst ab. Die
Keys müssen unverschlüsselt sein (kein Passphrase-Schutz), sonst verweigert
der Server den Start.

Die vier Dateien als `stringData` in
`apps/overlays/<env>/secrets.yaml` eintragen (Vorlage: Secret
`guided-ssh-ca-keys` in `apps/overlays/production/secrets.yaml` — die dort
eingetragenen Keys sind öffentlich bekannte Wegwerf-Beispiele und **müssen**
ersetzt werden) und anschließend verschlüsseln:

```sh
sops --encrypt --in-place apps/overlays/production/secrets.yaml
```

### Aktivieren

Der Modus ist eine Chart-Value, gehört also in den HelmRelease-Patch der
Umgebung (`apps/overlays/<env>/helmrelease-patch.yaml`):

```yaml
  values:
    secrets:
      ca:
        mode: self-managed
        # Master-Key bleibt Pflicht: er leitet den Session-Key der Web-UI ab.
        existingSecret: guided-ssh-ca
        selfManaged:
          existingSecret: guided-ssh-ca-keys
```

Beim Start übernimmt der Server die gemounteten Keys in die Tabelle `ca_keys`
(ohne Private Key, Zustand `active`) — eine leere Datenbank plus dieses Repo
reproduziert damit dieselbe CA.

### Rotation

Rotation ist ein Commit, kein Eingriff am laufenden System:

1. Neues Schlüsselpaar erzeugen (Kommandos oben, in ein leeres Verzeichnis).
2. Den Dateiinhalt im SOPS-verschlüsselten Secret ersetzen (`sops
   apps/overlays/production/secrets.yaml`), committen, mergen — Flux rollt das
   Deployment neu aus.
3. Beim Start übernimmt der Server den neuen Key als `active` und setzt den
   bisherigen auf `retiring`. Dessen **Public Key bleibt im CA-Bundle**
   (`GET /v1/ca/bundle/{user|host}`), Hosts vertrauen also weiter den bereits
   ausgestellten Zertifikaten; die Agenten holen das Bundle stündlich.
4. Sind alle mit dem alten Key signierten Zertifikate abgelaufen
   (Benutzer-Zertifikate ≤ 16 h, Host-Zertifikate 30 Tage), den alten Key
   endgültig zurückziehen — derzeit per SQL, ein Admin-Kommando fehlt noch:

   ```sql
   UPDATE ca_keys SET state = 'retired', retired_at = now()
    WHERE purpose = 'user' AND state = 'retiring';
   ```

Ein bereits auf `retired` gesetzter Key darf nicht erneut gemountet werden —
der Server bricht dann beim Start mit einer entsprechenden Meldung ab.

Das Übergangsfenster gilt nur für die SSH-CAs: Client-Zertifikate der Agenten
prüft der Server ausschließlich gegen die **aktive** mTLS-CA. Ein Wechsel von
`mtls-ca.key`/`mtls-ca.crt` macht alle ausgestellten Agent-Zertifikate
ungültig und erfordert ein Re-Enrollment der Hosts — die drei Dateien also
nicht „mitrotieren", wenn nur die Benutzer-CA getauscht werden soll.

## Grants deklarativ (GitOps)

`apps/overlays/<env>/grants.yaml` ist der versionierte Zielzustand der
Zugriffsregeln (Format: `docs/grants.md`). Der CronJob
`guided-ssh-grants-sync` ruft alle 15 Minuten `gssh-admin apply -f
grants.yaml` gegen die Admin-API auf — Änderungen an Zugriffsregeln laufen
damit als reviewbarer Merge-Request; was in der Datei fehlt, wird gelöscht.
Sofort statt zum nächsten Tick:

```sh
kubectl -n guided-ssh create job --from=cronjob/guided-ssh-grants-sync sync-now
```

### IdP-Service-Account für den Sync

`gssh-admin` authentifiziert sich im CronJob nicht-interaktiv per
Client-Credentials-Flow (`GSSH_CLIENT_ID`/`GSSH_CLIENT_SECRET`). Das
ausgestellte ID-Token muss vom Server wie ein Benutzer-Token verifizierbar
sein: Issuer = `GSSH_OIDC_ISSUER`, Audience enthält `GSSH_OIDC_CLIENT_ID`,
`groups`-Claim enthält die Admin-Gruppe. Einrichtung in Keycloak:

1. Client `gssh-grants-sync` anlegen: confidential („Client authentication“
   an), **Service accounts roles** aktivieren, Standard/Direct-Flows aus.
2. Dedizierte Client-Scope-Mapper des Clients:
   - **Audience**-Mapper: `GSSH_OIDC_CLIENT_ID` (z. B. `gssh-cli`) in die
     Token-Audience aufnehmen („Add to ID token“ an).
   - **Group Membership**-Mapper: Claim `groups` („Full group path“ aus,
     „Add to ID token“ an).
3. Den Service-Account-Benutzer `service-account-gssh-grants-sync` in die
   Admin-Gruppe (`GSSH_ADMIN_GROUP`, z. B. `gssh-admins`) aufnehmen.
4. Client-Secret in `secrets.yaml` (`guided-ssh-sync-oidc/client-secret`)
   eintragen und mit SOPS verschlüsseln.

Der Scope `openid` muss dem Client zugewiesen sein, damit die Token-Antwort
ein `id_token` enthält.

## Upgrade-Pfad

Chart-Releases entstehen im Produkt-Repo (Chart-Version-Bump → Tag
`guided-ssh-x.y.z` → GitHub Pages `index.yaml`). Rollout per Flux:

- **staging** folgt `>=0.1.0 <0.2.0` automatisch: Flux prüft das Helm-Repo
  im `chart.spec.interval` und rollt neue Patch-/Minor-Versionen ohne Commit
  aus — Frühwarnung vor production.
- **production** pinnt exakt. Upgrade = `version:` in
  `apps/overlays/production/helmrelease-patch.yaml` bumpen, Merge-Request,
  merge; Flux führt das `helm upgrade` aus.

DB-Migrationen laufen bei jedem Rollout automatisch: Init-Container
`migrate` (goose) vor dem Server, ein Postgres-Advisory-Lock serialisiert
parallele Replikas. Schlägt das Upgrade fehl, greift
`upgrade.remediation.retries` (Helm-Rollback durch Flux); Migrationen sind
vorwärts-only und müssen deshalb abwärtskompatibel zur Vorversion sein.

Der komplette Pfad (Bump → Flux-Reconcile → Migration → Ready) ist
automatisiert testbar: `hack/flux-upgrade-test.sh` baut einen kind-Cluster
mit Flux, installiert Chart-Version A aus einem lokalen Helm-Repo, bumpt auf
Version B und verifiziert Rollout und Migrationslauf.

## Betriebsnotizen

- Das Image des Sync-CronJobs (`docker.io/guidedtraffic/guided-ssh:<tag>`)
  zur ausgerollten `appVersion` passend halten — `gssh-admin` liegt im
  Server-Image (distroless, Command wird überschrieben).
- `grants.yaml` wird ohne Hash-Suffix als ConfigMap generiert: Job-Pods
  starten frisch und lesen immer den aktuellen Stand; ein Rolling-Update
  wie bei Deployments ist nicht nötig.
- Agent-mTLS braucht TLS-Passthrough: die Agent-API läuft über den
  separaten Service (production: `type: LoadBalancer`), nicht über den
  HTTP-Ingress.
