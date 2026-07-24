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
Postgres-Verbindungsdaten, `secrets.ca.existingSecret` mit dem CA-Master-Key)
— SOPS und external-secrets sind damit gleichwertig austauschbar.

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
