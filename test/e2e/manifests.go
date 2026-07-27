//go:build e2e

package e2e

// Kubernetes manifests and configurations of the E2E environment as
// templates; placeholders {{NS}}, {{ALICE_OTHERGROUPS}} … are replaced via
// render().

// postgresYAML is the throwaway database (analogous to hack/flux-upgrade-test.sh).
const postgresYAML = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
spec:
  replicas: 1
  selector:
    matchLabels: {app: postgres}
  template:
    metadata:
      labels: {app: postgres}
    spec:
      containers:
        - name: postgres
          image: postgres:17-alpine
          env:
            - {name: POSTGRES_USER, value: gssh}
            - {name: POSTGRES_PASSWORD, value: gssh-e2e-pw}
            - {name: POSTGRES_DB, value: gssh}
          ports: [{containerPort: 5432}]
          readinessProbe:
            exec: {command: [pg_isready, -U, gssh]}
            periodSeconds: 2
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
spec:
  selector: {app: postgres}
  ports: [{port: 5432}]
`

// glauthConfig is the mini LDAP with static users and groups. Dex cannot
// deliver groups with staticPasswords — GLAuth provides them via the LDAP
// connector. Offboarding = remove alice from "dev" (5502) (rewrite
// ALICE_OTHERGROUPS) + GLAuth restart.
const glauthConfig = `
[ldap]
  enabled = true
  listen = "0.0.0.0:3893"

[ldaps]
  enabled = false

[backend]
  datastore = "config"
  baseDN = "dc=glauth,dc=com"

[[users]]
  name = "alice"
  uidnumber = 5001
  primarygroup = 5500
  othergroups = [{{ALICE_OTHERGROUPS}}]
  mail = "alice@example.com"
  passsha256 = "17a96502d336e4c18a43182a353d7f0a38414c6fc4daf678acae834a819cecee" # alice-password

[[users]]
  name = "dexsearch"
  uidnumber = 5002
  primarygroup = 5503
  passsha256 = "27dfcce560bd77eae4cd19c8b20a31aae5192860f3e2cc14f9ac60e26ae6d849" # dexsearch-pw
    [[users.capabilities]]
    action = "search"
    object = "*"

[[groups]]
  name = "users"
  gidnumber = 5500

[[groups]]
  name = "admins"
  gidnumber = 5501

[[groups]]
  name = "dev"
  gidnumber = 5502

[[groups]]
  name = "svcaccts"
  gidnumber = 5503
`

// glauthYAML deploys GLAuth with the configuration from the ConfigMap.
const glauthYAML = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: glauth
spec:
  replicas: 1
  selector:
    matchLabels: {app: glauth}
  template:
    metadata:
      labels: {app: glauth}
    spec:
      containers:
        # No args override: the image entrypoint (dumb-init + start script)
        # reads /app/config/config.cfg — exactly where the ConfigMap is mounted.
        - name: glauth
          image: glauth/glauth:v2.3.2
          ports: [{containerPort: 3893}]
          readinessProbe:
            tcpSocket: {port: 3893}
            periodSeconds: 2
          volumeMounts:
            - {name: config, mountPath: /app/config}
      volumes:
        - name: config
          configMap: {name: glauth-config}
---
apiVersion: v1
kind: Service
metadata:
  name: glauth
spec:
  selector: {app: glauth}
  ports: [{port: 3893}]
`

// dexConfig: Dex with a static public client (gssh-cli) and LDAP connector
// against GLAuth; passwordConnector allows the resource owner password
// grant (admin token of the suite), skipApprovalScreen streamlines the
// device flow.
const dexConfig = `
issuer: http://dex.{{NS}}.svc.cluster.local:5556/dex
storage:
  type: memory
web:
  http: 0.0.0.0:5556
oauth2:
  skipApprovalScreen: true
  passwordConnector: ldap
expiry:
  deviceRequests: 10m
  idTokens: 24h
staticClients:
  - id: gssh-cli
    name: gssh CLI
    public: true
connectors:
  - type: ldap
    id: ldap
    name: LDAP
    config:
      host: glauth.{{NS}}.svc.cluster.local:3893
      insecureNoSSL: true
      bindDN: cn=dexsearch,ou=svcaccts,dc=glauth,dc=com
      bindPW: dexsearch-pw
      userSearch:
        baseDN: dc=glauth,dc=com
        filter: "(objectClass=posixAccount)"
        username: uid
        idAttr: uid
        emailAttr: mail
        nameAttr: cn
      groupSearch:
        baseDN: dc=glauth,dc=com
        filter: "(objectClass=posixGroup)"
        userMatchers:
          - userAttr: uid
            groupAttr: memberUid
        nameAttr: cn
`

const dexYAML = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dex
spec:
  replicas: 1
  selector:
    matchLabels: {app: dex}
  template:
    metadata:
      labels: {app: dex}
    spec:
      containers:
        - name: dex
          image: ghcr.io/dexidp/dex:v2.41.1
          args: ["dex", "serve", "/etc/dex/cfg/config.yaml"]
          ports: [{containerPort: 5556}]
          readinessProbe:
            httpGet: {path: /dex/healthz, port: 5556}
            periodSeconds: 2
          volumeMounts:
            - {name: config, mountPath: /etc/dex/cfg}
      volumes:
        - name: config
          configMap: {name: dex-config}
---
apiVersion: v1
kind: Service
metadata:
  name: dex
spec:
  selector: {app: dex}
  ports: [{port: 5556}]
`

// gitlabFakeNginx serves discovery + JWKS of the simulated GitLab OIDC
// (static JSON is enough — the suite signs job tokens itself).
const gitlabFakeNginx = `
server {
  listen 80;
  default_type application/json;
  location = /.well-known/openid-configuration { alias /data/discovery.json; }
  location = /oauth/discovery/keys { alias /data/jwks.json; }
}
`

const gitlabFakeYAML = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gitlab-fake
spec:
  replicas: 1
  selector:
    matchLabels: {app: gitlab-fake}
  template:
    metadata:
      labels: {app: gitlab-fake}
    spec:
      containers:
        - name: nginx
          image: nginx:1.27-alpine
          ports: [{containerPort: 80}]
          readinessProbe:
            httpGet: {path: /.well-known/openid-configuration, port: 80}
            periodSeconds: 2
          volumeMounts:
            - {name: config, mountPath: /etc/nginx/conf.d/default.conf, subPath: default.conf}
            - {name: config, mountPath: /data}
      volumes:
        - name: config
          configMap: {name: gitlab-fake}
---
apiVersion: v1
kind: Service
metadata:
  name: gitlab-fake
spec:
  selector: {app: gitlab-fake}
  ports: [{port: 80}]
`

// testhostYAML is an sshd test host ({{NAME}}: testhost-web/testhost-db);
// enrollment happens via kubectl exec, then the entrypoint starts agentd +
// sshd.
const testhostYAML = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{NAME}}
spec:
  replicas: 1
  selector:
    matchLabels: {app: {{NAME}}}
  template:
    metadata:
      labels: {app: {{NAME}}}
    spec:
      containers:
        - name: sshd
          image: gssh-e2e-testhost:e2e
          imagePullPolicy: Never
          ports: [{containerPort: 22}]
---
apiVersion: v1
kind: Service
metadata:
  name: {{NAME}}
spec:
  selector: {app: {{NAME}}}
  ports: [{port: 22}]
`

// workstationYAML is the "human": alpine + openssh-client + gssh binary,
// ssh-agent under /tmp/agent.sock, gssh configuration from the ConfigMap.
const workstationYAML = `
apiVersion: v1
kind: Pod
metadata:
  name: workstation
spec:
  containers:
    - name: workstation
      image: gssh-e2e-workstation:e2e
      imagePullPolicy: Never
      volumeMounts:
        - {name: gssh-config, mountPath: /etc/gssh}
  volumes:
    - name: gssh-config
      configMap: {name: gssh-config}
`

// gsshConfig is the workstation's CLI configuration.
const gsshConfig = `
api_url: http://guided-ssh.{{NS}}.svc.cluster.local
issuer: http://dex.{{NS}}.svc.cluster.local:5556/dex
client_id: gssh-cli
scopes: [openid, profile, email, groups]
`

// helmValues configures the production chart for the E2E environment.
// GSSH_HOST_CERT_VALIDITY=3m makes host rotation (2/3 of the lifetime)
// observable in minutes; a generous rate limit, because all of the suite's
// requests come from a single client IP through the port-forward.
const helmValues = `
image:
  repository: gssh-e2e-server
  tag: e2e
  pullPolicy: Never
secrets:
  db:
    existingSecret: guided-ssh-e2e
  ca:
    existingSecret: guided-ssh-e2e
config:
  oidc:
    issuer: http://dex.{{NS}}.svc.cluster.local:5556/dex
    client:
      clientID: gssh-cli
  ci:
    issuer: http://gitlab-fake.{{NS}}.svc.cluster.local
    audience: guided-ssh
  groups:
    admin: admins
  rateLimit:
    perMinute: "600"
    failPerMinute: "120"
    trustProxy: false
  extraEnv:
    - name: GSSH_HOST_CERT_VALIDITY
      value: 3m
`

// helmValuesInternal configures the chart with an internal test database
// (Postgres sidecar, internalDatabase.enabled): no DB secret, only the CA
// secret — the minimal path for "trying it out without your own Postgres
// instance".
const helmValuesInternal = `
image:
  repository: gssh-e2e-server
  tag: e2e
  pullPolicy: Never
internalDatabase:
  enabled: true
secrets:
  ca:
    existingSecret: {{RELEASE}}-ca
config:
  rateLimit:
    trustProxy: false
`

// grantsBase: initial state — group dev may act as deploy on role=web
// hosts, CI project platform/deploy (protected refs only) as well.
const grantsBase = `
grants:
  - group: dev
    tags:
      role: web
    principals: [deploy]
    max_validity: 8h
ci_grants:
  - project: platform/deploy
    protected_only: true
    tags:
      role: web
    principals: [deploy]
    max_validity: 1h
`

// grantsWithDB extends grantsBase with access to role=db (grant change).
const grantsWithDB = `
grants:
  - group: dev
    tags:
      role: web
    principals: [deploy]
    max_validity: 8h
  - group: dev
    tags:
      role: db
    principals: [deploy]
    max_validity: 8h
ci_grants:
  - project: platform/deploy
    protected_only: true
    tags:
      role: web
    principals: [deploy]
    max_validity: 1h
`
