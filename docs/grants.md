# Access Control (Grants)

A **grant** links an IdP group, via a tag selector, to target principals
on the hosts:

> Group × tag selector → target principals (e.g. `deploy`, `root`), sudo
> yes/no, maximum certificate validity

Design rationale: [ADR-018](adr/018-grants-additive.md).

## Evaluated in two places

1. **At certificate issuance** (`POST /v1/sign/user`): users without at
   least one grant (via their groups) receive no certificate (403).
   The requested validity is capped to the maximum across all of the
   user's grants; the server's policy maximum (16 h) also applies.
   The certificate's principals remain identity principals (username,
   email).
2. **On the host** (`AuthorizedPrincipalsCommand`, fail-closed, ADR-017):
   for the local user `%u`, the server returns the identity principals
   of all active members of groups whose grant includes `%u` as a target
   principal and whose tag selector matches the host tags
   (selector ⊆ tags; an empty selector = all hosts).

## Conflict rules: additive, no deny

There are **no deny rules**. Every grant expands access; the effect of
multiple grants is their union:

- Access: allowed as soon as **one** grant matches.
- Validity: the **maximum** of `max_validity` across the user's grants.
- sudo: true as soon as **one** matching grant sets it (enforcement in Phase 9).

Revocation works exclusively through removing grants or group memberships
(IdP sync). Effect: issuance takes effect at the next login, host ACLs
within the cache TTL (default 5 m); already-issued certificates expire
normally.

## Management: gssh-admin

Server-side prerequisite: `GSSH_ADMIN_GROUP` (IdP group of admins;
unconfigured ⇒ admin API disabled). `gssh-admin` uses the same
configuration file as `gssh` (`~/.config/guided-ssh/config.yaml`) and
authenticates via OIDC (browser, `--device`, or a token via
`--token`/`GSSH_ID_TOKEN`, e.g. in CI).

```console
gssh-admin grant list
gssh-admin grant create --group deployers --tags env=prod \
    --principals deploy --max-validity 8h
gssh-admin grant update <id> --principals deploy,root --sudo=true
gssh-admin grant delete <id>
```

Every change produces an audit event (`grant.created/updated/deleted`) with
the admin as actor.

## Declarative management (GitOps)

`gssh-admin apply -f grants.yaml` fully reconciles the current state with
the file — it is the desired state. Grants are identified by (issuer, group,
tag selector): new ones are created, differing ones updated,
**ones no longer declared are deleted**. Unknown groups are created; the
IdP sync links members once the group exists there.

```yaml
# grants.yaml — desired state of all access rules
grants:
  - group: deployers
    tags:            # selector ⊆ host tags; omit = all hosts
      env: prod
    principals: [deploy]
    max_validity: 8h
  - group: admins
    principals: [root]
    sudo: true
    max_validity: 4h
    # issuer: https://idp.example/realms/x   # optional, default: token issuer
```

Recommended workflow: maintain `grants.yaml` in the Git repository, merge
changes via review, run `gssh-admin apply` in the pipeline (token via
`GSSH_ID_TOKEN`).

## Bastion pattern (ProxyJump)

The bastion and target hosts are ordinary enrolled hosts; access is
controlled **separately**, because sshd authorizes independently on each hop:

1. Enroll the bastion with its own tag (e.g. `role=bastion`), target hosts
   with their tags (e.g. `env=prod`).
2. Grant two grants — the bastion grant deliberately grants only an
   unprivileged login:

```yaml
grants:
  - group: deployers
    tags: {role: bastion}
    principals: [jump]      # unprivileged user on the bastion
    max_validity: 8h
  - group: deployers
    tags: {env: prod}
    principals: [deploy]
    max_validity: 8h
```

3. Client side (`~/.ssh/config`); the same certificate authenticates both
   hops, the ssh-agent is not forwarded:

```ssh-config
Host bastion.example.com
  User jump

Host *.prod.example.com
  User deploy
  ProxyJump bastion.example.com
```

Anyone who loses bastion authorization also loses the path to the targets
— regardless of the target grant. A `ForwardAgent` is not needed
(ProxyJump tunnels the TCP connection, the agent stays local).
