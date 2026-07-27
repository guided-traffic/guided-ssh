import {
  AgentManifest,
  AuditEvent,
  AuthSession,
  CiGrant,
  ClientManifest,
  Grant,
  Group,
  Host,
  ServiceAccount,
  UiConfig,
  User,
} from "../../api/models";

/**
 * Fixture data for the backend-less mock mode (design review at runtime).
 * Every list deliberately contains one example per UI variant: each pill
 * color, empty and populated optional fields, active and inactive rows.
 * Timestamps are relative to "now" so the variants stay stable — a host
 * whose certificate "expires in 3 days" still does so next month.
 */

const MINUTE = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;

function ago(ms: number): string {
  return new Date(Date.now() - ms).toISOString();
}

function ahead(ms: number): string {
  return new Date(Date.now() + ms).toISOString();
}

export const mockSession: AuthSession = {
  authenticated: true,
  username: "design-reviewer",
  roles: ["admin", "auditor"],
};

export const mockUiConfig: UiConfig = {
  oidc_issuer: "https://idp.example.com/realms/acme",
  oidc_client_id: "gssh-cli",
  admin_group: "ssh-admins",
  auditor_group: "ssh-auditors",
};

/**
 * Hosts: every combination of last-seen pill (ok < 24h, warn ≥ 24h, muted =
 * never) and certificate pill (ok, warn < 7 days, danger = expired, muted =
 * none), plus tag variants (none, few, many). web-01 carries a
 * last_seen_addr (connect dialog's IP suggestion); the others do not.
 */
export const mockHosts: Host[] = [
  {
    id: "0b7f5f2e-9f2a-4c9e-8a3d-1f2e3d4c5b6a",
    name: "web-01.prod.example.com",
    tags: { env: "prod", role: "web" },
    created_at: ago(90 * DAY),
    enrolled_at: ago(90 * DAY),
    last_seen_at: ago(4 * MINUTE),
    last_seen_addr: "10.20.30.40",
    cert_valid_before: ahead(21 * DAY),
  },
  {
    id: "1c8e6d3f-0a3b-4d8f-9b4e-2a3b4c5d6e7f",
    name: "db-01.prod.example.com",
    tags: {
      env: "prod",
      role: "db",
      dc: "fra1",
      team: "platform",
      tier: "critical",
    },
    created_at: ago(200 * DAY),
    enrolled_at: ago(200 * DAY),
    last_seen_at: ago(3 * DAY),
    cert_valid_before: ahead(3 * DAY),
  },
  {
    id: "2d9f7e4a-1b4c-4e9a-8c5f-3b4c5d6e7f8a",
    name: "legacy-worker-07",
    tags: { env: "staging" },
    created_at: ago(400 * DAY),
    enrolled_at: ago(400 * DAY),
    last_seen_at: ago(45 * DAY),
    cert_valid_before: ago(11 * DAY),
  },
  {
    id: "3e0a8f5b-2c5d-4f0b-9d6a-4c5d6e7f8a9b",
    name: "edge-eu-02",
    tags: {},
    created_at: ago(2 * HOUR),
    enrolled_at: null,
    last_seen_at: null,
    cert_valid_before: null,
  },
  {
    id: "4f1b9a6c-3d6e-4a1c-8e7b-5d6e7f8a9b0c",
    name: "ci-runner-large-01",
    tags: { env: "ci", role: "runner", arch: "arm64" },
    created_at: ago(14 * DAY),
    enrolled_at: ago(14 * DAY),
    last_seen_at: ago(19 * HOUR),
    cert_valid_before: ahead(29 * DAY),
  },
];

/** Rollout ready, so the "Add Host" dialog is reachable in the mock too. */
export const mockAgentManifest: AgentManifest = {
  rollout_ready: true,
  version: "v2.3.0",
  pin_source: "static",
  pin_error: "",
  missing: [],
  agents: [
    {
      os: "linux",
      arch: "amd64",
      sha256: "a3f5…" + "e".repeat(58),
      size: 23_400_192,
    },
    {
      os: "linux",
      arch: "arm64",
      sha256: "b4a6…" + "f".repeat(58),
      size: 21_876_544,
    },
  ],
};

/**
 * Client install ready — the Client setup page and the connect dialog render
 * fully. The pin fields mirror a server with an operator-controlled pin; the
 * UI itself does not consume them (the pin is the `client.sh --pin` opt-in).
 */
export const mockClientManifest: ClientManifest = {
  ready: true,
  version: "v2.3.0",
  pin_source: "static",
  pin: "9nPmyRTjBQvKfBpB9OiE9YEfR9dPbGVoBSSlYqAr4X0=",
  missing: [],
  clients: [
    { os: "darwin", arch: "arm64", sha256: "c5b7…" + "a".repeat(58), size: 8_178_432 },
    { os: "linux", arch: "amd64", sha256: "d6c8…" + "b".repeat(58), size: 8_599_040 },
    { os: "linux", arch: "arm64", sha256: "e7d9…" + "c".repeat(58), size: 7_968_256 },
  ],
};

/**
 * Grants: sudo on/off, broad and narrow tag selectors, single and multiple
 * principals, short and long validity.
 */
export const mockGrants: Grant[] = [
  {
    id: "5a2c0b7d-4e7f-4b2d-9f8c-6e7f8a9b0c1d",
    group: "platform-team",
    issuer: "https://idp.example.com/realms/acme",
    principals: ["deploy", "root"],
    sudo: true,
    max_validity_seconds: 8 * 3600,
    tag_selector: { env: "prod" },
    created_at: ago(120 * DAY),
    updated_at: ago(5 * DAY),
  },
  {
    id: "6b3d1c8e-5f8a-4c3e-8a9d-7f8a9b0c1d2e",
    group: "developers",
    issuer: "https://idp.example.com/realms/acme",
    principals: ["app"],
    sudo: false,
    max_validity_seconds: 3600,
    tag_selector: { env: "staging", role: "web" },
    created_at: ago(60 * DAY),
    updated_at: ago(60 * DAY),
  },
  {
    id: "7c4e2d9f-6a9b-4d4f-9b0e-8a9b0c1d2e3f",
    group: "on-call",
    issuer: "https://idp.example.com/realms/acme",
    principals: ["root"],
    sudo: true,
    max_validity_seconds: 30 * 60,
    tag_selector: {},
    created_at: ago(30 * DAY),
    updated_at: ago(2 * HOUR),
  },
];

/**
 * CI grants: with and without ref/environment patterns, protected-only
 * on/off, project vs. namespace path.
 */
export const mockCiGrants: CiGrant[] = [
  {
    id: "8d5f3e0a-7b0c-4e5a-8c1f-9b0c1d2e3f4a",
    project: "acme/webshop",
    principals: ["deploy"],
    ref_pattern: "refs/tags/v*",
    environment_pattern: "production",
    protected_only: true,
    max_validity_seconds: 15 * 60,
    tag_selector: { env: "prod", role: "web" },
    created_at: ago(45 * DAY),
    updated_at: ago(45 * DAY),
  },
  {
    id: "9e6a4f1b-8c1d-4f6b-9d2a-0c1d2e3f4a5b",
    project: "acme/infrastructure",
    principals: ["ansible", "deploy"],
    protected_only: false,
    max_validity_seconds: 3600,
    tag_selector: {},
    created_at: ago(10 * DAY),
    updated_at: ago(1 * DAY),
  },
];

/** Service accounts: active and deactivated (kill switch) example. */
export const mockServiceAccounts: ServiceAccount[] = [
  {
    id: "a0b1c2d3-9d2e-4a7c-8e3b-1d2e3f4a5b6c",
    name: "acme/webshop",
    kind: "gitlab-ci",
    issuer: "https://gitlab.example.com",
    active: true,
    claim_matcher: { project_path: "acme/webshop" },
    created_at: ago(45 * DAY),
    updated_at: ago(45 * DAY),
  },
  {
    id: "b1c2d3e4-0e3f-4b8d-9f4c-2e3f4a5b6c7d",
    name: "acme/legacy-deploy",
    kind: "gitlab-ci",
    issuer: "https://gitlab.example.com",
    active: false,
    claim_matcher: { project_path: "acme/legacy-deploy" },
    created_at: ago(300 * DAY),
    updated_at: ago(7 * DAY),
  },
];

/** Users: active/inactive, many/few/no groups, long names. */
export const mockUsers: User[] = [
  {
    id: "c2d3e4f5-1f4a-4c9e-8a5d-3f4a5b6c7d8e",
    username: "ada",
    email: "ada.lovelace@example.com",
    issuer: "https://idp.example.com/realms/acme",
    subject: "idp-user-1001",
    active: true,
    groups: ["ssh-admins", "platform-team", "on-call"],
    created_at: ago(300 * DAY),
    updated_at: ago(1 * DAY),
  },
  {
    id: "d3e4f5a6-2a5b-4d0f-9b6e-4a5b6c7d8e9f",
    username: "grace",
    email: "grace.hopper@example.com",
    issuer: "https://idp.example.com/realms/acme",
    subject: "idp-user-1002",
    active: true,
    groups: ["developers"],
    created_at: ago(150 * DAY),
    updated_at: ago(150 * DAY),
  },
  {
    id: "e4f5a6b7-3b6c-4e1a-8c7f-5b6c7d8e9f0a",
    username: "former-contractor-with-very-long-name",
    email: "former.contractor@subsidiary.example.co.uk",
    issuer: "https://idp.example.com/realms/acme",
    subject: "idp-user-2077",
    active: false,
    groups: [],
    created_at: ago(500 * DAY),
    updated_at: ago(90 * DAY),
  },
];

export const mockGroups: Group[] = [
  {
    id: "f5a6b7c8-4c7d-4f2b-9d8a-6c7d8e9f0a1b",
    name: "ssh-admins",
    issuer: "https://idp.example.com/realms/acme",
    created_at: ago(300 * DAY),
  },
  {
    id: "a6b7c8d9-5d8e-4a3c-8e9b-7d8e9f0a1b2c",
    name: "ssh-auditors",
    issuer: "https://idp.example.com/realms/acme",
    created_at: ago(300 * DAY),
  },
  {
    id: "b7c8d9e0-6e9f-4b4d-9f0c-8e9f0a1b2c3d",
    name: "platform-team",
    issuer: "https://idp.example.com/realms/acme",
    created_at: ago(280 * DAY),
  },
  {
    id: "c8d9e0f1-7f0a-4c5e-8a1d-9f0a1b2c3d4e",
    name: "developers",
    issuer: "https://idp.example.com/realms/acme",
    created_at: ago(250 * DAY),
  },
  {
    id: "d9e0f1a2-8a1b-4d6f-9b2e-0a1b2c3d4e5f",
    name: "on-call",
    issuer: "https://idp.example.com/realms/acme",
    created_at: ago(100 * DAY),
  },
];

/**
 * Audit events: one handcrafted example per known event type (every pill
 * color: accent, ok, warn, danger, muted), then generated filler so the
 * paginator has multiple pages (page size 50).
 */
const auditSamples: Array<
  Pick<AuditEvent, "event_type" | "actor" | "payload">
> = [
  {
    event_type: "ca.cert_issued",
    actor: "user:ada@https://idp.example.com/realms/acme",
    payload: {
      cert_type: "user",
      key_id: "ada@idp",
      principals: ["ada", "ada.lovelace@example.com"],
      serial: 4711,
      valid_seconds: 3600,
    },
  },
  {
    event_type: "ca.agent_cert_issued",
    actor: "host:web-01.prod.example.com",
    payload: {
      cert_type: "host",
      principals: ["web-01.prod.example.com"],
      serial: 4712,
      valid_days: 30,
    },
  },
  {
    event_type: "ca.key_created",
    actor: "system",
    payload: { purpose: "user", algorithm: "ed25519" },
  },
  {
    event_type: "ca.key_rotated",
    actor: "system",
    payload: {
      purpose: "host",
      previous_state: "active",
      new_state: "retiring",
    },
  },
  {
    event_type: "ca.key_retired",
    actor: "system",
    payload: { purpose: "host", fingerprint: "SHA256:xyz…" },
  },
  {
    event_type: "grant.created",
    actor: "user:ada@https://idp.example.com/realms/acme",
    payload: {
      grant_id: mockGrants[0].id,
      group: "platform-team",
      principals: ["deploy", "root"],
      sudo: true,
    },
  },
  {
    event_type: "grant.updated",
    actor: "user:ada@https://idp.example.com/realms/acme",
    payload: {
      grant_id: mockGrants[2].id,
      group: "on-call",
      changed: ["max_validity_seconds"],
    },
  },
  {
    event_type: "grant.deleted",
    actor: "user:ada@https://idp.example.com/realms/acme",
    payload: {
      grant_id: "00000000-dead-beef-0000-000000000000",
      group: "interns",
    },
  },
  {
    event_type: "ci_grant.created",
    actor: "user:grace@https://idp.example.com/realms/acme",
    payload: {
      ci_grant_id: mockCiGrants[0].id,
      project: "acme/webshop",
      ref_pattern: "refs/tags/v*",
    },
  },
  {
    event_type: "ci_grant.updated",
    actor: "user:grace@https://idp.example.com/realms/acme",
    payload: {
      ci_grant_id: mockCiGrants[1].id,
      project: "acme/infrastructure",
    },
  },
  {
    event_type: "ci_grant.deleted",
    actor: "user:ada@https://idp.example.com/realms/acme",
    payload: {
      ci_grant_id: "00000000-dead-beef-0000-000000000001",
      project: "acme/sunset",
    },
  },
  {
    event_type: "service_account.updated",
    actor: "user:ada@https://idp.example.com/realms/acme",
    payload: {
      service_account_id: mockServiceAccounts[1].id,
      name: "acme/legacy-deploy",
      active: false,
    },
  },
  {
    event_type: "host.enrolled",
    actor: "host:ci-runner-large-01",
    payload: {
      host: "ci-runner-large-01",
      tags: { env: "ci", role: "runner", arch: "arm64" },
    },
  },
  {
    event_type: "auth.user_deactivated",
    actor: "system:group-sync",
    payload: {
      username: "former-contractor-with-very-long-name",
      reason: "removed from all groups",
    },
  },
  {
    event_type: "auth.user_reactivated",
    actor: "system:group-sync",
    payload: { username: "grace", reason: "group membership restored" },
  },
];

function buildAuditEvents(): AuditEvent[] {
  const events: AuditEvent[] = [];
  const total = 137; // > 2 pages at page size 50
  for (let i = 0; i < total; i++) {
    const sample = auditSamples[i % auditSamples.length];
    events.push({
      id: total - i,
      event_type: sample.event_type,
      actor: sample.actor,
      payload: sample.payload,
      // Newest first, roughly every 40 minutes with some spread.
      occurred_at: ago(i * 40 * MINUTE + (i % 7) * 3 * MINUTE),
    });
  }
  return events;
}

export const mockAuditEvents: AuditEvent[] = buildAuditEvents();
