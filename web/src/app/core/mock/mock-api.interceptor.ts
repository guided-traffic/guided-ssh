import {
  HttpEvent,
  HttpInterceptorFn,
  HttpRequest,
  HttpResponse,
} from "@angular/common/http";
import { Observable, of } from "rxjs";
import { delay } from "rxjs/operators";

import {
  ApplyResult,
  AuditList,
  CiGrant,
  CiGrantRequest,
  EnrollTokenRequest,
  EnrollTokenResponse,
  Grant,
  GrantRequest,
  ServiceAccount,
} from "../../api/models";
import {
  mockAgentManifest,
  mockAuditEvents,
  mockCiGrants,
  mockClientManifest,
  mockGrants,
  mockGroups,
  mockHosts,
  mockServiceAccounts,
  mockSession,
  mockUiConfig,
  mockUsers,
} from "./mock-data";

/**
 * mockApiInterceptor answers every /v1 request from fixtures — the UI runs
 * without any backend (design review at runtime; enabled via
 * environment.mockApi, i.e. plain `ng serve`). Grants, CI grants, and
 * service accounts are held in module state, so create/edit/delete dialogs
 * behave like the real thing until the next reload.
 *
 * Role variants: `localStorage.setItem('gssh-mock-roles', 'readonly')` (or
 * 'auditor,readonly', or '' for logged-out) + reload shows the UI as that
 * role; removing the key restores the full admin view.
 */
export const mockApiInterceptor: HttpInterceptorFn = (req, next) => {
  if (!req.url.startsWith("/v1/")) {
    return next(req);
  }
  const response = route(req);
  if (!response) {
    console.warn(`[mock-api] no fixture for ${req.method} ${req.url} — 404`);
    return respond(req, 404, { error: "no mock fixture" });
  }
  return response;
};

/** Simulated network latency so spinners and loading states show up. */
const LATENCY_MS = 250;

function respond(
  req: HttpRequest<unknown>,
  status: number,
  body: unknown,
): Observable<HttpEvent<unknown>> {
  return of(new HttpResponse({ url: req.url, status, body })).pipe(
    delay(LATENCY_MS),
  );
}

// Mutable copies: dialogs create/update/delete against these until reload.
const grants: Grant[] = structuredClone(mockGrants);
const ciGrants: CiGrant[] = structuredClone(mockCiGrants);
const serviceAccounts: ServiceAccount[] = structuredClone(mockServiceAccounts);

function route(
  req: HttpRequest<unknown>,
): Observable<HttpEvent<unknown>> | null {
  const path = req.url.split("?")[0];
  const method = req.method;

  if (method === "GET" && path === "/v1/auth/me") {
    return respond(req, 200, sessionFixture());
  }
  if (method === "POST" && path === "/v1/auth/logout") {
    return respond(req, 204, null);
  }
  if (method === "GET" && path === "/v1/ui/config") {
    return respond(req, 200, mockUiConfig);
  }
  if (method === "GET" && path === "/v1/admin/hosts") {
    return respond(req, 200, mockHosts);
  }
  if (method === "GET" && path === "/v1/agents") {
    return respond(req, 200, mockAgentManifest);
  }
  if (method === "GET" && path === "/v1/clients") {
    return respond(req, 200, mockClientManifest);
  }
  if (method === "POST" && path === "/v1/admin/enroll-tokens") {
    return respond(
      req,
      201,
      enrollTokenFixture(req.body as EnrollTokenRequest),
    );
  }
  if (method === "GET" && path === "/v1/admin/users") {
    return respond(req, 200, mockUsers);
  }
  if (method === "GET" && path === "/v1/admin/groups") {
    return respond(req, 200, mockGroups);
  }
  if (method === "GET" && path === "/v1/admin/service-accounts") {
    return respond(req, 200, serviceAccounts);
  }
  if (method === "GET" && path === "/v1/admin/audit") {
    return respond(req, 200, auditFixture(req));
  }
  if (method === "GET" && path === "/v1/admin/audit/export") {
    return respond(req, 200, exportFixture(req));
  }

  const grantRoute = crudRoute(
    req,
    path,
    "/v1/admin/grants",
    grants,
    applyGrant,
  );
  if (grantRoute) {
    return grantRoute;
  }
  return (
    crudRoute(req, path, "/v1/admin/ci-grants", ciGrants, applyCiGrant) ??
    serviceAccountRoute(req, path)
  );
}

/** Session with optional role override from localStorage (see file docs). */
function sessionFixture(): typeof mockSession {
  const override = localStorage.getItem("gssh-mock-roles");
  if (override === null) {
    return mockSession;
  }
  const roles = override
    .split(",")
    .map((role) => role.trim())
    .filter(Boolean) as NonNullable<typeof mockSession.roles>;
  if (roles.length === 0) {
    return { authenticated: false };
  }
  return { ...mockSession, roles };
}

function enrollTokenFixture(
  body: EnrollTokenRequest | null,
): EnrollTokenResponse {
  const ttlSeconds = body?.ttl_seconds ?? 24 * 3600;
  const token = "mock-enroll-token-c2VjcmV0LXRva2Vu";
  const audit = body?.session_audit ? " --session-audit" : "";
  return {
    token,
    expires_at: new Date(Date.now() + ttlSeconds * 1000).toISOString(),
    install_command: `curl -fsSL https://gssh.example.com/install.sh | sh -s -- --token ${token} --pin sha256:AAAA…${audit}`,
  };
}

/** Audit list with the same filters the server supports. */
function auditFixture(req: HttpRequest<unknown>): AuditList {
  const params = req.params;
  const eventType = params.get("event_type") ?? "";
  const actor = params.get("actor") ?? "";
  const q = (params.get("q") ?? "").toLowerCase();
  const since = params.get("since");
  const until = params.get("until");
  const limit = Number(params.get("limit") ?? 50);
  const offset = Number(params.get("offset") ?? 0);

  const filtered = mockAuditEvents.filter((event) => {
    if (eventType && event.event_type !== eventType) {
      return false;
    }
    if (actor && event.actor !== actor) {
      return false;
    }
    if (q && !JSON.stringify(event).toLowerCase().includes(q)) {
      return false;
    }
    if (since && event.occurred_at < since) {
      return false;
    }
    if (until && event.occurred_at > until) {
      return false;
    }
    return true;
  });
  return {
    total: filtered.length,
    events: filtered.slice(offset, offset + limit),
  };
}

function exportFixture(req: HttpRequest<unknown>): Blob {
  const { events } = auditFixture(req);
  if (req.params.get("format") === "csv") {
    const rows = events.map(
      (event) =>
        `${event.id},${event.occurred_at},${event.event_type},"${event.actor}"`,
    );
    return new Blob(["id,occurred_at,event_type,actor\n" + rows.join("\n")], {
      type: "text/csv",
    });
  }
  return new Blob([JSON.stringify(events, null, 2)], {
    type: "application/json",
  });
}

/**
 * crudRoute implements list/create/update/delete/apply for the two grant
 * collections; returns null if the path doesn't belong to the collection.
 */
function crudRoute<T extends { id: string }, R>(
  req: HttpRequest<unknown>,
  path: string,
  base: string,
  items: T[],
  applyRequest: (request: R, existing: T | undefined) => T,
): Observable<HttpEvent<unknown>> | null {
  if (path === `${base}/apply` && req.method === "POST") {
    const result: ApplyResult = {
      created: 1,
      updated: 2,
      deleted: 0,
      unchanged: items.length,
    };
    return respond(req, 200, result);
  }
  if (path === base) {
    if (req.method === "GET") {
      return respond(req, 200, items);
    }
    if (req.method === "POST") {
      const created = applyRequest(req.body as R, undefined);
      items.unshift(created);
      return respond(req, 201, created);
    }
    return null;
  }
  if (!path.startsWith(`${base}/`)) {
    return null;
  }
  const id = path.slice(base.length + 1);
  const index = items.findIndex((item) => item.id === id);
  if (index === -1) {
    return respond(req, 404, { error: "not found" });
  }
  switch (req.method) {
    case "GET":
      return respond(req, 200, items[index]);
    case "PUT": {
      const updated = applyRequest(req.body as R, items[index]);
      items[index] = updated;
      return respond(req, 200, updated);
    }
    case "DELETE":
      items.splice(index, 1);
      return respond(req, 204, null);
    default:
      return null;
  }
}

function applyGrant(request: GrantRequest, existing: Grant | undefined): Grant {
  const now = new Date().toISOString();
  return {
    id: existing?.id ?? crypto.randomUUID(),
    group: request.group ?? existing?.group ?? "",
    issuer: request.issuer || (existing?.issuer ?? mockUiConfig.oidc_issuer),
    principals: request.principals,
    sudo: request.sudo ?? false,
    max_validity_seconds: request.max_validity_seconds,
    tag_selector: request.tag_selector ?? {},
    created_at: existing?.created_at ?? now,
    updated_at: now,
  };
}

function applyCiGrant(
  request: CiGrantRequest,
  existing: CiGrant | undefined,
): CiGrant {
  const now = new Date().toISOString();
  return {
    id: existing?.id ?? crypto.randomUUID(),
    project: request.project ?? existing?.project ?? "",
    principals: request.principals,
    ref_pattern: request.ref_pattern,
    environment_pattern: request.environment_pattern,
    protected_only: request.protected_only ?? false,
    max_validity_seconds: request.max_validity_seconds,
    tag_selector: request.tag_selector ?? {},
    created_at: existing?.created_at ?? now,
    updated_at: now,
  };
}

function serviceAccountRoute(
  req: HttpRequest<unknown>,
  path: string,
): Observable<HttpEvent<unknown>> | null {
  const base = "/v1/admin/service-accounts/";
  if (req.method !== "PUT" || !path.startsWith(base)) {
    return null;
  }
  const id = path.slice(base.length);
  const account = serviceAccounts.find((item) => item.id === id);
  if (!account) {
    return respond(req, 404, { error: "not found" });
  }
  const body = req.body as Partial<ServiceAccount>;
  account.active = body.active ?? account.active;
  account.updated_at = new Date().toISOString();
  return respond(req, 200, account);
}
