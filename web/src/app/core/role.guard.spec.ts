import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ActivatedRouteSnapshot, UrlTree, provideRouter } from '@angular/router';
import { describe, expect, it } from 'vitest';

import { roleGuard } from './role.guard';
import { Role, SessionService } from './session.service';

/**
 * Regression tests for the infinite redirect at app startup:
 * '' → 'hosts' → guard (roles still empty) → UrlTree('/') → '' → 'hosts' → …
 * The guard must therefore (a) only decide after session.init(), and
 * (b) never redirect to '/' — only to '/hosts', if that is safely
 * reachable (readonly present), otherwise cancel navigation (false).
 */

class FakeSession {
  readonly roles = signal<ReadonlySet<Role>>(new Set());
  initCalls = 0;
  private readonly pending: ReadonlySet<Role>;

  constructor(rolesAfterInit: Role[]) {
    this.pending = new Set(rolesAfterInit);
  }

  async init(): Promise<void> {
    this.initCalls++;
    // Roles only become known asynchronously — just like the real checkAuth.
    await Promise.resolve();
    this.roles.set(this.pending);
  }
}

const runGuard = async (session: FakeSession, minRole: Role) => {
  TestBed.configureTestingModule({
    providers: [provideRouter([]), { provide: SessionService, useValue: session }],
  });
  const route = { data: { minRole } } as unknown as ActivatedRouteSnapshot;
  return TestBed.runInInjectionContext(() =>
    roleGuard(route, {} as never),
  ) as Promise<boolean | UrlTree>;
};

describe('roleGuard', () => {
  it('without roles: cancels (false) instead of redirecting to "/" — no infinite redirect', async () => {
    const result = await runGuard(new FakeSession([]), 'readonly');
    expect(result).toBe(false);
  });

  it('waits for session.init() before checking roles', async () => {
    const session = new FakeSession(['admin', 'auditor', 'readonly']);
    const result = await runGuard(session, 'readonly');
    expect(session.initCalls).toBeGreaterThan(0);
    expect(result).toBe(true);
  });

  it('insufficient role: redirects to /hosts (readonly is enough there), never to "/"', async () => {
    const result = await runGuard(new FakeSession(['readonly']), 'auditor');
    expect(result).toBeInstanceOf(UrlTree);
    expect(String(result)).toBe('/hosts');
  });

  it('sufficient role: access allowed', async () => {
    const result = await runGuard(new FakeSession(['auditor', 'readonly']), 'auditor');
    expect(result).toBe(true);
  });
});
