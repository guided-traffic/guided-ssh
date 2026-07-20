import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ActivatedRouteSnapshot, UrlTree, provideRouter } from '@angular/router';
import { describe, expect, it } from 'vitest';

import { roleGuard } from './role.guard';
import { Role, SessionService } from './session.service';

/**
 * Regressionstests für den Endlos-Redirect beim App-Start:
 * '' → 'hosts' → Guard (Rollen noch leer) → UrlTree('/') → '' → 'hosts' → …
 * Der Guard darf deshalb (a) erst nach session.init() entscheiden und
 * (b) niemals auf '/' umleiten — nur nach '/hosts', wenn das sicher
 * erreichbar ist (readonly vorhanden), sonst Navigation abbrechen (false).
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
    // Rollen werden erst asynchron bekannt — wie in echt (checkAuth).
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
  it('ohne Rollen: bricht ab (false) statt auf "/" umzuleiten — kein Endlos-Redirect', async () => {
    const result = await runGuard(new FakeSession([]), 'readonly');
    expect(result).toBe(false);
  });

  it('wartet auf session.init(), bevor Rollen geprüft werden', async () => {
    const session = new FakeSession(['admin', 'auditor', 'readonly']);
    const result = await runGuard(session, 'readonly');
    expect(session.initCalls).toBeGreaterThan(0);
    expect(result).toBe(true);
  });

  it('unzureichende Rolle: Umleitung nach /hosts (dort reicht readonly), nie nach "/"', async () => {
    const result = await runGuard(new FakeSession(['readonly']), 'auditor');
    expect(result).toBeInstanceOf(UrlTree);
    expect(String(result)).toBe('/hosts');
  });

  it('ausreichende Rolle: Zugriff erlaubt', async () => {
    const result = await runGuard(new FakeSession(['auditor', 'readonly']), 'auditor');
    expect(result).toBe(true);
  });
});
