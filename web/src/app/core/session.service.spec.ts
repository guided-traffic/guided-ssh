import { HttpClient } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { describe, expect, it } from 'vitest';

import { AuthSession } from '../api/models';
import { SessionService } from './session.service';

/**
 * init() darf niemals unbehandelt rejecten: Fehler (Server down, BFF nicht
 * konfiguriert ⇒ 503) landen im error-Signal, checking endet — die UI zeigt
 * eine Fehlermeldung statt ewig zu hängen.
 */
describe('SessionService.init', () => {
  const setup = (me: () => unknown) => {
    TestBed.configureTestingModule({
      providers: [{ provide: HttpClient, useValue: { get: me } }],
    });
    return TestBed.inject(SessionService);
  };

  it('übernimmt Benutzername und Rollen aus /v1/auth/me', async () => {
    const session: AuthSession = {
      authenticated: true,
      username: 'alice',
      roles: ['auditor', 'readonly'],
    };
    const service = setup(() => of(session));
    await service.init();
    expect(service.authenticated()).toBe(true);
    expect(service.username()).toBe('alice');
    expect(service.roles()).toEqual(new Set(['auditor', 'readonly']));
    expect(service.isAuditor()).toBe(true);
    expect(service.isAdmin()).toBe(false);
    expect(service.checking()).toBe(false);
    expect(service.error()).toBe('');
  });

  it('bleibt ohne Session abgemeldet und ohne Fehler', async () => {
    const service = setup(() => of({ authenticated: false } as AuthSession));
    await service.init();
    expect(service.authenticated()).toBe(false);
    expect(service.hasAnyRole()).toBe(false);
    expect(service.checking()).toBe(false);
    expect(service.error()).toBe('');
  });

  it('meldet Fehler statt zu rejecten, wenn /v1/auth/me fehlschlägt', async () => {
    const service = setup(() => throwError(() => new Error('503')));
    await expect(service.init()).resolves.toBeUndefined();
    expect(service.checking()).toBe(false);
    expect(service.authenticated()).toBe(false);
    expect(service.error()).not.toBe('');
  });

  it('init ist idempotent — mehrfacher Aufruf (App + Guard) fragt nur einmal an', async () => {
    let calls = 0;
    const service = setup(() => {
      calls++;
      return of({ authenticated: false } as AuthSession);
    });
    await Promise.all([service.init(), service.init()]);
    await service.init();
    expect(calls).toBe(1);
  });
});
