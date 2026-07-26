import { HttpClient } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { describe, expect, it } from 'vitest';

import { AuthSession } from '../api/models';
import { SessionService } from './session.service';

/**
 * init() must never reject unhandled: errors (server down, BFF not
 * configured ⇒ 503) end up in the error signal, checking ends — the UI
 * shows an error message instead of hanging forever.
 */
describe('SessionService.init', () => {
  const setup = (me: () => unknown) => {
    TestBed.configureTestingModule({
      providers: [{ provide: HttpClient, useValue: { get: me } }],
    });
    return TestBed.inject(SessionService);
  };

  it('adopts username and roles from /v1/auth/me', async () => {
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

  it('stays signed out without a session and without an error', async () => {
    const service = setup(() => of({ authenticated: false } as AuthSession));
    await service.init();
    expect(service.authenticated()).toBe(false);
    expect(service.hasAnyRole()).toBe(false);
    expect(service.checking()).toBe(false);
    expect(service.error()).toBe('');
  });

  it('reports an error instead of rejecting when /v1/auth/me fails', async () => {
    const service = setup(() => throwError(() => new Error('503')));
    await expect(service.init()).resolves.toBeUndefined();
    expect(service.checking()).toBe(false);
    expect(service.authenticated()).toBe(false);
    expect(service.error()).not.toBe('');
  });

  it('init is idempotent — multiple calls (app + guard) only fetch once', async () => {
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
