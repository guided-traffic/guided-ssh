import { HttpClient } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { OidcSecurityService } from 'angular-auth-oidc-client';
import { of, throwError } from 'rxjs';
import { describe, expect, it } from 'vitest';

import { UiConfig } from '../api/models';
import { SessionService, rolesFor } from './session.service';

const cfg: UiConfig = {
  oidc_issuer: 'https://idp.example.com',
  oidc_client_id: 'gssh-ui',
  admin_group: 'gssh-admins',
  auditor_group: 'gssh-auditors',
  readonly_group: 'gssh-readonly',
};

describe('rolesFor', () => {
  it('admin schließt auditor und readonly ein', () => {
    expect(rolesFor(['gssh-admins'], cfg)).toEqual(new Set(['admin', 'auditor', 'readonly']));
  });

  it('auditor schließt readonly ein', () => {
    expect(rolesFor(['gssh-auditors', 'dev'], cfg)).toEqual(new Set(['auditor', 'readonly']));
  });

  it('readonly bleibt readonly', () => {
    expect(rolesFor(['gssh-readonly'], cfg)).toEqual(new Set(['readonly']));
  });

  it('ohne passende Gruppe keine Rolle', () => {
    expect(rolesFor(['dev'], cfg).size).toBe(0);
  });

  it('leere Gruppen-Konfiguration vergibt die Rolle an niemanden (fail-closed)', () => {
    const noAdmin = { ...cfg, admin_group: '' };
    expect(rolesFor([''], noAdmin).size).toBe(0);
  });
});

/**
 * init() darf niemals unbehandelt rejecten: Fehler (Config nicht ladbar,
 * OIDC-Discovery down/CORS) landen im error-Signal, checking endet — die UI
 * zeigt eine Fehlermeldung statt ewig zu hängen.
 */
describe('SessionService.init Fehlerbehandlung', () => {
  const setup = (providers: unknown[]) => {
    TestBed.configureTestingModule({ providers: providers as [] });
    return TestBed.inject(SessionService);
  };

  it('Config-Fehler: error gesetzt, checking beendet, kein Reject', async () => {
    const session = setup([
      { provide: HttpClient, useValue: { get: () => throwError(() => new Error('boom')) } },
      { provide: OidcSecurityService, useValue: {} },
    ]);
    await expect(session.init()).resolves.toBeUndefined();
    expect(session.checking()).toBe(false);
    expect(session.error()).not.toBe('');
    expect(session.authenticated()).toBe(false);
  });

  it('checkAuth-Fehler: error gesetzt, checking beendet, kein Reject', async () => {
    const session = setup([
      { provide: HttpClient, useValue: { get: () => of(cfg) } },
      {
        provide: OidcSecurityService,
        useValue: { checkAuth: () => throwError(() => new Error('discovery unreachable')) },
      },
    ]);
    await expect(session.init()).resolves.toBeUndefined();
    expect(session.checking()).toBe(false);
    expect(session.error()).not.toBe('');
  });

  it('init ist idempotent — mehrfacher Aufruf (App + Guard) startet checkAuth nur einmal', async () => {
    let calls = 0;
    const session = setup([
      { provide: HttpClient, useValue: { get: () => of(cfg) } },
      {
        provide: OidcSecurityService,
        useValue: {
          checkAuth: () => {
            calls++;
            return of({ isAuthenticated: false });
          },
        },
      },
    ]);
    await Promise.all([session.init(), session.init()]);
    await session.init();
    expect(calls).toBe(1);
  });
});
