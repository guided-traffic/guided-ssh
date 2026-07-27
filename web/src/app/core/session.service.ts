import { HttpClient } from '@angular/common/http';
import { Injectable, computed, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { AuthSession } from '../api/models';

/** Roles of the admin API; admin ⊃ auditor (as in the backend). */
export type Role = 'admin' | 'auditor';

/**
 * SessionService holds the login state and roles of the signed-in person.
 * Login runs server-side (BFF): GET /v1/auth/login starts the OIDC flow
 * on the server, the session lives in an HttpOnly cookie, and
 * GET /v1/auth/me returns the state, username, and roles. The roles are
 * only for display purposes (navigation, buttons) — they are enforced by
 * the server on every request.
 */
@Injectable({ providedIn: 'root' })
export class SessionService {
  private readonly http = inject(HttpClient);

  readonly checking = signal(true);
  readonly authenticated = signal(false);
  readonly username = signal('');
  readonly roles = signal<ReadonlySet<Role>>(new Set());
  /** Error message when the login check was not possible (server down). */
  readonly error = signal('');
  /** Message when the server rejected the IdP login (no admin/auditor role). */
  readonly loginError = signal('');

  readonly isAdmin = computed(() => this.roles().has('admin'));
  readonly isAuditor = computed(() => this.roles().has('auditor'));
  readonly hasAnyRole = computed(() => this.roles().size > 0);

  private ready?: Promise<void>;

  /**
   * init loads the login state from the server. Idempotent (app start and
   * route guards share a single run) and never rejects: errors end up in
   * the error signal so the UI can display them.
   */
  init(): Promise<void> {
    this.ready ??= this.run();
    return this.ready;
  }

  private async run(): Promise<void> {
    this.consumeLoginError();
    try {
      const session = await firstValueFrom(this.http.get<AuthSession>('/v1/auth/me'));
      this.authenticated.set(session.authenticated);
      if (session.authenticated) {
        this.username.set(session.username ?? '');
        this.roles.set(new Set((session.roles ?? []) as Role[]));
      }
    } catch (err) {
      console.error('Login check failed', err);
      this.error.set(
        'Sign-in currently unavailable: server unreachable or login not ' +
          'configured. See the browser console for details.',
      );
    } finally {
      this.checking.set(false);
    }
  }

  /**
   * consumeLoginError reads the login_error marker a rejected
   * /v1/auth/callback redirects with and strips it from the URL —
   * synchronously, before the first await, so the router's initial
   * navigation ('' → 'hosts' preserves query params) never carries it on.
   */
  private consumeLoginError(): void {
    const params = new URLSearchParams(window.location.search);
    if (params.get('login_error') !== 'no_role') {
      return;
    }
    this.loginError.set(
      'Sign-in rejected: your account has neither the admin nor the auditor ' +
        'role. Ask an operator to add you to one of these IdP groups, then try again.',
    );
    params.delete('login_error');
    const query = params.toString();
    window.history.replaceState(null, '', window.location.pathname + (query ? '?' + query : ''));
  }

  /** Starts the server-side login; returns to the current page afterwards. */
  login(): void {
    const target = window.location.pathname + window.location.search;
    window.location.assign('/v1/auth/login?redirect=' + encodeURIComponent(target));
  }

  /** Ends the server session; the IdP session remains active (Dex has no end-session endpoint). */
  logout(): void {
    this.http.post('/v1/auth/logout', null).subscribe({
      complete: () => window.location.assign('/'),
      error: () => window.location.assign('/'),
    });
  }
}
