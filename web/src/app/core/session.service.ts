import { HttpClient } from '@angular/common/http';
import { Injectable, computed, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { AuthSession } from '../api/models';

/** Rollen der Admin-API; admin ⊃ auditor ⊃ readonly (wie im Backend). */
export type Role = 'admin' | 'auditor' | 'readonly';

/**
 * SessionService hält Login-Zustand und Rollen der angemeldeten Person.
 * Der Login läuft server-seitig (BFF): GET /v1/auth/login startet den
 * OIDC-Flow beim Server, die Session liegt in einem HttpOnly-Cookie und
 * GET /v1/auth/me liefert Zustand, Benutzername und Rollen. Die Rollen
 * dienen nur der Anzeige (Navigation, Buttons) — durchgesetzt werden sie
 * vom Server bei jedem Request.
 */
@Injectable({ providedIn: 'root' })
export class SessionService {
  private readonly http = inject(HttpClient);

  readonly checking = signal(true);
  readonly authenticated = signal(false);
  readonly username = signal('');
  readonly roles = signal<ReadonlySet<Role>>(new Set());
  /** Fehlermeldung, wenn die Login-Prüfung nicht möglich war (Server down). */
  readonly error = signal('');

  readonly isAdmin = computed(() => this.roles().has('admin'));
  readonly isAuditor = computed(() => this.roles().has('auditor'));
  readonly hasAnyRole = computed(() => this.roles().size > 0);

  private ready?: Promise<void>;

  /**
   * init lädt den Login-Zustand vom Server. Idempotent (App-Start und
   * Route-Guards teilen sich einen Lauf) und rejected nie: Fehler landen
   * im error-Signal, damit die UI sie anzeigt.
   */
  init(): Promise<void> {
    this.ready ??= this.run();
    return this.ready;
  }

  private async run(): Promise<void> {
    try {
      const session = await firstValueFrom(this.http.get<AuthSession>('/v1/auth/me'));
      this.authenticated.set(session.authenticated);
      if (session.authenticated) {
        this.username.set(session.username ?? '');
        this.roles.set(new Set((session.roles ?? []) as Role[]));
      }
    } catch (err) {
      console.error('Login-Prüfung fehlgeschlagen', err);
      this.error.set(
        'Anmeldung derzeit nicht möglich: Server nicht erreichbar oder ' +
          'Login nicht konfiguriert. Details in der Browser-Konsole.',
      );
    } finally {
      this.checking.set(false);
    }
  }

  /** Startet den server-seitigen Login; zurück geht es auf die aktuelle Seite. */
  login(): void {
    const target = window.location.pathname + window.location.search;
    window.location.assign('/v1/auth/login?redirect=' + encodeURIComponent(target));
  }

  /** Beendet die Server-Session; die IdP-Session bleibt bestehen (Dex ohne End-Session). */
  logout(): void {
    this.http.post('/v1/auth/logout', null).subscribe({
      complete: () => window.location.assign('/'),
      error: () => window.location.assign('/'),
    });
  }
}
