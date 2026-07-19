import { HttpClient } from '@angular/common/http';
import { Injectable, computed, inject, signal } from '@angular/core';
import { OidcSecurityService } from 'angular-auth-oidc-client';
import { firstValueFrom } from 'rxjs';

import { UiConfig } from '../api/models';

/** Rollen der Admin-API; admin ⊃ auditor ⊃ readonly (wie im Backend). */
export type Role = 'admin' | 'auditor' | 'readonly';

/** rolesFor mappt die Gruppen aus den Token-Claims auf UI-Rollen. */
export function rolesFor(groups: readonly string[], cfg: UiConfig): Set<Role> {
  const has = (group: string) => group !== '' && groups.includes(group);
  const roles = new Set<Role>();
  if (has(cfg.admin_group)) {
    roles.add('admin');
  }
  if (roles.has('admin') || has(cfg.auditor_group)) {
    roles.add('auditor');
  }
  if (roles.has('auditor') || has(cfg.readonly_group)) {
    roles.add('readonly');
  }
  return roles;
}

/**
 * SessionService hält Login-Zustand und Rollen der angemeldeten Person.
 * Die Rollen dienen nur der Anzeige (Navigation, Buttons) — durchgesetzt
 * werden sie vom Server bei jedem Request.
 */
@Injectable({ providedIn: 'root' })
export class SessionService {
  private readonly oidc = inject(OidcSecurityService);
  private readonly http = inject(HttpClient);

  readonly checking = signal(true);
  readonly authenticated = signal(false);
  readonly username = signal('');
  readonly roles = signal<ReadonlySet<Role>>(new Set());

  readonly isAdmin = computed(() => this.roles().has('admin'));
  readonly isAuditor = computed(() => this.roles().has('auditor'));
  readonly hasAnyRole = computed(() => this.roles().size > 0);

  /** init führt checkAuth aus (inkl. Code-Callback) und lädt die Rollen. */
  async init(): Promise<void> {
    try {
      const config = await firstValueFrom(this.http.get<UiConfig>('/v1/ui/config'));
      const result = await firstValueFrom(this.oidc.checkAuth());
      this.authenticated.set(result.isAuthenticated);
      if (result.isAuthenticated) {
        const payload = await firstValueFrom(this.oidc.getPayloadFromIdToken());
        const groups: string[] = Array.isArray(payload?.['groups']) ? payload['groups'] : [];
        this.username.set(payload?.['preferred_username'] ?? payload?.['email'] ?? payload?.['sub'] ?? '');
        this.roles.set(rolesFor(groups, config));
      }
    } finally {
      this.checking.set(false);
    }
  }

  login(): void {
    this.oidc.authorize();
  }

  logout(): void {
    this.oidc.logoffAndRevokeTokens().subscribe({
      // Fallback, falls der IdP kein End-Session unterstützt.
      error: () => this.oidc.logoffLocal(),
    });
  }
}
