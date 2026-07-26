import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';

import { Role, SessionService } from './session.service';

/**
 * roleGuard checks a route's minimum role (route.data['minRole']).
 * Display logic only — the API rejects unauthorized requests regardless.
 *
 * Waits for session.init(), since the initial navigation would otherwise
 * check against still-empty roles. Never redirects to '/': '' → 'hosts' →
 * guard → '/' used to be a synchronous infinite redirect that completely
 * froze the page. The fallback is '/hosts' (readonly is enough there) —
 * and only if that role is present; otherwise navigation is cancelled and
 * the app shell shows the login, error, or "no role" card.
 */
export const roleGuard: CanActivateFn = async (route) => {
  const session = inject(SessionService);
  const router = inject(Router);
  const minRole = (route.data['minRole'] ?? 'readonly') as Role;
  await session.init();
  if (session.roles().has(minRole)) {
    return true;
  }
  return session.roles().has('readonly') ? router.parseUrl('/hosts') : false;
};
