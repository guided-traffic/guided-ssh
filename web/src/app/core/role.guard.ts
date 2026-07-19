import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';

import { Role, SessionService } from './session.service';

/**
 * roleGuard prüft die Mindest-Rolle einer Route (route.data['minRole']).
 * Nur Anzeige-Logik — die API lehnt unberechtigte Requests ohnehin ab.
 */
export const roleGuard: CanActivateFn = (route) => {
  const session = inject(SessionService);
  const router = inject(Router);
  const minRole = (route.data['minRole'] ?? 'readonly') as Role;
  if (session.roles().has(minRole)) {
    return true;
  }
  return router.parseUrl('/');
};
