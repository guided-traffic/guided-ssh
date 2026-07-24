import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';

import { Role, SessionService } from './session.service';

/**
 * roleGuard prüft die Mindest-Rolle einer Route (route.data['minRole']).
 * Nur Anzeige-Logik — die API lehnt unberechtigte Requests ohnehin ab.
 *
 * Wartet auf session.init(), weil die Initial-Navigation sonst gegen noch
 * leere Rollen prüft. Leitet nie auf '/' um: '' → 'hosts' → Guard → '/' war
 * ein synchroner Endlos-Redirect, der die Seite komplett eingefroren hat.
 * Fallback ist '/hosts' (readonly reicht dort) — und nur, wenn diese Rolle
 * vorhanden ist; sonst wird die Navigation abgebrochen und die App-Shell
 * zeigt Login-, Fehler- oder „keine Rolle“-Karte.
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
