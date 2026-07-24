import { HttpInterceptorFn } from '@angular/common/http';

/**
 * Markiert alle API-Requests mit X-Requested-With: Cookie-authentifizierte
 * Requests akzeptiert der Server nur mit diesem Custom-Header (CSRF-Schutz
 * zusätzlich zu SameSite=Lax, weil Cross-Site-Formulare keine Custom-Header
 * setzen können). Das Session-Cookie selbst schickt der Browser bei
 * Same-Origin-Requests automatisch mit — hier ist kein Token nötig.
 */
export const apiHeaderInterceptor: HttpInterceptorFn = (req, next) => {
  if (!req.url.startsWith('/v1/')) {
    return next(req);
  }
  return next(req.clone({ setHeaders: { 'X-Requested-With': 'XMLHttpRequest' } }));
};
