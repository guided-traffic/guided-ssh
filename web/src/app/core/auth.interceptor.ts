import { HttpInterceptorFn } from '@angular/common/http';

/**
 * Marks all API requests with X-Requested-With: the server only accepts
 * cookie-authenticated requests that carry this custom header (CSRF
 * protection in addition to SameSite=Lax, since cross-site forms cannot
 * set custom headers). The browser sends the session cookie itself
 * automatically on same-origin requests — no token is needed here.
 */
export const apiHeaderInterceptor: HttpInterceptorFn = (req, next) => {
  if (!req.url.startsWith('/v1/')) {
    return next(req);
  }
  return next(req.clone({ setHeaders: { 'X-Requested-With': 'XMLHttpRequest' } }));
};
