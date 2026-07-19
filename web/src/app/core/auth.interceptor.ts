import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { OidcSecurityService } from 'angular-auth-oidc-client';
import { switchMap, take } from 'rxjs';

/**
 * Hängt das OIDC-ID-Token als Bearer-Token an alle API-Requests — der
 * Server validiert ID-Tokens (konsistent zu gssh-admin). /v1/ui/config
 * bleibt ohne Token (öffentlich, wird vor dem Login geladen).
 */
export const authTokenInterceptor: HttpInterceptorFn = (req, next) => {
  if (!req.url.startsWith('/v1/') || req.url.startsWith('/v1/ui/config')) {
    return next(req);
  }
  const oidc = inject(OidcSecurityService);
  return oidc.getIdToken().pipe(
    take(1),
    switchMap((token) => {
      if (token) {
        req = req.clone({ setHeaders: { Authorization: `Bearer ${token}` } });
      }
      return next(req);
    }),
  );
};
