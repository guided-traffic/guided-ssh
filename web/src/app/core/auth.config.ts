import { HttpClient } from '@angular/common/http';
import { LogLevel, StsConfigHttpLoader } from 'angular-auth-oidc-client';
import { map } from 'rxjs';

import { UiConfig } from '../api/models';

/**
 * Lädt die OIDC-Konfiguration vom Server (/v1/ui/config): Issuer und
 * Client-ID kommen aus dem Deployment, die SPA bleibt konfigurationsfrei.
 * Authorization Code + PKCE (Public Client, kein Secret).
 */
export const authConfigFactory = (http: HttpClient): StsConfigHttpLoader => {
  const config$ = http.get<UiConfig>('/v1/ui/config').pipe(
    map((cfg) => ({
      authority: cfg.oidc_issuer,
      clientId: cfg.oidc_client_id,
      redirectUrl: window.location.origin,
      postLogoutRedirectUri: window.location.origin,
      responseType: 'code',
      scope: 'openid profile email',
      silentRenew: true,
      useRefreshToken: true,
      renewTimeBeforeTokenExpiresInSeconds: 60,
      logLevel: LogLevel.Warn,
    })),
  );
  return new StsConfigHttpLoader(config$);
};
