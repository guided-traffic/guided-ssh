import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { ApplicationConfig, provideBrowserGlobalErrorListeners } from '@angular/core';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { provideRouter } from '@angular/router';

import { provideApiConfiguration } from './api/api-configuration';
import { routes } from './app.routes';
import { apiHeaderInterceptor } from './core/auth.interceptor';
import { provideAppIcons } from './core/icons';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideRouter(routes),
    provideHttpClient(withInterceptors([apiHeaderInterceptor])),
    provideAnimationsAsync(),
    provideAppIcons(),
    // API paths already carry a leading '/v1' (same-origin). Root URL must be
    // empty, otherwise the default '/' produces '//v1/...' (protocol-relative → CORS fail).
    provideApiConfiguration(''),
  ],
};
