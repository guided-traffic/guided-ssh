import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { ApplicationConfig, provideBrowserGlobalErrorListeners } from '@angular/core';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { provideRouter } from '@angular/router';
import { StsConfigLoader, provideAuth } from 'angular-auth-oidc-client';

import { routes } from './app.routes';
import { authConfigFactory } from './core/auth.config';
import { authTokenInterceptor } from './core/auth.interceptor';
import { provideAppIcons } from './core/icons';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideRouter(routes),
    provideHttpClient(withInterceptors([authTokenInterceptor])),
    provideAnimationsAsync(),
    provideAuth({
      loader: { provide: StsConfigLoader, useFactory: authConfigFactory, deps: [HttpClient] },
    }),
    provideAppIcons(),
  ],
};
