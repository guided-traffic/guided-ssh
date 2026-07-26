/**
 * Default environment (production and `ng serve -c backend`): all API calls
 * go to the real server (same origin or the dev-server proxy).
 */
export const environment = {
  /** true ⇒ the mock interceptor answers every /v1 request with fixtures. */
  mockApi: false,
};
