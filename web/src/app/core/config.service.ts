import { Injectable, computed, inject, signal } from '@angular/core';

import { Api } from '../api/api';
import { getUiConfig } from '../api/functions';
import { UiConfig } from '../api/models';

/**
 * ConfigService holds the public bootstrap configuration
 * (GET /v1/ui/config), loaded once per app run and shared by the pages that
 * need it.
 *
 * grantsEditable/ciGrantsEditable say whether the server accepts in-app rule
 * writes for that domain at all — manual provisioning enabled and the domain
 * not owned by a rules file (docs/major-tickets/GITOPS_EXTERNAL_RULES.md,
 * D7). They only keep the UI from offering writes that would 403; the server
 * enforces the same conditions on every request. Both stay false until the
 * configuration is loaded, so a failed request hides the buttons instead of
 * showing dead ones.
 */
@Injectable({ providedIn: 'root' })
export class ConfigService {
  private readonly api = inject(Api);

  readonly config = signal<UiConfig | null>(null);
  /** True once the configuration is known — separates "not loaded" from "not editable". */
  readonly loaded = computed(() => this.config() !== null);
  readonly grantsEditable = computed(() => this.config()?.grants_editable ?? false);
  readonly ciGrantsEditable = computed(() => this.config()?.ci_grants_editable ?? false);

  private ready?: Promise<void>;

  /** Loads the configuration once (idempotent); never rejects. */
  load(): Promise<void> {
    this.ready ??= this.api
      .invoke(getUiConfig)
      .then((config) => this.config.set(config))
      .catch((err: unknown) => console.error('Loading the UI configuration failed', err));
    return this.ready;
  }
}
