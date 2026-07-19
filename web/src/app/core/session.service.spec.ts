import { describe, expect, it } from 'vitest';

import { UiConfig } from '../api/models';
import { rolesFor } from './session.service';

const cfg: UiConfig = {
  oidc_issuer: 'https://idp.example.com',
  oidc_client_id: 'gssh-ui',
  admin_group: 'gssh-admins',
  auditor_group: 'gssh-auditors',
  readonly_group: 'gssh-readonly',
};

describe('rolesFor', () => {
  it('admin schließt auditor und readonly ein', () => {
    expect(rolesFor(['gssh-admins'], cfg)).toEqual(new Set(['admin', 'auditor', 'readonly']));
  });

  it('auditor schließt readonly ein', () => {
    expect(rolesFor(['gssh-auditors', 'dev'], cfg)).toEqual(new Set(['auditor', 'readonly']));
  });

  it('readonly bleibt readonly', () => {
    expect(rolesFor(['gssh-readonly'], cfg)).toEqual(new Set(['readonly']));
  });

  it('ohne passende Gruppe keine Rolle', () => {
    expect(rolesFor(['dev'], cfg).size).toBe(0);
  });

  it('leere Gruppen-Konfiguration vergibt die Rolle an niemanden (fail-closed)', () => {
    const noAdmin = { ...cfg, admin_group: '' };
    expect(rolesFor([''], noAdmin).size).toBe(0);
  });
});
