import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { describe, expect, it } from 'vitest';

import { Api } from '../api/api';
import { Grant, UiConfig } from '../api/models';
import { SessionService } from '../core/session.service';
import { GrantsPage } from './grants';

const UI_CONFIG: UiConfig = {
  oidc_issuer: 'https://idp.example.com/realms/acme',
  oidc_client_id: 'gssh-cli',
  admin_group: 'ssh-admins',
  auditor_group: 'ssh-auditors',
  grants_editable: true,
  ci_grants_editable: true,
};

const GRANTS: Grant[] = [
  {
    id: '0b7f5f2e-9f2a-4c9e-8a3d-1f2e3d4c5b6a',
    group: 'deployers',
    issuer: 'https://idp.example.com/realms/acme',
    tag_selector: { env: 'prod' },
    principals: ['deploy'],
    sudo: false,
    max_validity_seconds: 28_800,
    created_at: '2026-07-01T10:00:00Z',
    updated_at: '2026-07-01T10:00:00Z',
  },
];

/** Renders the page as an admin with the given editability flag. */
async function render(grantsEditable: boolean): Promise<ComponentFixture<GrantsPage>> {
  TestBed.configureTestingModule({
    providers: [
      provideNoopAnimations(),
      {
        provide: Api,
        useValue: {
          invoke: (fn: { PATH?: string }) =>
            fn.PATH === '/v1/ui/config'
              ? Promise.resolve({ ...UI_CONFIG, grants_editable: grantsEditable })
              : Promise.resolve(GRANTS),
        },
      },
      { provide: SessionService, useValue: { isAdmin: () => true } },
    ],
  });
  const fixture = TestBed.createComponent(GrantsPage);
  fixture.detectChanges();
  await new Promise((resolve) => setTimeout(resolve, 0));
  fixture.detectChanges();
  return fixture;
}

/** Text of all buttons — the editable state shows up as Add/Edit/Delete. */
function actions(fixture: ComponentFixture<GrantsPage>): string[] {
  return Array.from(fixture.nativeElement.querySelectorAll('button') as NodeListOf<HTMLElement>).map(
    (button) => (button.getAttribute('aria-label') ?? button.textContent ?? '').trim(),
  );
}

describe('Access rules page', () => {
  it('offers editing for admins when the server allows in-app rule writes', async () => {
    const fixture = await render(true);

    expect(actions(fixture)).toContain('Edit');
    expect(actions(fixture)).toContain('Delete');
    expect(fixture.nativeElement.textContent).toContain('New Rule');
    expect(fixture.nativeElement.textContent).not.toContain('managed declaratively');
  });

  it('hides every write action and explains why when the rules are GitOps-owned', async () => {
    const fixture = await render(false);

    expect(actions(fixture)).not.toContain('Edit');
    expect(actions(fixture)).not.toContain('Delete');
    expect(fixture.nativeElement.textContent).not.toContain('New Rule');
    expect(fixture.nativeElement.textContent).toContain(
      'Rules are managed declaratively (GitOps) — in-app editing is disabled.',
    );
    // The list itself stays readable — the page is read-only, not hidden.
    expect(fixture.nativeElement.textContent).toContain('deployers');
  });
});
