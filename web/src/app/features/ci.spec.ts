import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { describe, expect, it } from 'vitest';

import { Api } from '../api/api';
import { CiGrant, ServiceAccount, UiConfig } from '../api/models';
import { SessionService } from '../core/session.service';
import { CiPage } from './ci';

const UI_CONFIG: UiConfig = {
  oidc_issuer: 'https://idp.example.com/realms/acme',
  oidc_client_id: 'gssh-cli',
  admin_group: 'ssh-admins',
  auditor_group: 'ssh-auditors',
  grants_editable: true,
  ci_grants_editable: true,
};

const CI_GRANTS: CiGrant[] = [
  {
    id: '3d5f1a2b-4c6d-4e8f-9a0b-1c2d3e4f5a6b',
    project: 'infra/ansible',
    ref_pattern: 'main',
    protected_only: true,
    tag_selector: { env: 'prod' },
    principals: ['deploy'],
    max_validity_seconds: 3_600,
    created_at: '2026-07-01T10:00:00Z',
    updated_at: '2026-07-01T10:00:00Z',
  },
];

const ACCOUNTS: ServiceAccount[] = [
  {
    id: '7c8d9e0f-1a2b-4c3d-8e5f-6a7b8c9d0e1f',
    name: 'infra/ansible',
    kind: 'gitlab-ci',
    issuer: 'https://gitlab.example.com',
    claim_matcher: {},
    active: true,
    created_at: '2026-07-01T10:00:00Z',
    updated_at: '2026-07-01T10:00:00Z',
  },
];

/** Renders the page as an admin with the given editability flag. */
async function render(ciGrantsEditable: boolean): Promise<ComponentFixture<CiPage>> {
  TestBed.configureTestingModule({
    providers: [
      provideNoopAnimations(),
      {
        provide: Api,
        useValue: {
          invoke: (fn: { PATH?: string }) => {
            switch (fn.PATH) {
              case '/v1/ui/config':
                return Promise.resolve({ ...UI_CONFIG, ci_grants_editable: ciGrantsEditable });
              case '/v1/admin/service-accounts':
                return Promise.resolve(ACCOUNTS);
              default:
                return Promise.resolve(CI_GRANTS);
            }
          },
        },
      },
      { provide: SessionService, useValue: { isAdmin: () => true } },
    ],
  });
  const fixture = TestBed.createComponent(CiPage);
  fixture.detectChanges();
  await new Promise((resolve) => setTimeout(resolve, 0));
  fixture.detectChanges();
  return fixture;
}

/** Text of all buttons — the editable state shows up as Add/Edit/Delete. */
function actions(fixture: ComponentFixture<CiPage>): string[] {
  return Array.from(fixture.nativeElement.querySelectorAll('button') as NodeListOf<HTMLElement>).map(
    (button) => (button.getAttribute('aria-label') ?? button.textContent ?? '').trim(),
  );
}

describe('CI page', () => {
  it('offers editing for admins when the server allows in-app rule writes', async () => {
    const fixture = await render(true);

    expect(actions(fixture)).toContain('Edit');
    expect(actions(fixture)).toContain('Delete');
    expect(fixture.nativeElement.textContent).toContain('New CI Rule');
    expect(fixture.nativeElement.textContent).not.toContain('managed declaratively');
  });

  it('hides every rule write and explains why when the CI rules are GitOps-owned', async () => {
    const fixture = await render(false);

    expect(actions(fixture)).not.toContain('Edit');
    expect(actions(fixture)).not.toContain('Delete');
    expect(fixture.nativeElement.textContent).not.toContain('New CI Rule');
    expect(fixture.nativeElement.textContent).toContain(
      'CI rules are managed declaratively (GitOps) — in-app editing is disabled.',
    );
    expect(fixture.nativeElement.textContent).toContain('infra/ansible');
  });

  // Service accounts are not part of the declarative rule files — the kill
  // switch is an incident control the server keeps accepting, so file
  // ownership of the CI rules must not hide it.
  it('keeps the service-account kill switch usable while rules are GitOps-owned', async () => {
    const fixture = await render(false);

    const tabs = fixture.nativeElement.querySelectorAll('[role="tab"]') as NodeListOf<HTMLElement>;
    tabs[1].click();
    fixture.detectChanges();
    await new Promise((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();

    const toggle = fixture.nativeElement.querySelector(
      'mat-slide-toggle button',
    ) as HTMLButtonElement | null;
    expect(toggle).not.toBeNull();
    expect(toggle?.disabled).toBe(false);
  });
});
