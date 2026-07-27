import { ComponentFixture, TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';

import { Api } from '../api/api';
import { ClientManifest, UiConfig } from '../api/models';
import {
  ClientSetupPage,
  clientMissingText,
  installCommand,
  manualConfig,
  twoStepCommands,
} from './client-setup';

const BASE = 'https://gssh.example.com';

const UI_CONFIG: UiConfig = {
  oidc_issuer: 'https://idp.example.com/realms/acme',
  oidc_client_id: 'gssh-cli',
  admin_group: 'ssh-admins',
  auditor_group: 'ssh-auditors',
  grants_editable: true,
  ci_grants_editable: true,
};

const READY: ClientManifest = {
  version: 'v2.3.0',
  ready: true,
  missing: [],
  pin: '',
  pin_source: 'dial',
  clients: [
    { os: 'linux', arch: 'amd64', size: 8_599_040, sha256: 'a'.repeat(64) },
    { os: 'darwin', arch: 'arm64', size: 8_178_432, sha256: 'b'.repeat(64) },
  ],
};

/**
 * render creates the page and lets the (plain-promise) API calls settle — a
 * macrotask tick drains the microtask queue the component's Promise.all uses.
 */
async function render(manifest: ClientManifest | null): Promise<ComponentFixture<ClientSetupPage>> {
  setup(manifest);
  const fixture = TestBed.createComponent(ClientSetupPage);
  fixture.detectChanges();
  await new Promise((resolve) => setTimeout(resolve, 0));
  fixture.detectChanges();
  return fixture;
}

/** Provides the page with fixed manifest/ui-config answers. */
function setup(manifest: ClientManifest | null): void {
  TestBed.configureTestingModule({
    providers: [
      {
        provide: Api,
        useValue: {
          invoke: (fn: { PATH?: string }) =>
            fn.PATH === '/v1/clients'
              ? manifest === null
                ? Promise.reject(new Error('unavailable'))
                : Promise.resolve(manifest)
              : Promise.resolve(UI_CONFIG),
        },
      },
    ],
  });
}

describe('Client setup page', () => {
  it('installCommand is the documented one-liner', () => {
    expect(installCommand(BASE)).toBe('curl -fsSL https://gssh.example.com/client.sh | sh');
  });

  it('twoStepCommands offers the same install without piping into a shell', () => {
    const lines = twoStepCommands(BASE).split('\n');
    expect(lines[0]).toBe('curl -fsSLO https://gssh.example.com/client.sh');
    expect(lines[2]).toBe('sh client.sh');
    expect(twoStepCommands(BASE)).not.toContain('| sh');
    expect(twoStepCommands(BASE)).not.toContain('sudo');
  });

  it('manualConfig renders the three keys and never a pin', () => {
    const config = manualConfig(BASE, UI_CONFIG);
    expect(config).toContain('api_url: "https://gssh.example.com"');
    expect(config).toContain('issuer: "https://idp.example.com/realms/acme"');
    expect(config).toContain('client_id: "gssh-cli"');
    expect(config).not.toContain('pin_sha256');
  });

  it('manualConfig stays empty without issuer or client ID (no half config to copy)', () => {
    expect(manualConfig(BASE, null)).toBe('');
    expect(manualConfig(BASE, { ...UI_CONFIG, oidc_client_id: '' })).toBe('');
  });

  it('clientMissingText translates the gate conditions into plain text', () => {
    const text = clientMissingText(['binaries', 'oidc_client_id']);
    expect(text).toContain('client binaries');
    expect(text).toContain('OIDC client ID');
    expect(clientMissingText(['unknown-key'])).toBe('unknown-key');
  });

  it('renders the three steps, the downloads, and the manual configuration', async () => {
    const fixture = await render(READY);

    const rendered = fixture.nativeElement.textContent as string;
    expect(rendered).toContain(installCommand(window.location.origin));
    expect(rendered).toContain('gssh login');
    expect(rendered).toContain('gssh ssh <host>');
    expect(rendered).toContain('linux/amd64');
    expect(rendered).toContain('darwin/arm64');
    expect(rendered).toContain('a'.repeat(64));
    expect(rendered).toContain('8.6 MB');
    expect(rendered).toContain(`issuer: "${UI_CONFIG.oidc_issuer}"`);

    const links = Array.from(
      fixture.nativeElement.querySelectorAll('a[download]') as NodeListOf<HTMLAnchorElement>,
    ).map((a) => a.getAttribute('href'));
    expect(links).toEqual(['/v1/clients/linux/amd64', '/v1/clients/darwin/arm64']);
  });

  it('shows the missing conditions instead of the instructions when the gate is closed', async () => {
    const fixture = await render({
      ...READY,
      ready: false,
      missing: ['binaries', 'public_url_https'],
      clients: [],
    });

    const rendered = fixture.nativeElement.textContent as string;
    expect(rendered).toContain('Client install not configured');
    expect(rendered).toContain('Server build without client binaries');
    expect(rendered).toContain('not an https URL');
    expect(rendered).not.toContain('client.sh | sh');
  });

  it('reports a failed manifest request instead of showing a broken install', async () => {
    const fixture = await render(null);

    const rendered = fixture.nativeElement.textContent as string;
    expect(rendered).toContain('could not be loaded');
    expect(rendered).not.toContain('client.sh | sh');
  });
});
