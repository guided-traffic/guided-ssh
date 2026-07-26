import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { MAT_DIALOG_DATA, MatDialog, MatDialogRef } from '@angular/material/dialog';
import { provideRouter } from '@angular/router';
import { describe, expect, it } from 'vitest';

import { Api } from '../api/api';
import { ClientManifest, Host } from '../api/models';
import { SessionService } from '../core/session.service';
import {
  HostConnectDialog,
  HostConnectData,
  connectCommand,
  ipLoginCommands,
  pinFallbackHint,
} from './host-connect-dialog';
import { HostsPage } from './hosts';

const PIN = '9nPmyRTjBQvKfBpB9OiE9YEfR9dPbGVoBSSlYqAr4X0=';

const HOST: Host = {
  id: '0b7f5f2e-9f2a-4c9e-8a3d-1f2e3d4c5b6a',
  name: 'web-01.prod.example.com',
  tags: {},
  created_at: '2026-01-01T00:00:00Z',
  enrolled_at: '2026-01-01T00:00:00Z',
};

const MANIFEST: ClientManifest = {
  version: 'v2.3.0',
  ready: true,
  missing: [],
  pin: PIN,
  pin_source: 'static',
  clients: [{ os: 'linux', arch: 'amd64', size: 8_599_040, sha256: 'a'.repeat(64) }],
};

function createDialog(manifest: ClientManifest | null) {
  const data: HostConnectData = { host: HOST, manifest };
  TestBed.configureTestingModule({
    providers: [
      provideRouter([]),
      { provide: MAT_DIALOG_DATA, useValue: data },
      { provide: MatDialogRef, useValue: { close: () => {} } },
    ],
  });
  return TestBed.createComponent(HostConnectDialog);
}

describe('Host connect dialog', () => {
  it('connectCommand names the host', () => {
    expect(connectCommand('web-01')).toBe('gssh ssh web-01');
  });

  it('ipLoginCommands pairs the IP override with the pin and the connect line', () => {
    const lines = ipLoginCommands(' 203.0.113.7 ', PIN, 'web-01').split('\n');
    expect(lines[0]).toBe(`gssh login --api-url https://203.0.113.7 --pin-sha256 ${PIN}`);
    expect(lines[1]).toBe('gssh ssh web-01');
    expect(ipLoginCommands('203.0.113.7:8443', PIN, 'web-01')).toContain(
      'https://203.0.113.7:8443',
    );
  });

  it('ipLoginCommands is fail-closed: no pin, no IP, no shell metacharacters', () => {
    expect(ipLoginCommands('203.0.113.7', '', 'web-01')).toBe('');
    expect(ipLoginCommands('   ', PIN, 'web-01')).toBe('');
    expect(ipLoginCommands('203.0.113.7 ; rm -rf /', PIN, 'web-01')).toBe('');
    expect(ipLoginCommands('$(id)', PIN, 'web-01')).toBe('');
  });

  it('pinFallbackHint explains the dial source and the missing source separately', () => {
    expect(pinFallbackHint('dial')).toContain('auto-derived');
    expect(pinFallbackHint('dial')).toContain('GSSH_PUBLIC_PIN');
    expect(pinFallbackHint('')).toContain('No pin source configured');
    expect(pinFallbackHint('mystery')).toContain('mystery');
  });

  it('renders install, connect, and the pinned IP fallback that follows the input', async () => {
    const fixture = createDialog(MANIFEST);
    fixture.detectChanges();
    await fixture.whenStable();

    const rendered = () => fixture.nativeElement.textContent as string;
    expect(rendered()).toContain('One-time setup');
    expect(rendered()).toContain('client.sh | sh');
    expect(rendered()).toContain('gssh ssh web-01.prod.example.com');
    expect(rendered()).toContain('DNS fallback');
    // No IP entered yet ⇒ no command, only the prompt to enter one.
    expect(rendered()).not.toContain('--pin-sha256');

    const dialog = fixture.componentInstance as unknown as { ip: string };
    dialog.ip = '203.0.113.7';
    fixture.detectChanges();
    await fixture.whenStable();

    expect(rendered()).toContain(
      `gssh login --api-url https://203.0.113.7 --pin-sha256 ${PIN}`,
    );
  });

  it('without an offered pin it explains the gap and renders no command', async () => {
    const fixture = createDialog({ ...MANIFEST, pin: '', pin_source: 'dial' });
    fixture.detectChanges();
    await fixture.whenStable();

    const rendered = fixture.nativeElement.textContent as string;
    expect(rendered).toContain('Not available');
    expect(rendered).toContain('auto-derived');
    expect(rendered).not.toContain('--pin-sha256');
    expect(rendered).not.toContain('--api-url');
    // The connect line is independent of the pin and stays.
    expect(rendered).toContain('gssh ssh web-01.prod.example.com');
  });

  it('keeps the connect line when the client manifest is unavailable', async () => {
    const fixture = createDialog(null);
    fixture.detectChanges();
    await fixture.whenStable();

    const rendered = fixture.nativeElement.textContent as string;
    expect(rendered).toContain('could not be loaded');
    expect(rendered).toContain('gssh ssh web-01.prod.example.com');
    expect(rendered).not.toContain('--pin-sha256');
  });
});

describe('Hosts page connect action', () => {
  const unenrolled: Host = { ...HOST, id: 'ffffffff-0000-0000-0000-000000000000', name: 'edge-02', enrolled_at: null };

  /** Hosts page with two hosts (one enrolled, one not) and a recording dialog. */
  async function createHostsPage() {
    const opened: unknown[] = [];
    TestBed.configureTestingModule({
      providers: [
        {
          provide: Api,
          useValue: {
            invoke: (fn: { PATH?: string }) =>
              fn.PATH === '/v1/clients'
                ? Promise.resolve(MANIFEST)
                : Promise.resolve([HOST, unenrolled]),
          },
        },
        { provide: MatDialog, useValue: { open: (...args: unknown[]) => opened.push(args) } },
        { provide: SessionService, useValue: { isAdmin: signal(false), isAuditor: signal(false) } },
      ],
    });
    const fixture = TestBed.createComponent(HostsPage);
    fixture.detectChanges();
    // Macrotask tick: the page's API calls are plain promises, not tracked tasks.
    await new Promise((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
    return { fixture, opened };
  }

  it('offers Connect per row and disables it for hosts that are not enrolled', async () => {
    const { fixture } = await createHostsPage();
    const buttons = Array.from(
      fixture.nativeElement.querySelectorAll(
        'button[aria-label^="Connect to"]',
      ) as NodeListOf<HTMLButtonElement>,
    );
    expect(buttons.map((b) => b.getAttribute('aria-label'))).toEqual([
      `Connect to ${HOST.name}`,
      'Connect to edge-02',
    ]);
    expect(buttons[0].disabled).toBe(false);
    expect(buttons[1].disabled).toBe(true);
  });

  it('opens the dialog with the host and the client manifest', async () => {
    const { fixture, opened } = await createHostsPage();
    const page = fixture.componentInstance as unknown as { connect(host: Host): void };

    page.connect(unenrolled);
    expect(opened).toHaveLength(0);

    page.connect(HOST);
    expect(opened).toHaveLength(1);
    const [component, config] = opened[0] as [unknown, { data: HostConnectData }];
    expect(component).toBe(HostConnectDialog);
    expect(config.data).toEqual({ host: HOST, manifest: MANIFEST });
  });
});
