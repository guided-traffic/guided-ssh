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
  ipConnectCommand,
} from './host-connect-dialog';
import { HostsPage } from './hosts';

const HOST: Host = {
  id: '0b7f5f2e-9f2a-4c9e-8a3d-1f2e3d4c5b6a',
  name: 'web-01.prod.example.com',
  tags: {},
  created_at: '2026-01-01T00:00:00Z',
  enrolled_at: '2026-01-01T00:00:00Z',
  last_seen_addr: '10.20.30.40',
};

const MANIFEST: ClientManifest = {
  version: 'v2.3.0',
  ready: true,
  missing: [],
  pin: '',
  pin_source: 'dial',
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

  it('ipConnectCommand keeps host-cert verification via HostKeyAlias', () => {
    expect(ipConnectCommand(' 10.20.30.40 ', 'web-01')).toBe(
      'gssh ssh -o HostKeyAlias=web-01 10.20.30.40',
    );
    expect(ipConnectCommand('2001:db8::7', 'web-01')).toBe(
      'gssh ssh -o HostKeyAlias=web-01 2001:db8::7',
    );
  });

  it('ipConnectCommand is fail-closed: empty input, shell metacharacters, option injection', () => {
    expect(ipConnectCommand('', 'web-01')).toBe('');
    expect(ipConnectCommand('   ', 'web-01')).toBe('');
    expect(ipConnectCommand('10.0.0.1 ; rm -rf /', 'web-01')).toBe('');
    expect(ipConnectCommand('$(id)', 'web-01')).toBe('');
    // A leading dash would be parsed as an ssh option — the charset has no dash.
    expect(ipConnectCommand('-oProxyCommand=evil', 'web-01')).toBe('');
  });

  it('renders install, connect, and the IP fallback that follows the input', async () => {
    const fixture = createDialog(MANIFEST);
    fixture.detectChanges();
    await fixture.whenStable();

    const rendered = () => fixture.nativeElement.textContent as string;
    expect(rendered()).toContain('One-time setup');
    expect(rendered()).toContain('client.sh | sh');
    expect(rendered()).toContain('gssh ssh web-01.prod.example.com');
    expect(rendered()).toContain('DNS fallback');
    // No IP entered yet ⇒ no command, only the prompt to enter one. (The
    // explanatory hint mentions HostKeyAlias — check for the option syntax.)
    expect(rendered()).not.toContain('-o HostKeyAlias=');

    const dialog = fixture.componentInstance as unknown as { ip: string };
    dialog.ip = '10.20.30.40';
    fixture.detectChanges();
    await fixture.whenStable();

    expect(rendered()).toContain(
      'gssh ssh -o HostKeyAlias=web-01.prod.example.com 10.20.30.40',
    );
  });

  it('offers the last-seen address as a click-to-fill suggestion', async () => {
    const fixture = createDialog(MANIFEST);
    fixture.detectChanges();
    await fixture.whenStable();

    const rendered = () => fixture.nativeElement.textContent as string;
    expect(rendered()).toContain('Agent last connected from');
    expect(rendered()).toContain('10.20.30.40');
    // Suggestion alone renders no command — only the click fills the input.
    expect(rendered()).not.toContain('-o HostKeyAlias=');

    (fixture.nativeElement.querySelector('.addr-suggest') as HTMLButtonElement).click();
    fixture.detectChanges();
    await fixture.whenStable();

    expect((fixture.componentInstance as unknown as { ip: string }).ip).toBe('10.20.30.40');
    expect(rendered()).toContain(
      'gssh ssh -o HostKeyAlias=web-01.prod.example.com 10.20.30.40',
    );
  });

  it('shows no suggestion for a host without a recorded address', async () => {
    const data: HostConnectData = {
      host: { ...HOST, last_seen_addr: null },
      manifest: MANIFEST,
    };
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        { provide: MAT_DIALOG_DATA, useValue: data },
        { provide: MatDialogRef, useValue: { close: () => {} } },
      ],
    });
    const fixture = TestBed.createComponent(HostConnectDialog);
    fixture.detectChanges();
    await fixture.whenStable();

    expect(fixture.nativeElement.textContent).not.toContain('Agent last connected from');
  });

  it('keeps connect and IP fallback when the client manifest is unavailable', async () => {
    const fixture = createDialog(null);
    fixture.detectChanges();
    await fixture.whenStable();

    const rendered = fixture.nativeElement.textContent as string;
    expect(rendered).toContain('could not be loaded');
    expect(rendered).toContain('gssh ssh web-01.prod.example.com');
    expect(rendered).toContain('DNS fallback');
  });
});

describe('Hosts page connect action', () => {
  const unenrolled: Host = {
    ...HOST,
    id: 'ffffffff-0000-0000-0000-000000000000',
    name: 'edge-02',
    enrolled_at: null,
  };

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
        {
          provide: SessionService,
          useValue: { isAdmin: signal(false), isAuditor: signal(false) },
        },
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
