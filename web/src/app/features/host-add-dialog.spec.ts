import { TestBed } from '@angular/core/testing';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { of } from 'rxjs';
import { describe, expect, it } from 'vitest';

import { Api } from '../api/api';
import { AgentManifest, EnrollTokenResponse } from '../api/models';
import { HostAddDialog, maskToken, twoStepCommands, withArch } from './host-add-dialog';
import { pinErrorText, rolloutMissingText } from './hosts';

const COMMAND =
  'curl -fsSL https://gssh.example.com/install.sh | sudo sh -s -- --token gssh-et-abcdefgh1234';

describe('Host-hinzufügen-Dialog', () => {
  it('maskToken zeigt nur Prefix und die letzten vier Zeichen', () => {
    const masked = maskToken('gssh-et-abcdefgh1234');
    expect(masked.startsWith('gssh-et-')).toBe(true);
    expect(masked.endsWith('1234')).toBe(true);
    expect(masked).not.toContain('abcdefgh');
  });

  it('withArch hängt die Auswahl an, „auto“ lässt den Befehl unverändert', () => {
    expect(withArch(COMMAND, '')).toBe(COMMAND);
    expect(withArch(COMMAND, 'arm64')).toBe(`${COMMAND} --arch arm64`);
  });

  it('twoStepCommands baut die Variante ohne curl | sh mit gleichen Flags', () => {
    const lines = twoStepCommands(`${COMMAND} --session-audit`).split('\n');
    expect(lines[0]).toBe('curl -fsSLO https://gssh.example.com/install.sh');
    expect(lines[2]).toBe('sudo sh install.sh --token gssh-et-abcdefgh1234 --session-audit');
  });

  it('rolloutMissingText übersetzt die Gate-Bedingungen in Klartext', () => {
    const text = rolloutMissingText(['pin', 'agent_public_url']);
    expect(text).toContain('SPKI-Pin');
    expect(text).toContain('GSSH_AGENT_PUBLIC_URL');
    expect(rolloutMissingText(['unbekannt'])).toBe('unbekannt');
  });

  it('pinErrorText übersetzt die Fehlerkategorie und verweist aufs Server-Log', () => {
    expect(pinErrorText('')).toBe('');
    const text = pinErrorText('chain_untrusted');
    expect(text).toContain('nicht vertrauenswürdig');
    expect(text).toContain('Server-Log');
    expect(pinErrorText('unbekannt')).toContain('unbekannt');
  });

  it('mintet und zeigt Token maskiert, Befehl folgt der Arch-Auswahl', async () => {
    const manifest: AgentManifest = {
      version: '1.2.3',
      rollout_ready: true,
      missing: [],
      pin_source: 'static',
      pin_error: '',
      agents: [{ os: 'linux', arch: 'amd64', size: 14_800_000, sha256: 'a'.repeat(64) }],
    };
    const minted: EnrollTokenResponse = {
      token: 'gssh-et-abcdefgh1234',
      expires_at: '2026-07-25T13:37:00Z',
      install_command: COMMAND,
    };
    let sentBody: unknown;
    TestBed.configureTestingModule({
      providers: [
        { provide: MAT_DIALOG_DATA, useValue: manifest },
        { provide: MatDialogRef, useValue: { close: () => {} } },
        {
          provide: Api,
          useValue: {
            invoke: (_fn: unknown, params: { body: unknown }) => {
              sentBody = params.body;
              return Promise.resolve(minted);
            },
          },
        },
      ],
    });
    const fixture = TestBed.createComponent(HostAddDialog);
    const dialog = fixture.componentInstance as unknown as {
      tags: string;
      sessionAudit: boolean;
      arch: string;
      mint(): void;
      installLine(): string;
    };
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Session-Audit');

    dialog.tags = 'env=prod';
    dialog.sessionAudit = true;
    dialog.mint();
    await fixture.whenStable();
    fixture.detectChanges();

    expect(sentBody).toEqual({
      hostname: undefined,
      tags: { env: 'prod' },
      ttl_seconds: 3600,
      session_audit: true,
    });
    // Das Token-Feld zeigt nur die maskierte Form; im Install-Befehl steht der
    // Klartext bewusst (ohne ihn ist der Befehl nicht ausführbar).
    const rendered = fixture.nativeElement.textContent as string;
    expect(rendered).toContain(maskToken(minted.token));
    expect(rendered).toContain(COMMAND);
    expect(rendered).toContain('14,8 MB');

    dialog.arch = 'amd64';
    expect(dialog.installLine()).toBe(`${COMMAND} --arch amd64`);
  });
});
