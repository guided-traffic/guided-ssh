import { Clipboard } from '@angular/cdk/clipboard';
import { Component, Inject, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSnackBar } from '@angular/material/snack-bar';
import { RouterLink } from '@angular/router';

import { ClientManifest, Host } from '../api/models';
import { installCommand } from './client-setup';

/** Dialog input: the host to connect to plus the client manifest (may be null
 * when the manifest request failed — the connect line still works). */
export interface HostConnectData {
  host: Host;
  manifest: ClientManifest | null;
}

/**
 * IP charset for the DNS-fallback input: IPv4 or IPv6, nothing else.
 * Deliberately strict — the rendered line is copied into a shell, and a value
 * with spaces, quotes, or option-like dashes has no business in it. A port
 * does not belong here either: ssh takes it as `-p`, appended by the user.
 */
const IP_PATTERN = /^[0-9A-Fa-f.:]+$/;

/** connectCommand is the connect line for a host. */
export function connectCommand(hostName: string): string {
  return `gssh ssh ${hostName}`;
}

/**
 * ipConnectCommand renders the connect line for a host without a DNS entry:
 * connect to the IP while `HostKeyAlias` keeps the host-certificate check
 * against the enrolled name (its cert principals are the full and short
 * hostname, not the IP) — verification stays fully intact, nothing is
 * skipped. Empty without a usable IP.
 */
export function ipConnectCommand(ip: string, hostName: string): string {
  const target = ip.trim();
  if (!target || !IP_PATTERN.test(target)) {
    return '';
  }
  return `gssh ssh -o HostKeyAlias=${hostName} ${target}`;
}

@Component({
  selector: 'app-host-connect-dialog',
  imports: [
    FormsModule,
    RouterLink,
    MatDialogModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatIconModule,
  ],
  template: `
    <h2 mat-dialog-title>Connect to {{ data.host.name }}</h2>
    <mat-dialog-content>
      <div class="dialog-form">
        <details>
          <summary>One-time setup: install the client</summary>
          @if (manifest?.ready) {
            <div class="copy-row">
              <code class="mono grow wrap">{{ installLine() }}</code>
              <button
                mat-icon-button
                aria-label="Copy install command"
                (click)="copy(installLine(), 'Command')"
              >
                <mat-icon svgIcon="copy" />
              </button>
            </div>
          } @else if (manifest) {
            <div class="hint-text">The client install is not configured on this server.</div>
          } @else {
            <div class="hint-text">The client manifest could not be loaded.</div>
          }
          <div class="hint-text dim">
            Details, direct downloads, and the manual configuration:
            <a routerLink="/client" mat-dialog-close>Client setup</a>
          </div>
        </details>

        <label class="field-label">Connect</label>
        <div class="copy-row">
          <code class="mono grow wrap">{{ connectLine() }}</code>
          <button
            mat-icon-button
            aria-label="Copy connect command"
            (click)="copy(connectLine(), 'Command')"
          >
            <mat-icon svgIcon="copy" />
          </button>
        </div>
        <div class="hint-text dim">
          Whether you may enter this host is decided at sign time by the access rules —
          this dialog does not pre-check it.
        </div>

        <details>
          <summary>DNS fallback: connect via IP</summary>
          <div class="hint-text dim">
            For a host without a (working) DNS entry: connect to its IP address while
            <code>HostKeyAlias</code> keeps the host-certificate check against the
            enrolled name — verification stays fully intact, nothing is skipped.
          </div>
          <mat-form-field appearance="outline">
            <mat-label>Host IP address</mat-label>
            <input matInput [(ngModel)]="ip" placeholder="10.20.30.40" />
            <mat-hint>the target host's address, as reachable from your machine</mat-hint>
          </mat-form-field>
          @if (ipLine(); as line) {
            <div class="copy-row">
              <code class="mono grow wrap">{{ line }}</code>
              <button
                mat-icon-button
                aria-label="Copy IP connect command"
                (click)="copy(line, 'Command')"
              >
                <mat-icon svgIcon="copy" />
              </button>
            </div>
          } @else {
            <div class="hint-text dim">Enter an IP address to render the command.</div>
          }
        </details>
      </div>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-flat-button mat-dialog-close>Done</button>
    </mat-dialog-actions>
  `,
  styles: `
    .dialog-form {
      padding-top: 8px;
      min-width: 460px;
      max-width: 620px;
    }
    .field-label {
      display: block;
      font-size: 12px;
      color: var(--text-dim);
      margin: 16px 0 4px;
    }
    .copy-row {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .copy-row .grow {
      flex: 1;
      min-width: 0;
      padding: 8px 10px;
      border: 1px solid var(--hairline);
      border-radius: 6px;
      font-size: 12px;
      margin: 0;
    }
    .wrap {
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    .hint-text {
      font-size: 12px;
      line-height: 1.45;
      margin: 6px 0 8px;
    }
    details {
      margin-top: 12px;
      font-size: 13px;
    }
    details summary {
      cursor: pointer;
      color: var(--text-dim);
      margin-bottom: 8px;
    }
    mat-form-field {
      width: 100%;
    }
  `,
})
export class HostConnectDialog {
  private readonly clipboard = inject(Clipboard);
  private readonly snackBar = inject(MatSnackBar);

  /**
   * User-entered target IP — the server does not know it: hosts are stored
   * without an address, and the agent's observed egress IP would not be the
   * sshd address behind NAT anyway. Never guessed (ticket D3 "Do not").
   */
  protected ip = '';

  constructor(@Inject(MAT_DIALOG_DATA) protected readonly data: HostConnectData) {}

  protected get manifest(): ClientManifest | null {
    return this.data.manifest;
  }

  installLine(): string {
    return installCommand(window.location.origin);
  }

  connectLine(): string {
    return connectCommand(this.data.host.name);
  }

  ipLine(): string {
    return ipConnectCommand(this.ip, this.data.host.name);
  }

  copy(text: string, what: string): void {
    const ok = this.clipboard.copy(text);
    this.snackBar.open(ok ? `${what} copied` : `Failed to copy ${what.toLowerCase()}`, 'OK', {
      duration: 3000,
    });
  }
}
