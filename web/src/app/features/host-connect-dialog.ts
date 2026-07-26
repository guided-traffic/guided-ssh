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
 * Host/IP charset for the DNS-fallback input: IPv4, bracketed IPv6, optional
 * port. Deliberately strict — the rendered line is copied into a shell, and a
 * value with spaces or quotes has no business in it.
 */
const IP_PATTERN = /^[A-Za-z0-9.:[\]-]+$/;

/** connectCommand is the connect line for a host. */
export function connectCommand(hostName: string): string {
  return `gssh ssh ${hostName}`;
}

/**
 * ipLoginCommands renders the login-via-IP fallback. Fail-closed: without an
 * (operator-controlled) pin or without a usable IP it returns an empty string —
 * an unpinned IP login fails TLS verification and invites exactly the
 * verification-disabling workarounds this feature refuses to enable.
 */
export function ipLoginCommands(ip: string, pin: string, hostName: string): string {
  const target = ip.trim();
  if (!pin || !target || !IP_PATTERN.test(target)) {
    return '';
  }
  return [
    `gssh login --api-url https://${target} --pin-sha256 ${pin}`,
    connectCommand(hostName),
  ].join('\n');
}

/**
 * pinFallbackHint explains why no IP command is offered. `dial` is its own
 * case: that pin is auto-derived from the certificate the server currently
 * presents and rotates with it — as a stored anchor for a DNS outage it would
 * break at the worst moment, so the server never hands it out.
 */
export function pinFallbackHint(pinSource: string): string {
  if (pinSource === 'dial') {
    return (
      'The server pin is auto-derived (dial) and rotates with the certificate — ' +
      'the DNS fallback requires an operator-supplied pin (GSSH_PUBLIC_PIN or ' +
      'GSSH_PUBLIC_PIN_CERT_FILE).'
    );
  }
  if (pinSource === '') {
    return 'No pin source configured on the server (GSSH_PUBLIC_PIN or GSSH_PUBLIC_PIN_CERT_FILE).';
  }
  return `The server offers no pin for the source "${pinSource}".`;
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
          <summary>DNS fallback: log in via IP</summary>
          @if (pin) {
            <div class="hint-text dim">
              Bridges the client → API leg while DNS is down. The browser → IdP leg and
              the host name resolution keep their own DNS dependency; afterwards the
              signed certificate carries until it expires, so no further API contact is
              needed. The pin replaces chain <em>and</em> hostname verification — the
              connection stays fully verified.
            </div>
            <mat-form-field appearance="outline">
              <mat-label>Server IP address</mat-label>
              <input matInput [(ngModel)]="ip" placeholder="203.0.113.7" />
              <mat-hint>as reachable from your machine; port allowed (1.2.3.4:8443)</mat-hint>
            </mat-form-field>
            @if (ipLines(); as lines) {
              <div class="copy-row">
                <pre class="mono grow wrap">{{ lines }}</pre>
                <button
                  mat-icon-button
                  aria-label="Copy login commands"
                  (click)="copy(lines, 'Commands')"
                >
                  <mat-icon svgIcon="copy" />
                </button>
              </div>
            } @else {
              <div class="hint-text dim">Enter an IP address to render the command.</div>
            }
            <div class="hint-text dim">
              One-off: the configuration file is not touched. Permanently IP-based setups
              edit <code>api_url</code> and <code>pin_sha256</code> in
              <code>config.yaml</code>.
            </div>
          } @else {
            <div class="pill warn">Not available</div>
            <div class="hint-text">{{ fallbackHint() }}</div>
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

  /** User-entered IP — never derived: a guessed address is a silently wrong URL. */
  protected ip = '';

  constructor(@Inject(MAT_DIALOG_DATA) protected readonly data: HostConnectData) {}

  protected get manifest(): ClientManifest | null {
    return this.data.manifest;
  }

  /** Empty ⇒ no operator-controlled pin ⇒ no IP command anywhere in the UI. */
  protected get pin(): string {
    return this.data.manifest?.pin ?? '';
  }

  installLine(): string {
    return installCommand(window.location.origin);
  }

  connectLine(): string {
    return connectCommand(this.data.host.name);
  }

  ipLines(): string {
    return ipLoginCommands(this.ip, this.pin, this.data.host.name);
  }

  fallbackHint(): string {
    return pinFallbackHint(this.data.manifest?.pin_source ?? '');
  }

  copy(text: string, what: string): void {
    const ok = this.clipboard.copy(text);
    this.snackBar.open(ok ? `${what} copied` : `Failed to copy ${what.toLowerCase()}`, 'OK', {
      duration: 3000,
    });
  }
}
