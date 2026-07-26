import { Component, Inject, inject, signal } from '@angular/core';
import { Clipboard } from '@angular/cdk/clipboard';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MAT_DIALOG_DATA, MatDialogModule } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar } from '@angular/material/snack-bar';

import { Api } from '../api/api';
import { createEnrollToken } from '../api/functions';
import { AgentManifest, EnrollTokenResponse } from '../api/models';
import { formatBytes, formatTimestamp, textToTags } from '../core/format';

/** Selectable token lifetimes; default 1 h (see server default). */
export const TTL_OPTIONS: Array<{ seconds: number; label: string }> = [
  { seconds: 900, label: '15 min' },
  { seconds: 3600, label: '1 h' },
  { seconds: 14400, label: '4 h' },
  { seconds: 86400, label: '24 h' },
];

/**
 * maskToken hides the token's plaintext in the display: the prefix and the
 * last four characters stay visible (enough to recognize it), the rest does
 * not. The full plaintext only reaches the clipboard via the copy button.
 */
export function maskToken(token: string): string {
  const prefix = 'gssh-et-';
  const body = token.startsWith(prefix) ? token.slice(prefix.length) : token;
  if (body.length <= 4) {
    return token;
  }
  return `${token.startsWith(prefix) ? prefix : ''}${'•'.repeat(8)}${body.slice(-4)}`;
}

/**
 * withArch appends the arch selection to the install command. An empty
 * selection means "auto": the script then detects the architecture itself.
 */
export function withArch(command: string, arch: string): string {
  return arch === '' ? command : `${command} --arch ${arch}`;
}

/**
 * twoStepCommands splits the pipe-to-shell command into the variant without
 * `curl | sh`: download, review, run. Same URL, same flags.
 */
export function twoStepCommands(command: string): string {
  const url = command.match(/https?:\/\/\S+\/install\.sh/)?.[0] ?? '';
  const sep = command.indexOf(' -- ');
  const args = sep < 0 ? '' : command.slice(sep + 4);
  return [
    `curl -fsSLO ${url}`,
    'less install.sh          # review',
    `sudo sh install.sh ${args}`.trimEnd(),
  ].join('\n');
}

@Component({
  selector: 'app-host-add-dialog',
  imports: [
    FormsModule,
    MatDialogModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    MatCheckboxModule,
    MatButtonModule,
    MatIconModule,
  ],
  template: `
    <h2 mat-dialog-title>Add Host</h2>
    <mat-dialog-content>
      @if (result(); as res) {
        <div class="dialog-form">
          <div class="pill warn">
            The token is shown only once, and the TTL is already running (valid until
            {{ formatTimestamp(res.expires_at) }}).
          </div>

          <label class="field-label">Enrollment token</label>
          <div class="copy-row">
            <code class="mono grow">{{ maskToken(res.token) }}</code>
            <button mat-icon-button aria-label="Copy token" (click)="copy(res.token, 'Token')">
              <mat-icon svgIcon="copy" />
            </button>
          </div>

          <mat-form-field appearance="outline">
            <mat-label>Architecture</mat-label>
            <mat-select [(ngModel)]="arch">
              <mat-option value="">auto (script detects)</mat-option>
              @for (agent of manifest.agents; track agent.os + agent.arch) {
                <mat-option [value]="agent.arch">{{ agent.os }}/{{ agent.arch }}</mat-option>
              }
            </mat-select>
          </mat-form-field>

          <label class="field-label">Run on the host</label>
          <div class="copy-row">
            <code class="mono grow wrap">{{ installLine() }}</code>
            <button
              mat-icon-button
              aria-label="Copy command"
              (click)="copy(installLine(), 'Command')"
            >
              <mat-icon svgIcon="copy" />
            </button>
          </div>

          <details>
            <summary>Without <code>curl | sh</code>: download, review, run</summary>
            <div class="copy-row">
              <pre class="mono grow wrap">{{ twoStep() }}</pre>
              <button
                mat-icon-button
                aria-label="Copy two-step variant"
                (click)="copy(twoStep(), 'Commands')"
              >
                <mat-icon svgIcon="copy" />
              </button>
            </div>
          </details>

          <details>
            <summary>Shipped agent binaries ({{ manifest.version }})</summary>
            <table class="agent-table mono">
              @for (agent of manifest.agents; track agent.os + agent.arch) {
                <tr>
                  <td>{{ agent.os }}/{{ agent.arch }}</td>
                  <td>{{ formatBytes(agent.size) }}</td>
                  <td class="dim">{{ agent.sha256 }}</td>
                </tr>
              }
            </table>
          </details>
        </div>
      } @else {
        <div class="dialog-form">
          <mat-form-field appearance="outline">
            <mat-label>Hostname (optional)</mat-label>
            <input matInput [(ngModel)]="hostname" placeholder="web-01" />
            <mat-hint>empty = token not bound to a hostname</mat-hint>
          </mat-form-field>
          <div class="dim hint-text">
            If set, the token is bound to exactly this name — it must exactly match the
            target host's <code>hostname</code> output (mind short name vs. FQDN),
            otherwise enrollment fails. The token remains unused in that case; a re-run
            with the corrected name will work.
          </div>
          <mat-form-field appearance="outline">
            <mat-label>Tags (key=value, …)</mat-label>
            <input matInput [(ngModel)]="tags" placeholder="env=prod, role=web" />
          </mat-form-field>
          <mat-form-field appearance="outline">
            <mat-label>Token validity</mat-label>
            <mat-select [(ngModel)]="ttlSeconds">
              @for (option of ttlOptions; track option.seconds) {
                <mat-option [value]="option.seconds">{{ option.label }}</mat-option>
              }
            </mat-select>
          </mat-form-field>
          <mat-checkbox [(ngModel)]="sessionAudit">Enable session audit</mat-checkbox>
          <div class="dim hint-text">
            The agent attaches <code>pam_exec</code> hooks to the PAM stacks of sshd and sudo
            (<code>/etc/pam.d/*</code>) and correlates sessions with certificates (sshd
            <code>LogLevel VERBOSE</code>). Reports session start/end and sudo actions to the
            platform. Changes the host's PAM configuration — hence opt-in.
          </div>
          @if (error()) {
            <div class="pill danger">{{ error() }}</div>
          }
        </div>
      }
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      @if (result()) {
        <button mat-flat-button mat-dialog-close>Done</button>
      } @else {
        <button mat-button mat-dialog-close>Cancel</button>
        <button mat-flat-button (click)="mint()" [disabled]="minting()">Generate Token</button>
      }
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
      margin: 12px 0 4px;
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
      margin: 4px 0 8px;
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
    .agent-table {
      font-size: 11px;
      border-collapse: collapse;
    }
    .agent-table td {
      padding: 2px 12px 2px 0;
      overflow-wrap: anywhere;
    }
  `,
})
export class HostAddDialog {
  private readonly api = inject(Api);
  private readonly clipboard = inject(Clipboard);
  private readonly snackBar = inject(MatSnackBar);

  protected readonly ttlOptions = TTL_OPTIONS;
  protected readonly maskToken = maskToken;
  protected readonly formatBytes = formatBytes;
  protected readonly formatTimestamp = formatTimestamp;

  protected hostname = '';
  protected tags = '';
  protected ttlSeconds = 3600;
  protected sessionAudit = false;
  /** Empty = "auto"; the script then detects the architecture itself. */
  protected arch = '';

  protected readonly minting = signal(false);
  protected readonly error = signal('');
  protected readonly result = signal<EnrollTokenResponse | null>(null);

  /** installLine is the command including the current arch selection. */
  installLine(): string {
    return withArch(this.result()?.install_command ?? '', this.arch);
  }

  twoStep(): string {
    return twoStepCommands(this.installLine());
  }

  constructor(@Inject(MAT_DIALOG_DATA) protected readonly manifest: AgentManifest) {}

  mint(): void {
    let parsedTags: Record<string, string>;
    try {
      parsedTags = textToTags(this.tags);
    } catch (err) {
      this.error.set(String(err instanceof Error ? err.message : err));
      return;
    }
    this.minting.set(true);
    this.error.set('');
    this.api
      .invoke(createEnrollToken, {
        body: {
          hostname: this.hostname.trim() || undefined,
          tags: Object.keys(parsedTags).length > 0 ? parsedTags : undefined,
          ttl_seconds: this.ttlSeconds,
          session_audit: this.sessionAudit,
        },
      })
      .then((res) => this.result.set(res))
      .catch(() => this.error.set('Failed to generate token'))
      .finally(() => this.minting.set(false));
  }

  copy(text: string, what: string): void {
    const ok = this.clipboard.copy(text);
    this.snackBar.open(ok ? `${what} copied` : `Failed to copy ${what.toLowerCase()}`, 'OK', {
      duration: 3000,
    });
  }
}
