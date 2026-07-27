import { Clipboard } from '@angular/cdk/clipboard';
import { Component, OnInit, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSnackBar } from '@angular/material/snack-bar';

import { Api } from '../api/api';
import { getClientManifest, getUiConfig } from '../api/functions';
import { ClientBinary, ClientManifest, UiConfig } from '../api/models';
import { formatBytes } from '../core/format';

/**
 * Plain-text explanations for the client gate's conditions (see
 * internal/api/clients.go). The page shows them instead of the instructions —
 * an install command that leads to a 503 would be worse than a clear reason.
 */
const CLIENT_MISSING_LABELS: Record<string, string> = {
  binaries: 'Server build without client binaries',
  public_url: 'GSSH_PUBLIC_URL is missing',
  public_url_https: 'GSSH_PUBLIC_URL is not an https URL',
  oidc_issuer: 'OIDC issuer is not configured',
  oidc_client_id: 'OIDC client ID is not configured',
};

/**
 * clientMissingText summarizes the missing conditions in readable form.
 * Unknown keys are passed through as-is (newer server, older UI).
 */
export function clientMissingText(missing: readonly string[]): string {
  return missing.map((key) => CLIENT_MISSING_LABELS[key] ?? key).join(' · ');
}

/** installCommand is the one-liner from the ticket's target UX. */
export function installCommand(baseUrl: string): string {
  return `curl -fsSL ${baseUrl}/client.sh | sh`;
}

/**
 * twoStepCommands splits the one-liner into the variant without
 * `curl | sh`: download, review, run — same URL, no pipe into a shell.
 */
export function twoStepCommands(baseUrl: string): string {
  return [
    `curl -fsSLO ${baseUrl}/client.sh`,
    'less client.sh          # review',
    'sh client.sh',
  ].join('\n');
}

/**
 * manualConfig renders the configuration the script would write — for a
 * manual install from the direct downloads. Deliberately without
 * `pin_sha256`: the client talks WebPKI by default (see the security model),
 * the pin is the `--pin` opt-in.
 *
 * Empty when issuer or client ID are unknown: `LoadConfig` requires all three
 * values, so a snippet with blanks would only produce a client that refuses
 * to start — the same fail-closed rule the server's script gate follows.
 */
export function manualConfig(baseUrl: string, config: UiConfig | null): string {
  if (!config?.oidc_issuer || !config.oidc_client_id) {
    return '';
  }
  return [
    `api_url: "${baseUrl}"`,
    `issuer: "${config.oidc_issuer}"`,
    `client_id: "${config.oidc_client_id}"`,
  ].join('\n');
}

@Component({
  selector: 'app-client-setup',
  imports: [MatButtonModule, MatIconModule, MatProgressSpinnerModule],
  template: `
    <div class="page">
      <div class="page-header">
        <div>
          <h1>Client setup</h1>
          <div class="page-sub">
            Install the <code>gssh</code> client and connect — no root, no token
          </div>
        </div>
        <button mat-stroked-button (click)="load()" [disabled]="loading()">
          <mat-icon svgIcon="refresh" />Refresh
        </button>
      </div>

      @if (loading()) {
        <div class="glass-panel empty-state"><mat-spinner diameter="28" /></div>
      } @else if (!manifest()) {
        <div class="glass-panel empty-state">Client manifest could not be loaded.</div>
      } @else if (manifest(); as m) {
        @if (!m.ready) {
          <div class="glass-panel section">
            <div class="pill warn">Client install not configured</div>
            <p class="hint-text">
              The server does not serve the client install right now:
              {{ clientMissingText(m.missing) }}.
            </p>
            <p class="hint-text dim">
              Until then the client can be installed from a release artifact and configured
              by hand — the values are the same as below.
            </p>
          </div>
        } @else {
          <div class="glass-panel section">
            <h2>1 &middot; Install</h2>
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
            <p class="hint-text dim">
              Installs <code>gssh {{ m.version }}</code> into <code>~/.local/bin</code> and
              writes <code>~/.config/guided-ssh/config.yaml</code> with this server's
              values — an existing configuration is replaced (kept as
              <code>config.yaml.bak</code>), so re-running the command is also how you
              switch environments.
            </p>

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

            <h2>2 &middot; Sign in</h2>
            <div class="copy-row">
              <code class="mono grow">gssh login</code>
              <button
                mat-icon-button
                aria-label="Copy login command"
                (click)="copy('gssh login', 'Command')"
              >
                <mat-icon svgIcon="copy" />
              </button>
            </div>
            <p class="hint-text dim">
              Opens the browser SSO. Access is granted here and nowhere else — the install
              itself confers nothing.
            </p>

            <h2>3 &middot; Connect</h2>
            <div class="copy-row">
              <code class="mono grow">gssh ssh &lt;host&gt;</code>
              <button
                mat-icon-button
                aria-label="Copy connect command"
                (click)="copy('gssh ssh <host>', 'Command')"
              >
                <mat-icon svgIcon="copy" />
              </button>
            </div>
            <p class="hint-text dim">
              The Hosts page has a per-host connect dialog with the ready-made command.
              Optional: <code>gssh integrate</code> prints a snippet for native
              <code>ssh</code>/<code>scp</code> and IDEs.
            </p>
          </div>

          <div class="glass-panel section">
            <h2>Direct downloads</h2>
            <p class="hint-text dim">
              Same binaries the script fetches, version {{ m.version }}. Verify with
              <code>sha256sum</code> (macOS: <code>shasum -a 256</code>), then
              <code>chmod +x</code> and move into your <code>PATH</code>.
            </p>
            <table class="client-table mono">
              @for (client of m.clients; track client.os + client.arch) {
                <tr>
                  <td>{{ client.os }}/{{ client.arch }}</td>
                  <td>{{ formatBytes(client.size) }}</td>
                  <td class="dim sha">{{ client.sha256 }}</td>
                  <td>
                    <button
                      mat-icon-button
                      [attr.aria-label]="'Copy SHA-256 for ' + client.os + '/' + client.arch"
                      (click)="copy(client.sha256, 'SHA-256')"
                    >
                      <mat-icon svgIcon="copy" />
                    </button>
                  </td>
                  <td>
                    <a
                      mat-icon-button
                      [href]="downloadUrl(client)"
                      [attr.aria-label]="'Download ' + client.os + '/' + client.arch"
                      download
                    >
                      <mat-icon svgIcon="download" />
                    </a>
                  </td>
                </tr>
              } @empty {
                <tr>
                  <td class="dim">No client binaries in this server build.</td>
                </tr>
              }
            </table>

            <h2>Manual configuration</h2>
            <p class="hint-text dim">
              For a manual install: write this to
              <code>~/.config/guided-ssh/config.yaml</code> (mode 0600).
            </p>
            @if (configSnippet(); as snippet) {
              <div class="copy-row">
                <pre class="mono grow wrap">{{ snippet }}</pre>
                <button
                  mat-icon-button
                  aria-label="Copy configuration"
                  (click)="copy(snippet, 'Configuration')"
                >
                  <mat-icon svgIcon="copy" />
                </button>
              </div>
            } @else {
              <div class="hint-text">
                The OIDC values could not be loaded — reload the page. The install script
                writes them itself; only the manual path needs them here.
              </div>
            }
          </div>
        }
      }
    </div>
  `,
  styles: `
    .section {
      padding: 20px 22px;
      margin-bottom: 16px;
    }
    .section h2 {
      font-size: 14px;
      font-weight: 600;
      margin: 20px 0 8px;
    }
    .section h2:first-of-type {
      margin-top: 4px;
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
      margin: 6px 0 0;
      max-width: 70ch;
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
    .client-table {
      font-size: 12px;
      border-collapse: collapse;
      width: 100%;
    }
    .client-table td {
      padding: 2px 12px 2px 0;
      overflow-wrap: anywhere;
    }
    .client-table .sha {
      font-size: 11px;
    }
  `,
})
export class ClientSetupPage implements OnInit {
  private readonly api = inject(Api);
  private readonly clipboard = inject(Clipboard);
  private readonly snackBar = inject(MatSnackBar);

  protected readonly manifest = signal<ClientManifest | null>(null);
  protected readonly uiConfig = signal<UiConfig | null>(null);
  protected readonly loading = signal(false);

  protected readonly formatBytes = formatBytes;
  protected readonly clientMissingText = clientMissingText;

  /**
   * The server's own origin — the UI is served by the API server, so this is
   * the URL the script and config need. Deliberately not derived from any
   * configured value: what the browser reached is what the client reaches.
   */
  protected readonly baseUrl = window.location.origin;

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    Promise.all([
      this.api.invoke(getClientManifest).catch(() => null),
      this.api.invoke(getUiConfig).catch(() => null),
    ])
      .then(([manifest, config]) => {
        this.manifest.set(manifest);
        this.uiConfig.set(config);
      })
      .finally(() => this.loading.set(false));
  }

  installLine(): string {
    return installCommand(this.baseUrl);
  }

  twoStep(): string {
    return twoStepCommands(this.baseUrl);
  }

  configSnippet(): string {
    return manualConfig(this.baseUrl, this.uiConfig());
  }

  downloadUrl(client: ClientBinary): string {
    return `/v1/clients/${client.os}/${client.arch}`;
  }

  copy(text: string, what: string): void {
    const ok = this.clipboard.copy(text);
    this.snackBar.open(ok ? `${what} copied` : `Failed to copy ${what.toLowerCase()}`, 'OK', {
      duration: 3000,
    });
  }
}
