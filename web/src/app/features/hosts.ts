import { Component, OnInit, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';

import { Api } from '../api/api';
import { getAgentManifest, getClientManifest, listHosts } from '../api/functions';
import { AgentManifest, ClientManifest, Host } from '../api/models';
import { formatTimestamp, relativeTime } from '../core/format';
import { SessionService } from '../core/session.service';
import { HostAddDialog } from './host-add-dialog';
import { HostConnectDialog } from './host-connect-dialog';

const CERT_WARN_DAYS = 7;

/**
 * Plain-text explanations for the rollout gate's conditions (see internal/api/rollout.go).
 * The button is deliberately disabled rather than hidden — the operator
 * should be able to see why the one-command install isn't available right now.
 */
const ROLLOUT_MISSING_LABELS: Record<string, string> = {
  binaries: 'Server build without agent binaries',
  pin: 'SPKI pin not determined (GSSH_PUBLIC_PIN / cert file / self-dial)',
  agent_public_url: 'GSSH_AGENT_PUBLIC_URL is missing',
  public_url: 'GSSH_PUBLIC_URL is missing',
  agent_public_url_https: 'GSSH_AGENT_PUBLIC_URL is not an https URL',
  public_url_https: 'GSSH_PUBLIC_URL is not an https URL',
};

/**
 * Plain-text explanations for the manifest's pin error categories (`pin_error`, see
 * internal/api/pinprovider.go). The full error text is deliberately kept only in the
 * server log — only the category plus a pointer to where to look shows up here.
 */
const PIN_ERROR_LABELS: Record<string, string> = {
  no_public_url: 'no https public URL configured (or none at all)',
  chain_untrusted: 'certificate chain of the public URL is not trusted',
  dial_failed: 'self-dial to the public URL failed',
  cert_file_unreadable: 'pin certificate file is missing or unreadable',
};

/** rolloutMissingText summarizes the missing conditions in readable form. */
export function rolloutMissingText(missing: readonly string[]): string {
  return missing.map((key) => ROLLOUT_MISSING_LABELS[key] ?? key).join(' · ');
}

/**
 * pinErrorText translates the error category; empty if none is reported.
 * Unknown categories are passed through as-is (newer server, older UI).
 */
export function pinErrorText(pinError: string): string {
  if (!pinError) {
    return '';
  }
  return `${PIN_ERROR_LABELS[pinError] ?? pinError} (details: server log)`;
}

@Component({
  selector: 'app-hosts',
  imports: [
    MatTableModule,
    MatButtonModule,
    MatIconModule,
    MatProgressSpinnerModule,
    MatTooltipModule,
  ],
  template: `
    <div class="page">
      <div class="page-header">
        <div>
          <h1>Hosts</h1>
          <div class="page-sub">Managed hosts with tags, status, and certificate expiry</div>
        </div>
        <div>
          <button mat-stroked-button (click)="load()" [disabled]="loading()">
            <mat-icon svgIcon="refresh" />Refresh
          </button>
          @if (session.isAdmin()) {
            <button
              mat-flat-button
              style="margin-left: 8px"
              [disabled]="!manifest()?.rollout_ready"
              (click)="addHost()"
            >
              <mat-icon svgIcon="add" />Add Host
            </button>
            @if (manifest(); as m) {
              @if (!m.rollout_ready) {
                <div class="page-sub rollout-hint">
                  Host rollout not configured:
                  {{ rolloutMissingText(m.missing) }}
                  @if (pinErrorText(m.pin_error); as pinError) {
                    <div>Pin error: {{ pinError }}</div>
                  }
                </div>
              }
            }
          }
        </div>
      </div>

      <div class="glass-panel table-scroll">
        @if (loading()) {
          <div class="empty-state"><mat-spinner diameter="28" /></div>
        } @else if (hosts().length === 0) {
          <div class="empty-state">No hosts enrolled yet.</div>
        } @else {
          <table mat-table [dataSource]="hosts()">
            <ng-container matColumnDef="name">
              <th mat-header-cell *matHeaderCellDef>Host</th>
              <td mat-cell *matCellDef="let h" class="mono">{{ h.name }}</td>
            </ng-container>
            <ng-container matColumnDef="tags">
              <th mat-header-cell *matHeaderCellDef>Tags</th>
              <td mat-cell *matCellDef="let h">
                @for (tag of tagList(h); track tag) {
                  <span class="tag-chip">{{ tag }}</span>
                } @empty {
                  <span class="dim">—</span>
                }
              </td>
            </ng-container>
            <ng-container matColumnDef="seen">
              <th mat-header-cell *matHeaderCellDef>Last Seen</th>
              <td mat-cell *matCellDef="let h">
                <span [class]="'pill ' + seenClass(h)">{{ relativeTime(h.last_seen_at) }}</span>
              </td>
            </ng-container>
            <ng-container matColumnDef="cert">
              <th mat-header-cell *matHeaderCellDef>Host Certificate</th>
              <td mat-cell *matCellDef="let h">
                <span [class]="'pill ' + certClass(h)">{{ certLabel(h) }}</span>
              </td>
            </ng-container>
            <ng-container matColumnDef="enrolled">
              <th mat-header-cell *matHeaderCellDef>Enrolled</th>
              <td mat-cell *matCellDef="let h" class="dim">
                {{ formatTimestamp(h.enrolled_at) }}
              </td>
            </ng-container>
            <ng-container matColumnDef="actions">
              <th mat-header-cell *matHeaderCellDef class="actions-cell"></th>
              <td mat-cell *matCellDef="let h" class="actions-cell">
                <!-- The tooltip sits on the wrapper: a disabled button receives no
                     pointer events, and the reason is exactly what needs explaining. -->
                <span [matTooltip]="connectTooltip(h)">
                  <button
                    mat-icon-button
                    [disabled]="!h.enrolled_at"
                    [attr.aria-label]="'Connect to ' + h.name"
                    (click)="connect(h)"
                  >
                    <mat-icon svgIcon="terminal" />
                  </button>
                </span>
              </td>
            </ng-container>
            <tr mat-header-row *matHeaderRowDef="columns"></tr>
            <tr mat-row *matRowDef="let row; columns: columns"></tr>
          </table>
        }
      </div>
    </div>
  `,
  styles: `
    .rollout-hint {
      margin-top: 6px;
      max-width: 420px;
      text-align: right;
    }
    .actions-cell {
      width: 56px;
      text-align: right;
      padding-right: 8px;
    }
  `,
})
export class HostsPage implements OnInit {
  private readonly api = inject(Api);
  private readonly dialog = inject(MatDialog);
  protected readonly session = inject(SessionService);

  protected readonly columns = ['name', 'tags', 'seen', 'cert', 'enrolled', 'actions'];
  protected readonly hosts = signal<Host[]>([]);
  protected readonly loading = signal(false);
  /** Rollout manifest; null while it hasn't been loaded yet. */
  protected readonly manifest = signal<AgentManifest | null>(null);
  /**
   * Client manifest for the connect dialog (install one-liner, pin for the DNS
   * fallback). Loaded for every role — connecting is not an admin action.
   */
  protected readonly clientManifest = signal<ClientManifest | null>(null);

  protected readonly relativeTime = relativeTime;
  protected readonly formatTimestamp = formatTimestamp;
  protected readonly rolloutMissingText = rolloutMissingText;
  protected readonly pinErrorText = pinErrorText;

  ngOnInit(): void {
    this.load();
    this.api
      .invoke(getClientManifest)
      .then((manifest) => this.clientManifest.set(manifest))
      .catch(() => this.clientManifest.set(null));
    if (this.session.isAdmin()) {
      this.loadManifest();
    }
  }

  load(): void {
    this.loading.set(true);
    this.api
      .invoke(listHosts)
      .then((hosts) => this.hosts.set(hosts))
      .finally(() => this.loading.set(false));
  }

  /**
   * loadManifest fetches the rollout state. On failure ⇒ no manifest, the
   * button stays disabled (nothing is silently offered).
   */
  private loadManifest(): void {
    this.api
      .invoke(getAgentManifest)
      .then((manifest) => this.manifest.set(manifest))
      .catch(() => this.manifest.set(null));
  }

  addHost(): void {
    const manifest = this.manifest();
    if (!manifest?.rollout_ready) {
      return;
    }
    this.dialog
      .open(HostAddDialog, { data: manifest, width: '640px' })
      .afterClosed()
      .subscribe(() => this.load());
  }

  /**
   * connect opens the per-host dialog. Only for enrolled hosts — an
   * unenrolled host has no agent and nothing to connect to yet.
   */
  connect(host: Host): void {
    if (!host.enrolled_at) {
      return;
    }
    this.dialog.open(HostConnectDialog, {
      data: { host, manifest: this.clientManifest() },
      width: '640px',
    });
  }

  connectTooltip(host: Host): string {
    return host.enrolled_at ? 'Connect' : 'Not enrolled yet — nothing to connect to';
  }

  tagList(host: Host): string[] {
    return Object.entries(host.tags ?? {}).map(([k, v]) => `${k}=${v}`);
  }

  seenClass(host: Host): string {
    if (!host.last_seen_at) {
      return 'muted';
    }
    const ageHours = (Date.now() - new Date(host.last_seen_at).getTime()) / 3.6e6;
    return ageHours < 24 ? 'ok' : 'warn';
  }

  certLabel(host: Host): string {
    if (!host.cert_valid_before) {
      return 'no certificate';
    }
    const expiry = new Date(host.cert_valid_before);
    return expiry.getTime() < Date.now()
      ? `expired ${relativeTime(host.cert_valid_before)}`
      : `valid until ${formatTimestamp(host.cert_valid_before)}`;
  }

  certClass(host: Host): string {
    if (!host.cert_valid_before) {
      return 'muted';
    }
    const daysLeft = (new Date(host.cert_valid_before).getTime() - Date.now()) / 8.64e7;
    if (daysLeft < 0) {
      return 'danger';
    }
    return daysLeft < CERT_WARN_DAYS ? 'warn' : 'ok';
  }
}
