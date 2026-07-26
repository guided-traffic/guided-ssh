import { Component, OnInit, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatTableModule } from '@angular/material/table';

import { Api } from '../api/api';
import { getAgentManifest, listHosts } from '../api/functions';
import { AgentManifest, Host } from '../api/models';
import { formatTimestamp, relativeTime } from '../core/format';
import { SessionService } from '../core/session.service';
import { HostAddDialog } from './host-add-dialog';

const CERT_WARN_DAYS = 7;

/**
 * Klartext zu den Bedingungen des Rollout-Gates (siehe internal/api/rollout.go).
 * Der Button wird bewusst nicht versteckt, sondern deaktiviert — der Operator
 * soll sehen, warum der One-Command-Install gerade nicht geht.
 */
const ROLLOUT_MISSING_LABELS: Record<string, string> = {
  binaries: 'Server-Build ohne Agent-Binaries',
  pin: 'SPKI-Pin nicht ermittelt (GSSH_PUBLIC_PIN / Cert-Datei / Selbst-Dial)',
  agent_public_url: 'GSSH_AGENT_PUBLIC_URL fehlt',
  public_url: 'GSSH_PUBLIC_URL bzw. GSSH_UI_BASE_URL fehlt',
  agent_public_url_https: 'GSSH_AGENT_PUBLIC_URL ist kein https-URL',
  public_url_https: 'GSSH_PUBLIC_URL bzw. GSSH_UI_BASE_URL ist kein https-URL',
};

/**
 * Klartext zu den Pin-Fehlerkategorien des Manifests (`pin_error`, siehe
 * internal/api/pinprovider.go). Der Volltext des Fehlers steht bewusst nur im
 * Server-Log — hier landet nur die Kategorie plus der Hinweis, wo man nachsieht.
 */
const PIN_ERROR_LABELS: Record<string, string> = {
  no_public_url: 'keine bzw. keine https-Public-URL konfiguriert',
  chain_untrusted: 'Zertifikatskette der Public-URL nicht vertrauenswürdig',
  dial_failed: 'Selbst-Dial auf die Public-URL fehlgeschlagen',
  cert_file_unreadable: 'Pin-Zertifikatsdatei fehlt oder ist unlesbar',
};

/** rolloutMissingText fasst die fehlenden Bedingungen lesbar zusammen. */
export function rolloutMissingText(missing: readonly string[]): string {
  return missing.map((key) => ROLLOUT_MISSING_LABELS[key] ?? key).join(' · ');
}

/**
 * pinErrorText übersetzt die Fehlerkategorie; leer, wenn keine gemeldet ist.
 * Unbekannte Kategorien werden roh durchgereicht (neuer Server, alte UI).
 */
export function pinErrorText(pinError: string): string {
  if (!pinError) {
    return '';
  }
  return `${PIN_ERROR_LABELS[pinError] ?? pinError} (Details: Server-Log)`;
}

@Component({
  selector: 'app-hosts',
  imports: [MatTableModule, MatButtonModule, MatIconModule, MatProgressSpinnerModule],
  template: `
    <div class="page">
      <div class="page-header">
        <div>
          <h1>Hosts</h1>
          <div class="page-sub">Verwaltete Hosts mit Tags, Status und Zertifikatsablauf</div>
        </div>
        <div>
          <button mat-stroked-button (click)="load()" [disabled]="loading()">
            <mat-icon svgIcon="refresh" />Aktualisieren
          </button>
          @if (session.isAdmin()) {
            <button
              mat-flat-button
              style="margin-left: 8px"
              [disabled]="!manifest()?.rollout_ready"
              (click)="addHost()"
            >
              <mat-icon svgIcon="add" />Host hinzufügen
            </button>
            @if (manifest(); as m) {
              @if (!m.rollout_ready) {
                <div class="page-sub rollout-hint">
                  Host-Rollout nicht konfiguriert:
                  {{ rolloutMissingText(m.missing) }}
                  @if (pinErrorText(m.pin_error); as pinError) {
                    <div>Pin-Fehler: {{ pinError }}</div>
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
          <div class="empty-state">Noch keine Hosts enrolled.</div>
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
              <th mat-header-cell *matHeaderCellDef>Zuletzt gesehen</th>
              <td mat-cell *matCellDef="let h">
                <span [class]="'pill ' + seenClass(h)">{{ relativeTime(h.last_seen_at) }}</span>
              </td>
            </ng-container>
            <ng-container matColumnDef="cert">
              <th mat-header-cell *matHeaderCellDef>Host-Zertifikat</th>
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
  `,
})
export class HostsPage implements OnInit {
  private readonly api = inject(Api);
  private readonly dialog = inject(MatDialog);
  protected readonly session = inject(SessionService);

  protected readonly columns = ['name', 'tags', 'seen', 'cert', 'enrolled'];
  protected readonly hosts = signal<Host[]>([]);
  protected readonly loading = signal(false);
  /** Manifest des Rollouts; null, solange es nicht geladen ist. */
  protected readonly manifest = signal<AgentManifest | null>(null);

  protected readonly relativeTime = relativeTime;
  protected readonly formatTimestamp = formatTimestamp;
  protected readonly rolloutMissingText = rolloutMissingText;
  protected readonly pinErrorText = pinErrorText;

  ngOnInit(): void {
    this.load();
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
   * loadManifest holt den Rollout-Zustand. Fehlschlag ⇒ kein Manifest, der
   * Button bleibt deaktiviert (nichts wird stillschweigend angeboten).
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
      return 'kein Zertifikat';
    }
    const expiry = new Date(host.cert_valid_before);
    return expiry.getTime() < Date.now()
      ? `abgelaufen ${relativeTime(host.cert_valid_before)}`
      : `gültig bis ${formatTimestamp(host.cert_valid_before)}`;
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
