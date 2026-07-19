import { Component, OnInit, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatTableModule } from '@angular/material/table';

import { Api } from '../api/api';
import { listHosts } from '../api/functions';
import { Host } from '../api/models';
import { formatTimestamp, relativeTime } from '../core/format';

const CERT_WARN_DAYS = 7;

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
        <button mat-stroked-button (click)="load()" [disabled]="loading()">
          <mat-icon svgIcon="refresh" />Aktualisieren
        </button>
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
              <td mat-cell *matCellDef="let h" class="dim">{{ formatTimestamp(h.enrolled_at) }}</td>
            </ng-container>
            <tr mat-header-row *matHeaderRowDef="columns"></tr>
            <tr mat-row *matRowDef="let row; columns: columns"></tr>
          </table>
        }
      </div>
    </div>
  `,
})
export class HostsPage implements OnInit {
  private readonly api = inject(Api);

  protected readonly columns = ['name', 'tags', 'seen', 'cert', 'enrolled'];
  protected readonly hosts = signal<Host[]>([]);
  protected readonly loading = signal(false);

  protected readonly relativeTime = relativeTime;
  protected readonly formatTimestamp = formatTimestamp;

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.api
      .invoke(listHosts)
      .then((hosts) => this.hosts.set(hosts))
      .finally(() => this.loading.set(false));
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
