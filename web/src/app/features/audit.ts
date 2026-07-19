import { HttpClient, HttpParams } from '@angular/common/http';
import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { provideNativeDateAdapter } from '@angular/material/core';
import { MatDatepickerModule } from '@angular/material/datepicker';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatPaginatorModule, PageEvent } from '@angular/material/paginator';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSelectModule } from '@angular/material/select';
import { MatTableModule } from '@angular/material/table';

import { Api } from '../api/api';
import { listAudit } from '../api/functions';
import { AuditEvent } from '../api/models';
import { formatTimestamp, prettyJson } from '../core/format';

const PAGE_SIZE = 50;

// Bekannte Ereignistypen (Volltext-Feld deckt neue/unbekannte ab).
const EVENT_TYPES = [
  'ca.cert_issued',
  'ca.agent_cert_issued',
  'ca.key_created',
  'ca.key_rotated',
  'ca.key_retired',
  'grant.created',
  'grant.updated',
  'grant.deleted',
  'ci_grant.created',
  'ci_grant.updated',
  'ci_grant.deleted',
  'service_account.updated',
  'host.enrolled',
  'auth.user_deactivated',
  'auth.user_reactivated',
];

@Component({
  selector: 'app-audit',
  providers: [provideNativeDateAdapter()],
  imports: [
    FormsModule,
    MatTableModule,
    MatButtonModule,
    MatIconModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    MatDatepickerModule,
    MatPaginatorModule,
    MatProgressSpinnerModule,
  ],
  template: `
    <div class="page">
      <div class="page-header">
        <div>
          <h1>Audit</h1>
          <div class="page-sub">
            Jede Ausstellung, jedes Enrollment, jede Regel-Änderung — append-only
          </div>
        </div>
        <div>
          <button mat-stroked-button (click)="download('csv')">
            <mat-icon svgIcon="download" />CSV
          </button>
          <button mat-stroked-button (click)="download('json')" style="margin-left: 8px">
            <mat-icon svgIcon="download" />JSON
          </button>
        </div>
      </div>

      <div class="glass-panel filter-bar">
        <mat-form-field appearance="outline" subscriptSizing="dynamic">
          <mat-label>Ereignistyp</mat-label>
          <mat-select [(ngModel)]="eventType">
            <mat-option value="">alle</mat-option>
            @for (type of eventTypes; track type) {
              <mat-option [value]="type">{{ type }}</mat-option>
            }
          </mat-select>
        </mat-form-field>
        <mat-form-field appearance="outline" subscriptSizing="dynamic">
          <mat-label>Actor (exakt)</mat-label>
          <input matInput [(ngModel)]="actor" placeholder="user:… / ci:… " (keyup.enter)="apply()" />
        </mat-form-field>
        <mat-form-field appearance="outline" subscriptSizing="dynamic" class="grow">
          <mat-label>Suche (Nutzer, Host, Pipeline …)</mat-label>
          <input matInput [(ngModel)]="search" (keyup.enter)="apply()" />
          <mat-icon matSuffix svgIcon="search" />
        </mat-form-field>
        <mat-form-field appearance="outline" subscriptSizing="dynamic">
          <mat-label>Von</mat-label>
          <input matInput [matDatepicker]="fromPicker" [(ngModel)]="since" />
          <mat-datepicker-toggle matIconSuffix [for]="fromPicker" />
          <mat-datepicker #fromPicker />
        </mat-form-field>
        <mat-form-field appearance="outline" subscriptSizing="dynamic">
          <mat-label>Bis</mat-label>
          <input matInput [matDatepicker]="untilPicker" [(ngModel)]="until" />
          <mat-datepicker-toggle matIconSuffix [for]="untilPicker" />
          <mat-datepicker #untilPicker />
        </mat-form-field>
        <button mat-flat-button (click)="apply()">Filtern</button>
        <button mat-button (click)="reset()">Zurücksetzen</button>
      </div>

      <div class="glass-panel table-scroll" style="margin-top: 16px">
        @if (loading()) {
          <div class="empty-state"><mat-spinner diameter="28" /></div>
        } @else if (events().length === 0) {
          <div class="empty-state">Keine Audit-Events zum Filter.</div>
        } @else {
          <table mat-table [dataSource]="events()" multiTemplateDataRows>
            <ng-container matColumnDef="time">
              <th mat-header-cell *matHeaderCellDef>Zeitpunkt</th>
              <td mat-cell *matCellDef="let e" class="mono" style="white-space: nowrap">
                {{ formatTimestamp(e.occurred_at) }}
              </td>
            </ng-container>
            <ng-container matColumnDef="type">
              <th mat-header-cell *matHeaderCellDef>Ereignis</th>
              <td mat-cell *matCellDef="let e">
                <span [class]="'pill ' + typeClass(e.event_type)">{{ e.event_type }}</span>
              </td>
            </ng-container>
            <ng-container matColumnDef="actor">
              <th mat-header-cell *matHeaderCellDef>Actor</th>
              <td mat-cell *matCellDef="let e" class="mono">{{ e.actor }}</td>
            </ng-container>
            <ng-container matColumnDef="detail">
              <td mat-cell *matCellDef="let e" [attr.colspan]="columns.length" class="detail-cell">
                @if (expandedId() === e.id) {
                  <pre class="payload">{{ prettyJson(e.payload) }}</pre>
                }
              </td>
            </ng-container>
            <tr mat-header-row *matHeaderRowDef="columns"></tr>
            <tr
              mat-row
              *matRowDef="let row; columns: columns"
              class="event-row"
              (click)="toggle(row)"
            ></tr>
            <tr mat-row *matRowDef="let row; columns: ['detail']" class="detail-row"></tr>
          </table>
          <mat-paginator
            [length]="total()"
            [pageSize]="pageSize"
            [pageIndex]="pageIndex()"
            [hidePageSize]="true"
            (page)="page($event)"
          />
        }
      </div>
    </div>
  `,
  styles: `
    .filter-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 12px;
      padding: 16px;

      mat-form-field {
        width: 180px;
      }

      .grow {
        flex: 1 1 220px;
      }
    }

    .event-row {
      cursor: pointer;
    }

    .detail-cell {
      padding: 0 16px;
      border-bottom-width: 0;
    }

    tr.detail-row {
      height: 0;
    }

    .detail-cell pre {
      margin: 4px 0 12px;
    }
  `,
})
export class AuditPage implements OnInit {
  private readonly api = inject(Api);
  private readonly http = inject(HttpClient);

  protected readonly columns = ['time', 'type', 'actor'];
  protected readonly eventTypes = EVENT_TYPES;
  protected readonly pageSize = PAGE_SIZE;

  protected eventType = '';
  protected actor = '';
  protected search = '';
  protected since: Date | null = null;
  protected until: Date | null = null;

  protected readonly events = signal<AuditEvent[]>([]);
  protected readonly total = signal(0);
  protected readonly pageIndex = signal(0);
  protected readonly loading = signal(false);
  protected readonly expandedId = signal<number | null>(null);

  protected readonly formatTimestamp = formatTimestamp;
  protected readonly prettyJson = prettyJson;

  ngOnInit(): void {
    this.load();
  }

  apply(): void {
    this.pageIndex.set(0);
    this.load();
  }

  reset(): void {
    this.eventType = '';
    this.actor = '';
    this.search = '';
    this.since = null;
    this.until = null;
    this.apply();
  }

  page(event: PageEvent): void {
    this.pageIndex.set(event.pageIndex);
    this.load();
  }

  toggle(event: AuditEvent): void {
    this.expandedId.update((id) => (id === event.id ? null : event.id));
  }

  typeClass(eventType: string): string {
    if (eventType.startsWith('ca.cert') || eventType.startsWith('ca.agent')) {
      return 'accent';
    }
    if (eventType === 'auth.user_deactivated') {
      return 'danger';
    }
    if (eventType === 'auth.user_reactivated' || eventType === 'host.enrolled') {
      return 'ok';
    }
    if (eventType.startsWith('grant.') || eventType.startsWith('ci_grant.') || eventType.startsWith('service_account.')) {
      return 'warn';
    }
    return 'muted';
  }

  private filter(): Record<string, string> {
    const params: Record<string, string> = {};
    if (this.eventType) {
      params['event_type'] = this.eventType;
    }
    if (this.actor.trim()) {
      params['actor'] = this.actor.trim();
    }
    if (this.search.trim()) {
      params['q'] = this.search.trim();
    }
    if (this.since) {
      params['since'] = startOfDay(this.since).toISOString();
    }
    if (this.until) {
      params['until'] = endOfDay(this.until).toISOString();
    }
    return params;
  }

  load(): void {
    this.loading.set(true);
    this.expandedId.set(null);
    this.api
      .invoke(listAudit, {
        ...this.filter(),
        limit: PAGE_SIZE,
        offset: this.pageIndex() * PAGE_SIZE,
      })
      .then((result) => {
        this.events.set(result.events);
        this.total.set(result.total);
      })
      .finally(() => this.loading.set(false));
  }

  download(format: 'csv' | 'json'): void {
    const params = new HttpParams({ fromObject: { ...this.filter(), format } });
    this.http
      .get('/v1/admin/audit/export', { params, responseType: 'blob' })
      .subscribe((blob) => {
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = `audit-export.${format}`;
        anchor.click();
        URL.revokeObjectURL(url);
      });
  }
}

function startOfDay(date: Date): Date {
  const copied = new Date(date);
  copied.setHours(0, 0, 0, 0);
  return copied;
}

function endOfDay(date: Date): Date {
  const copied = new Date(date);
  copied.setHours(23, 59, 59, 999);
  return copied;
}
