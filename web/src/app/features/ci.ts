import { Component, Inject, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCheckboxModule } from '@angular/material/checkbox';
import {
  MAT_DIALOG_DATA,
  MatDialog,
  MatDialogModule,
  MatDialogRef,
} from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { MatTabsModule } from '@angular/material/tabs';

import { Api } from '../api/api';
import {
  createCiGrant,
  deleteCiGrant,
  listCiGrants,
  listServiceAccounts,
  updateCiGrant,
  updateServiceAccount,
} from '../api/functions';
import { CiGrant, CiGrantRequest, ServiceAccount } from '../api/models';
import { csvToList, formatSeconds, tagsToText, textToTags } from '../core/format';
import { SessionService } from '../core/session.service';

@Component({
  selector: 'app-ci',
  imports: [
    MatTabsModule,
    MatTableModule,
    MatButtonModule,
    MatIconModule,
    MatProgressSpinnerModule,
    MatSlideToggleModule,
  ],
  template: `
    <div class="page">
      <div class="page-header">
        <div>
          <h1>CI &amp; Service Accounts</h1>
          <div class="page-sub">GitLab pipelines: access rules and project identities</div>
        </div>
        <div>
          <button mat-stroked-button (click)="load()" [disabled]="loading()">
            <mat-icon svgIcon="refresh" />Refresh
          </button>
          @if (session.isAdmin()) {
            <button mat-flat-button (click)="edit(null)" style="margin-left: 8px">
              <mat-icon svgIcon="add" />New CI Rule
            </button>
          }
        </div>
      </div>

      <mat-tab-group>
        <mat-tab label="CI Access Rules">
          <div class="glass-panel table-scroll" style="margin-top: 16px">
            @if (loading()) {
              <div class="empty-state"><mat-spinner diameter="28" /></div>
            } @else if (ciGrants().length === 0) {
              <div class="empty-state">No CI access rules defined.</div>
            } @else {
              <table mat-table [dataSource]="ciGrants()">
                <ng-container matColumnDef="project">
                  <th mat-header-cell *matHeaderCellDef>Project / Namespace</th>
                  <td mat-cell *matCellDef="let g" class="mono">{{ g.project }}</td>
                </ng-container>
                <ng-container matColumnDef="conditions">
                  <th mat-header-cell *matHeaderCellDef>Conditions</th>
                  <td mat-cell *matCellDef="let g">
                    @if (g.protected_only) {
                      <span class="pill accent">protected refs only</span>
                    }
                    @if (g.ref_pattern) {
                      <span class="tag-chip">ref={{ g.ref_pattern }}</span>
                    }
                    @if (g.environment_pattern) {
                      <span class="tag-chip">env={{ g.environment_pattern }}</span>
                    }
                    @if (!g.protected_only && !g.ref_pattern && !g.environment_pattern) {
                      <span class="dim">all refs</span>
                    }
                  </td>
                </ng-container>
                <ng-container matColumnDef="selector">
                  <th mat-header-cell *matHeaderCellDef>Host Selector</th>
                  <td mat-cell *matCellDef="let g">
                    @for (tag of tagList(g.tag_selector); track tag) {
                      <span class="tag-chip">{{ tag }}</span>
                    } @empty {
                      <span class="pill accent">all hosts</span>
                    }
                  </td>
                </ng-container>
                <ng-container matColumnDef="principals">
                  <th mat-header-cell *matHeaderCellDef>Principals</th>
                  <td mat-cell *matCellDef="let g" class="mono">{{ g.principals.join(', ') }}</td>
                </ng-container>
                <ng-container matColumnDef="validity">
                  <th mat-header-cell *matHeaderCellDef>Max. Validity</th>
                  <td mat-cell *matCellDef="let g">{{ formatSeconds(g.max_validity_seconds) }}</td>
                </ng-container>
                <ng-container matColumnDef="actions">
                  <th mat-header-cell *matHeaderCellDef></th>
                  <td mat-cell *matCellDef="let g" style="white-space: nowrap; text-align: right">
                    @if (session.isAdmin()) {
                      <button mat-icon-button aria-label="Edit" (click)="edit(g)">
                        <mat-icon svgIcon="edit" />
                      </button>
                      <button mat-icon-button aria-label="Delete" (click)="remove(g)">
                        <mat-icon svgIcon="delete" />
                      </button>
                    }
                  </td>
                </ng-container>
                <tr mat-header-row *matHeaderRowDef="ciColumns"></tr>
                <tr mat-row *matRowDef="let row; columns: ciColumns"></tr>
              </table>
            }
          </div>
        </mat-tab>

        <mat-tab label="Service Accounts">
          <div class="glass-panel table-scroll" style="margin-top: 16px">
            @if (loading()) {
              <div class="empty-state"><mat-spinner diameter="28" /></div>
            } @else if (accounts().length === 0) {
              <div class="empty-state">
                No service accounts yet — they are created on the first CI issuance.
              </div>
            } @else {
              <table mat-table [dataSource]="accounts()">
                <ng-container matColumnDef="name">
                  <th mat-header-cell *matHeaderCellDef>Project</th>
                  <td mat-cell *matCellDef="let a" class="mono">{{ a.name }}</td>
                </ng-container>
                <ng-container matColumnDef="kind">
                  <th mat-header-cell *matHeaderCellDef>Type</th>
                  <td mat-cell *matCellDef="let a"><span class="pill muted">{{ a.kind }}</span></td>
                </ng-container>
                <ng-container matColumnDef="issuer">
                  <th mat-header-cell *matHeaderCellDef>Issuer</th>
                  <td mat-cell *matCellDef="let a" class="dim mono">{{ a.issuer }}</td>
                </ng-container>
                <ng-container matColumnDef="active">
                  <th mat-header-cell *matHeaderCellDef>Active (kill switch)</th>
                  <td mat-cell *matCellDef="let a">
                    <mat-slide-toggle
                      [checked]="a.active"
                      [disabled]="!session.isAdmin() || toggling() === a.id"
                      (change)="toggle(a, $event.checked)"
                    />
                  </td>
                </ng-container>
                <tr mat-header-row *matHeaderRowDef="accountColumns"></tr>
                <tr mat-row *matRowDef="let row; columns: accountColumns"></tr>
              </table>
            }
          </div>
        </mat-tab>
      </mat-tab-group>
    </div>
  `,
})
export class CiPage implements OnInit {
  private readonly api = inject(Api);
  private readonly dialog = inject(MatDialog);
  private readonly snackBar = inject(MatSnackBar);
  protected readonly session = inject(SessionService);

  protected readonly ciColumns = ['project', 'conditions', 'selector', 'principals', 'validity', 'actions'];
  protected readonly accountColumns = ['name', 'kind', 'issuer', 'active'];
  protected readonly ciGrants = signal<CiGrant[]>([]);
  protected readonly accounts = signal<ServiceAccount[]>([]);
  protected readonly loading = signal(false);
  protected readonly toggling = signal('');
  protected readonly formatSeconds = formatSeconds;

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    Promise.all([this.api.invoke(listCiGrants), this.api.invoke(listServiceAccounts)])
      .then(([grants, accounts]) => {
        this.ciGrants.set(grants);
        this.accounts.set(accounts);
      })
      .finally(() => this.loading.set(false));
  }

  tagList(selector: Record<string, string> | undefined): string[] {
    return Object.entries(selector ?? {}).map(([k, v]) => `${k}=${v}`);
  }

  edit(grant: CiGrant | null): void {
    this.dialog
      .open(CiGrantDialog, { data: grant, width: '480px' })
      .afterClosed()
      .subscribe((changed) => changed && this.load());
  }

  remove(grant: CiGrant): void {
    if (!confirm(`Really delete the CI rule for "${grant.project}"?`)) {
      return;
    }
    this.api
      .invoke(deleteCiGrant, { id: grant.id })
      .then(() => this.load())
      .catch(() => this.snackBar.open('Delete failed', 'OK', { duration: 4000 }));
  }

  toggle(account: ServiceAccount, active: boolean): void {
    this.toggling.set(account.id);
    this.api
      .invoke(updateServiceAccount, { id: account.id, body: { active } })
      .then((updated) =>
        this.accounts.update((list) => list.map((a) => (a.id === updated.id ? updated : a))),
      )
      .catch(() => {
        this.snackBar.open('Toggle failed', 'OK', { duration: 4000 });
        this.load();
      })
      .finally(() => this.toggling.set(''));
  }
}

@Component({
  selector: 'app-ci-grant-dialog',
  imports: [
    FormsModule,
    MatDialogModule,
    MatFormFieldModule,
    MatInputModule,
    MatCheckboxModule,
    MatButtonModule,
  ],
  template: `
    <h2 mat-dialog-title>{{ grant ? 'Edit CI Rule' : 'New CI Rule' }}</h2>
    <mat-dialog-content>
      <div class="dialog-form">
        <mat-form-field appearance="outline">
          <mat-label>GitLab project or namespace</mat-label>
          <input matInput [(ngModel)]="project" [disabled]="grant !== null" placeholder="infra/ansible" required />
        </mat-form-field>
        <mat-form-field appearance="outline">
          <mat-label>Ref pattern (glob, empty = all)</mat-label>
          <input matInput [(ngModel)]="refPattern" placeholder="main" />
        </mat-form-field>
        <mat-form-field appearance="outline">
          <mat-label>Environment pattern (glob, empty = all)</mat-label>
          <input matInput [(ngModel)]="environmentPattern" placeholder="production" />
        </mat-form-field>
        <mat-form-field appearance="outline">
          <mat-label>Host tag selector (key=value, …)</mat-label>
          <input matInput [(ngModel)]="tagSelector" placeholder="env=prod" />
        </mat-form-field>
        <mat-form-field appearance="outline">
          <mat-label>Principals (comma-separated)</mat-label>
          <input matInput [(ngModel)]="principals" placeholder="deploy" required />
        </mat-form-field>
        <mat-form-field appearance="outline">
          <mat-label>Maximum validity (minutes)</mat-label>
          <input matInput type="number" min="1" [(ngModel)]="validityMinutes" required />
        </mat-form-field>
        <mat-checkbox [(ngModel)]="protectedOnly">protected refs only (ref_protected)</mat-checkbox>
        @if (error()) {
          <div class="pill danger">{{ error() }}</div>
        }
      </div>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button mat-dialog-close>Cancel</button>
      <button mat-flat-button (click)="save()" [disabled]="saving()">Save</button>
    </mat-dialog-actions>
  `,
  styles: `
    .dialog-form {
      display: flex;
      flex-direction: column;
      gap: 4px;
      padding-top: 8px;
      min-width: 360px;
    }
  `,
})
export class CiGrantDialog {
  private readonly api = inject(Api);
  private readonly ref = inject(MatDialogRef<CiGrantDialog>);

  protected project = '';
  protected refPattern = '';
  protected environmentPattern = '';
  protected tagSelector = '';
  protected principals = '';
  protected validityMinutes = 60;
  protected protectedOnly = true;
  protected readonly saving = signal(false);
  protected readonly error = signal('');

  constructor(@Inject(MAT_DIALOG_DATA) protected readonly grant: CiGrant | null) {
    if (grant) {
      this.project = grant.project;
      this.refPattern = grant.ref_pattern ?? '';
      this.environmentPattern = grant.environment_pattern ?? '';
      this.tagSelector = tagsToText(grant.tag_selector);
      this.principals = grant.principals.join(', ');
      this.validityMinutes = Math.max(1, Math.round(grant.max_validity_seconds / 60));
      this.protectedOnly = grant.protected_only;
    }
  }

  save(): void {
    let body: CiGrantRequest;
    try {
      body = {
        project: this.project.trim() || undefined,
        ref_pattern: this.refPattern.trim() || undefined,
        environment_pattern: this.environmentPattern.trim() || undefined,
        protected_only: this.protectedOnly,
        tag_selector: textToTags(this.tagSelector),
        principals: csvToList(this.principals),
        max_validity_seconds: Math.round(this.validityMinutes * 60),
      };
    } catch (err) {
      this.error.set(String(err instanceof Error ? err.message : err));
      return;
    }
    if (!this.grant && !body.project) {
      this.error.set('Project is missing');
      return;
    }
    if (body.principals.length === 0) {
      this.error.set('At least one principal is required');
      return;
    }
    this.saving.set(true);
    const call = this.grant
      ? this.api.invoke(updateCiGrant, { id: this.grant.id, body })
      : this.api.invoke(createCiGrant, { body });
    call
      .then(() => this.ref.close(true))
      .catch(() => this.error.set('Save failed'))
      .finally(() => this.saving.set(false));
  }
}
