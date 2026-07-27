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
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';

import { Api } from '../api/api';
import { createGrant, deleteGrant, listGrants, updateGrant } from '../api/functions';
import { Grant, GrantRequest } from '../api/models';
import { ConfigService } from '../core/config.service';
import { csvToList, formatSeconds, tagsToText, textToTags } from '../core/format';
import { SessionService } from '../core/session.service';

@Component({
  selector: 'app-grants',
  imports: [MatTableModule, MatButtonModule, MatIconModule, MatProgressSpinnerModule],
  template: `
    <div class="page">
      <div class="page-header">
        <div>
          <h1>Access Rules</h1>
          <div class="page-sub">
            IdP group × tag selector → principals · additive, no deny (ADR-018)
          </div>
          @if (config.loaded() && !config.grantsEditable()) {
            <div class="page-sub">
              Rules are managed declaratively (GitOps) — in-app editing is disabled.
            </div>
          }
        </div>
        <div>
          <button mat-stroked-button (click)="load()" [disabled]="loading()">
            <mat-icon svgIcon="refresh" />Refresh
          </button>
          @if (session.isAdmin() && config.grantsEditable()) {
            <button mat-flat-button (click)="edit(null)" style="margin-left: 8px">
              <mat-icon svgIcon="add" />New Rule
            </button>
          }
        </div>
      </div>

      <div class="glass-panel table-scroll">
        @if (loading()) {
          <div class="empty-state"><mat-spinner diameter="28" /></div>
        } @else if (grants().length === 0) {
          <div class="empty-state">No access rules defined.</div>
        } @else {
          <table mat-table [dataSource]="grants()">
            <ng-container matColumnDef="group">
              <th mat-header-cell *matHeaderCellDef>Group</th>
              <td mat-cell *matCellDef="let g">
                <div>{{ g.group }}</div>
                <div class="dim mono" style="font-size: 11px">{{ g.issuer }}</div>
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
            <ng-container matColumnDef="sudo">
              <th mat-header-cell *matHeaderCellDef>sudo</th>
              <td mat-cell *matCellDef="let g">
                <span [class]="g.sudo ? 'pill warn' : 'pill muted'">{{ g.sudo ? 'yes' : 'no' }}</span>
              </td>
            </ng-container>
            <ng-container matColumnDef="validity">
              <th mat-header-cell *matHeaderCellDef>Max. Validity</th>
              <td mat-cell *matCellDef="let g">{{ formatSeconds(g.max_validity_seconds) }}</td>
            </ng-container>
            <ng-container matColumnDef="actions">
              <th mat-header-cell *matHeaderCellDef></th>
              <td mat-cell *matCellDef="let g" style="white-space: nowrap; text-align: right">
                @if (session.isAdmin() && config.grantsEditable()) {
                  <button mat-icon-button aria-label="Edit" (click)="edit(g)">
                    <mat-icon svgIcon="edit" />
                  </button>
                  <button mat-icon-button aria-label="Delete" (click)="remove(g)">
                    <mat-icon svgIcon="delete" />
                  </button>
                }
              </td>
            </ng-container>
            <tr mat-header-row *matHeaderRowDef="columns"></tr>
            <tr mat-row *matRowDef="let row; columns: columns"></tr>
          </table>
        }
      </div>
    </div>
  `,
})
export class GrantsPage implements OnInit {
  private readonly api = inject(Api);
  private readonly dialog = inject(MatDialog);
  private readonly snackBar = inject(MatSnackBar);
  protected readonly session = inject(SessionService);
  protected readonly config = inject(ConfigService);

  protected readonly columns = ['group', 'selector', 'principals', 'sudo', 'validity', 'actions'];
  protected readonly grants = signal<Grant[]>([]);
  protected readonly loading = signal(false);
  protected readonly formatSeconds = formatSeconds;

  ngOnInit(): void {
    void this.config.load();
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.api
      .invoke(listGrants)
      .then((grants) => this.grants.set(grants))
      .finally(() => this.loading.set(false));
  }

  tagList(selector: Record<string, string> | undefined): string[] {
    return Object.entries(selector ?? {}).map(([k, v]) => `${k}=${v}`);
  }

  edit(grant: Grant | null): void {
    this.dialog
      .open(GrantDialog, { data: grant, width: '480px' })
      .afterClosed()
      .subscribe((changed) => changed && this.load());
  }

  remove(grant: Grant): void {
    if (!confirm(`Really delete the access rule for "${grant.group}"?`)) {
      return;
    }
    this.api
      .invoke(deleteGrant, { id: grant.id })
      .then(() => this.load())
      .catch(() => this.snackBar.open('Delete failed', 'OK', { duration: 4000 }));
  }
}

@Component({
  selector: 'app-grant-dialog',
  imports: [
    FormsModule,
    MatDialogModule,
    MatFormFieldModule,
    MatInputModule,
    MatCheckboxModule,
    MatButtonModule,
  ],
  template: `
    <h2 mat-dialog-title>{{ grant ? 'Edit Access Rule' : 'New Access Rule' }}</h2>
    <mat-dialog-content>
      <div class="dialog-form">
        <mat-form-field appearance="outline">
          <mat-label>IdP group</mat-label>
          <input matInput [(ngModel)]="group" [disabled]="grant !== null" required />
        </mat-form-field>
        <mat-form-field appearance="outline">
          <mat-label>Issuer (empty = own IdP)</mat-label>
          <input matInput [(ngModel)]="issuer" [disabled]="grant !== null" />
        </mat-form-field>
        <mat-form-field appearance="outline">
          <mat-label>Host tag selector (key=value, …)</mat-label>
          <input matInput [(ngModel)]="tagSelector" placeholder="env=prod, role=web" />
          <mat-hint>empty = all hosts</mat-hint>
        </mat-form-field>
        <mat-form-field appearance="outline">
          <mat-label>Principals (comma-separated)</mat-label>
          <input matInput [(ngModel)]="principals" placeholder="deploy, root" required />
        </mat-form-field>
        <mat-form-field appearance="outline">
          <mat-label>Maximum validity (hours)</mat-label>
          <input matInput type="number" min="1" [(ngModel)]="validityHours" required />
        </mat-form-field>
        <mat-checkbox [(ngModel)]="sudo">allow sudo</mat-checkbox>
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
export class GrantDialog {
  private readonly api = inject(Api);
  private readonly ref = inject(MatDialogRef<GrantDialog>);

  protected group = '';
  protected issuer = '';
  protected tagSelector = '';
  protected principals = '';
  protected validityHours = 16;
  protected sudo = false;
  protected readonly saving = signal(false);
  protected readonly error = signal('');

  constructor(@Inject(MAT_DIALOG_DATA) protected readonly grant: Grant | null) {
    if (grant) {
      this.group = grant.group;
      this.issuer = grant.issuer;
      this.tagSelector = tagsToText(grant.tag_selector);
      this.principals = grant.principals.join(', ');
      this.validityHours = Math.max(1, Math.round(grant.max_validity_seconds / 3600));
      this.sudo = grant.sudo;
    }
  }

  save(): void {
    let body: GrantRequest;
    try {
      body = {
        group: this.group.trim() || undefined,
        issuer: this.issuer.trim() || undefined,
        tag_selector: textToTags(this.tagSelector),
        principals: csvToList(this.principals),
        sudo: this.sudo,
        max_validity_seconds: Math.round(this.validityHours * 3600),
      };
    } catch (err) {
      this.error.set(String(err instanceof Error ? err.message : err));
      return;
    }
    if (!this.grant && !body.group) {
      this.error.set('Group is missing');
      return;
    }
    if (body.principals.length === 0) {
      this.error.set('At least one principal is required');
      return;
    }
    this.saving.set(true);
    const call = this.grant
      ? this.api.invoke(updateGrant, { id: this.grant.id, body })
      : this.api.invoke(createGrant, { body });
    call
      .then(() => this.ref.close(true))
      .catch(() => this.error.set('Save failed'))
      .finally(() => this.saving.set(false));
  }
}
