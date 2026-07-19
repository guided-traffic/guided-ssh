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
import { csvToList, formatSeconds, tagsToText, textToTags } from '../core/format';
import { SessionService } from '../core/session.service';

@Component({
  selector: 'app-grants',
  imports: [MatTableModule, MatButtonModule, MatIconModule, MatProgressSpinnerModule],
  template: `
    <div class="page">
      <div class="page-header">
        <div>
          <h1>Zugriffsregeln</h1>
          <div class="page-sub">
            IdP-Gruppe × Tag-Selektor → Principals · additiv, kein deny (ADR-018)
          </div>
        </div>
        <div>
          <button mat-stroked-button (click)="load()" [disabled]="loading()">
            <mat-icon svgIcon="refresh" />Aktualisieren
          </button>
          @if (session.isAdmin()) {
            <button mat-flat-button (click)="edit(null)" style="margin-left: 8px">
              <mat-icon svgIcon="add" />Neue Regel
            </button>
          }
        </div>
      </div>

      <div class="glass-panel table-scroll">
        @if (loading()) {
          <div class="empty-state"><mat-spinner diameter="28" /></div>
        } @else if (grants().length === 0) {
          <div class="empty-state">Keine Zugriffsregeln definiert.</div>
        } @else {
          <table mat-table [dataSource]="grants()">
            <ng-container matColumnDef="group">
              <th mat-header-cell *matHeaderCellDef>Gruppe</th>
              <td mat-cell *matCellDef="let g">
                <div>{{ g.group }}</div>
                <div class="dim mono" style="font-size: 11px">{{ g.issuer }}</div>
              </td>
            </ng-container>
            <ng-container matColumnDef="selector">
              <th mat-header-cell *matHeaderCellDef>Host-Selektor</th>
              <td mat-cell *matCellDef="let g">
                @for (tag of tagList(g.tag_selector); track tag) {
                  <span class="tag-chip">{{ tag }}</span>
                } @empty {
                  <span class="pill accent">alle Hosts</span>
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
                <span [class]="g.sudo ? 'pill warn' : 'pill muted'">{{ g.sudo ? 'ja' : 'nein' }}</span>
              </td>
            </ng-container>
            <ng-container matColumnDef="validity">
              <th mat-header-cell *matHeaderCellDef>Max. Laufzeit</th>
              <td mat-cell *matCellDef="let g">{{ formatSeconds(g.max_validity_seconds) }}</td>
            </ng-container>
            <ng-container matColumnDef="actions">
              <th mat-header-cell *matHeaderCellDef></th>
              <td mat-cell *matCellDef="let g" style="white-space: nowrap; text-align: right">
                @if (session.isAdmin()) {
                  <button mat-icon-button aria-label="Bearbeiten" (click)="edit(g)">
                    <mat-icon svgIcon="edit" />
                  </button>
                  <button mat-icon-button aria-label="Löschen" (click)="remove(g)">
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

  protected readonly columns = ['group', 'selector', 'principals', 'sudo', 'validity', 'actions'];
  protected readonly grants = signal<Grant[]>([]);
  protected readonly loading = signal(false);
  protected readonly formatSeconds = formatSeconds;

  ngOnInit(): void {
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
    if (!confirm(`Zugriffsregel für „${grant.group}“ wirklich löschen?`)) {
      return;
    }
    this.api
      .invoke(deleteGrant, { id: grant.id })
      .then(() => this.load())
      .catch(() => this.snackBar.open('Löschen fehlgeschlagen', 'OK', { duration: 4000 }));
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
    <h2 mat-dialog-title>{{ grant ? 'Zugriffsregel bearbeiten' : 'Neue Zugriffsregel' }}</h2>
    <mat-dialog-content>
      <div class="dialog-form">
        <mat-form-field appearance="outline">
          <mat-label>IdP-Gruppe</mat-label>
          <input matInput [(ngModel)]="group" [disabled]="grant !== null" required />
        </mat-form-field>
        <mat-form-field appearance="outline">
          <mat-label>Issuer (leer = eigener IdP)</mat-label>
          <input matInput [(ngModel)]="issuer" [disabled]="grant !== null" />
        </mat-form-field>
        <mat-form-field appearance="outline">
          <mat-label>Host-Tag-Selektor (key=value, …)</mat-label>
          <input matInput [(ngModel)]="tagSelector" placeholder="env=prod, role=web" />
          <mat-hint>leer = alle Hosts</mat-hint>
        </mat-form-field>
        <mat-form-field appearance="outline">
          <mat-label>Principals (Komma-getrennt)</mat-label>
          <input matInput [(ngModel)]="principals" placeholder="deploy, root" required />
        </mat-form-field>
        <mat-form-field appearance="outline">
          <mat-label>Maximale Laufzeit (Stunden)</mat-label>
          <input matInput type="number" min="1" [(ngModel)]="validityHours" required />
        </mat-form-field>
        <mat-checkbox [(ngModel)]="sudo">sudo erlauben</mat-checkbox>
        @if (error()) {
          <div class="pill danger">{{ error() }}</div>
        }
      </div>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button mat-dialog-close>Abbrechen</button>
      <button mat-flat-button (click)="save()" [disabled]="saving()">Speichern</button>
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
      this.error.set('Gruppe fehlt');
      return;
    }
    if (body.principals.length === 0) {
      this.error.set('Mindestens ein Principal erforderlich');
      return;
    }
    this.saving.set(true);
    const call = this.grant
      ? this.api.invoke(updateGrant, { id: this.grant.id, body })
      : this.api.invoke(createGrant, { body });
    call
      .then(() => this.ref.close(true))
      .catch(() => this.error.set('Speichern fehlgeschlagen'))
      .finally(() => this.saving.set(false));
  }
}
