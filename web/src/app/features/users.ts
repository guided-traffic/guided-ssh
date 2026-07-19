import { Component, OnInit, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatTableModule } from '@angular/material/table';
import { MatTabsModule } from '@angular/material/tabs';

import { Api } from '../api/api';
import { listGroups, listUsers } from '../api/functions';
import { Group, User } from '../api/models';
import { formatTimestamp } from '../core/format';

@Component({
  selector: 'app-users',
  imports: [MatTabsModule, MatTableModule, MatButtonModule, MatIconModule, MatProgressSpinnerModule],
  template: `
    <div class="page">
      <div class="page-header">
        <div>
          <h1>Benutzer &amp; Gruppen</h1>
          <div class="page-sub">Aus dem IdP synchronisiert — der IdP bleibt Source of Truth</div>
        </div>
        <button mat-stroked-button (click)="load()" [disabled]="loading()">
          <mat-icon svgIcon="refresh" />Aktualisieren
        </button>
      </div>

      <mat-tab-group>
        <mat-tab label="Benutzer">
          <div class="glass-panel table-scroll" style="margin-top: 16px">
            @if (loading()) {
              <div class="empty-state"><mat-spinner diameter="28" /></div>
            } @else if (users().length === 0) {
              <div class="empty-state">Noch keine Benutzer synchronisiert.</div>
            } @else {
              <table mat-table [dataSource]="users()">
                <ng-container matColumnDef="username">
                  <th mat-header-cell *matHeaderCellDef>Benutzer</th>
                  <td mat-cell *matCellDef="let u">
                    <div>{{ u.username }}</div>
                    <div class="dim" style="font-size: 12px">{{ u.email }}</div>
                  </td>
                </ng-container>
                <ng-container matColumnDef="groups">
                  <th mat-header-cell *matHeaderCellDef>Gruppen</th>
                  <td mat-cell *matCellDef="let u">
                    @for (group of u.groups; track group) {
                      <span class="tag-chip">{{ group }}</span>
                    } @empty {
                      <span class="dim">—</span>
                    }
                  </td>
                </ng-container>
                <ng-container matColumnDef="active">
                  <th mat-header-cell *matHeaderCellDef>Status</th>
                  <td mat-cell *matCellDef="let u">
                    <span [class]="u.active ? 'pill ok' : 'pill danger'">
                      {{ u.active ? 'aktiv' : 'deaktiviert' }}
                    </span>
                  </td>
                </ng-container>
                <ng-container matColumnDef="updated">
                  <th mat-header-cell *matHeaderCellDef>Zuletzt aktualisiert</th>
                  <td mat-cell *matCellDef="let u" class="dim">{{ formatTimestamp(u.updated_at) }}</td>
                </ng-container>
                <tr mat-header-row *matHeaderRowDef="userColumns"></tr>
                <tr mat-row *matRowDef="let row; columns: userColumns"></tr>
              </table>
            }
          </div>
        </mat-tab>

        <mat-tab label="Gruppen">
          <div class="glass-panel table-scroll" style="margin-top: 16px">
            @if (loading()) {
              <div class="empty-state"><mat-spinner diameter="28" /></div>
            } @else if (groups().length === 0) {
              <div class="empty-state">Noch keine Gruppen synchronisiert.</div>
            } @else {
              <table mat-table [dataSource]="groups()">
                <ng-container matColumnDef="name">
                  <th mat-header-cell *matHeaderCellDef>Gruppe</th>
                  <td mat-cell *matCellDef="let g">{{ g.name }}</td>
                </ng-container>
                <ng-container matColumnDef="issuer">
                  <th mat-header-cell *matHeaderCellDef>Issuer</th>
                  <td mat-cell *matCellDef="let g" class="dim mono">{{ g.issuer }}</td>
                </ng-container>
                <ng-container matColumnDef="created">
                  <th mat-header-cell *matHeaderCellDef>Angelegt</th>
                  <td mat-cell *matCellDef="let g" class="dim">{{ formatTimestamp(g.created_at) }}</td>
                </ng-container>
                <tr mat-header-row *matHeaderRowDef="groupColumns"></tr>
                <tr mat-row *matRowDef="let row; columns: groupColumns"></tr>
              </table>
            }
          </div>
        </mat-tab>
      </mat-tab-group>
    </div>
  `,
})
export class UsersPage implements OnInit {
  private readonly api = inject(Api);

  protected readonly userColumns = ['username', 'groups', 'active', 'updated'];
  protected readonly groupColumns = ['name', 'issuer', 'created'];
  protected readonly users = signal<User[]>([]);
  protected readonly groups = signal<Group[]>([]);
  protected readonly loading = signal(false);
  protected readonly formatTimestamp = formatTimestamp;

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    Promise.all([this.api.invoke(listUsers), this.api.invoke(listGroups)])
      .then(([users, groups]) => {
        this.users.set(users);
        this.groups.set(groups);
      })
      .finally(() => this.loading.set(false));
  }
}
