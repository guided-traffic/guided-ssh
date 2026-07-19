import { Routes } from '@angular/router';

import { roleGuard } from './core/role.guard';

export const routes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'hosts' },
  {
    path: 'hosts',
    canActivate: [roleGuard],
    data: { minRole: 'readonly' },
    loadComponent: () => import('./features/hosts').then((m) => m.HostsPage),
  },
  {
    path: 'grants',
    canActivate: [roleGuard],
    data: { minRole: 'readonly' },
    loadComponent: () => import('./features/grants').then((m) => m.GrantsPage),
  },
  {
    path: 'ci',
    canActivate: [roleGuard],
    data: { minRole: 'readonly' },
    loadComponent: () => import('./features/ci').then((m) => m.CiPage),
  },
  {
    path: 'users',
    canActivate: [roleGuard],
    data: { minRole: 'readonly' },
    loadComponent: () => import('./features/users').then((m) => m.UsersPage),
  },
  {
    path: 'audit',
    canActivate: [roleGuard],
    data: { minRole: 'auditor' },
    loadComponent: () => import('./features/audit').then((m) => m.AuditPage),
  },
  { path: '**', redirectTo: 'hosts' },
];
