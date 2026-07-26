import { Injectable, effect, signal } from '@angular/core';

export type ThemeMode = 'light' | 'dark' | 'system';

const STORAGE_KEY = 'gssh-theme';

/**
 * ThemeService toggles the `dark` class on <html> — the single switch the
 * stylesheet (and Angular Material via `mat.theme-overrides`) keys off.
 * Selection persists in localStorage; "system" follows the OS preference live.
 */
@Injectable({ providedIn: 'root' })
export class ThemeService {
  readonly mode = signal<ThemeMode>(readStoredMode());

  private readonly media = window.matchMedia('(prefers-color-scheme: dark)');

  constructor() {
    this.media.addEventListener('change', () => this.apply());
    effect(() => {
      localStorage.setItem(STORAGE_KEY, this.mode());
      this.apply();
    });
  }

  set(mode: ThemeMode): void {
    this.mode.set(mode);
  }

  private apply(): void {
    const dark = this.mode() === 'dark' || (this.mode() === 'system' && this.media.matches);
    document.documentElement.classList.toggle('dark', dark);
  }
}

function readStoredMode(): ThemeMode {
  const value = localStorage.getItem(STORAGE_KEY);
  return value === 'light' || value === 'dark' || value === 'system' ? value : 'system';
}
