// Kleine Formatierungshelfer der Views (bewusst ohne Pipe-Boilerplate).

/** relativeTime formatiert einen Zeitstempel als deutsche Relativzeit. */
export function relativeTime(iso: string | null | undefined): string {
  if (!iso) {
    return 'nie';
  }
  const then = new Date(iso).getTime();
  const diffSec = Math.round((Date.now() - then) / 1000);
  const abs = Math.abs(diffSec);
  const units: Array<[number, string]> = [
    [60, 's'],
    [60, 'min'],
    [24, 'h'],
    [365, 'd'],
  ];
  let value = abs;
  let unit = 's';
  for (const [factor, label] of units) {
    unit = label;
    if (value < factor) {
      break;
    }
    value = Math.floor(value / factor);
  }
  return diffSec >= 0 ? `vor ${value} ${unit}` : `in ${value} ${unit}`;
}

/** formatSeconds formatiert eine Dauer in Sekunden kompakt (16 h, 30 d, 45 min). */
export function formatSeconds(seconds: number): string {
  if (seconds % 86400 === 0) {
    return `${seconds / 86400} d`;
  }
  if (seconds % 3600 === 0) {
    return `${seconds / 3600} h`;
  }
  if (seconds % 60 === 0) {
    return `${seconds / 60} min`;
  }
  return `${seconds} s`;
}

/** formatTimestamp formatiert einen ISO-Zeitstempel lokal und lesbar. */
export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) {
    return '—';
  }
  return new Date(iso).toLocaleString('de-DE', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

/** prettyJson formatiert ein Objekt als eingerücktes JSON. */
export function prettyJson(value: unknown): string {
  return JSON.stringify(value, null, 2) ?? '';
}

/** tagsToText serialisiert einen Tag-Selektor als "k=v, k2=v2". */
export function tagsToText(tags: Record<string, string> | undefined | null): string {
  return Object.entries(tags ?? {})
    .map(([k, v]) => `${k}=${v}`)
    .join(', ');
}

/** textToTags parst "k=v, k2=v2" in einen Tag-Selektor; wirft bei Syntaxfehlern. */
export function textToTags(text: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const raw of text.split(',')) {
    const pair = raw.trim();
    if (pair === '') {
      continue;
    }
    const idx = pair.indexOf('=');
    if (idx <= 0) {
      throw new Error(`ungültiges Tag „${pair}“ (erwartet key=value)`);
    }
    tags[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim();
  }
  return tags;
}

/** csvToList parst eine Komma-Liste in ein bereinigtes Array. */
export function csvToList(text: string): string[] {
  return text
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s !== '');
}
