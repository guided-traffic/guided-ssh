// Small formatting helpers for the views (deliberately without pipe boilerplate).

/** relativeTime formats a timestamp as a relative time string. */
export function relativeTime(iso: string | null | undefined): string {
  if (!iso) {
    return 'never';
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
  return diffSec >= 0 ? `${value} ${unit} ago` : `in ${value} ${unit}`;
}

/** formatSeconds formats a duration in seconds compactly (16 h, 30 d, 45 min). */
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

/** formatBytes formats a byte size compactly (14.8 MB). */
export function formatBytes(bytes: number): string {
  const units = ['B', 'kB', 'MB', 'GB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit++;
  }
  const rounded = unit === 0 ? value : Math.round(value * 10) / 10;
  return `${rounded.toLocaleString('en-US')} ${units[unit]}`;
}

/** formatTimestamp formats an ISO timestamp locally and readably. */
export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) {
    return '—';
  }
  return new Date(iso).toLocaleString('en-US', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

/** prettyJson formats an object as indented JSON. */
export function prettyJson(value: unknown): string {
  return JSON.stringify(value, null, 2) ?? '';
}

/** tagsToText serializes a tag selector as "k=v, k2=v2". */
export function tagsToText(tags: Record<string, string> | undefined | null): string {
  return Object.entries(tags ?? {})
    .map(([k, v]) => `${k}=${v}`)
    .join(', ');
}

/** textToTags parses "k=v, k2=v2" into a tag selector; throws on syntax errors. */
export function textToTags(text: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const raw of text.split(',')) {
    const pair = raw.trim();
    if (pair === '') {
      continue;
    }
    const idx = pair.indexOf('=');
    if (idx <= 0) {
      throw new Error(`invalid tag "${pair}" (expected key=value)`);
    }
    tags[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim();
  }
  return tags;
}

/** csvToList parses a comma-separated list into a cleaned-up array. */
export function csvToList(text: string): string[] {
  return text
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s !== '');
}
