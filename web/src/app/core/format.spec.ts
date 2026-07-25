import { describe, expect, it } from 'vitest';

import { csvToList, formatBytes, formatSeconds, tagsToText, textToTags } from './format';

describe('format helpers', () => {
  it('formatSeconds wählt die größte glatte Einheit', () => {
    expect(formatSeconds(30 * 86400)).toBe('30 d');
    expect(formatSeconds(16 * 3600)).toBe('16 h');
    expect(formatSeconds(45 * 60)).toBe('45 min');
    expect(formatSeconds(90)).toBe('90 s');
  });

  it('textToTags parst key=value-Listen und roundtrippt mit tagsToText', () => {
    const tags = textToTags('env=prod, role=web');
    expect(tags).toEqual({ env: 'prod', role: 'web' });
    expect(textToTags(tagsToText(tags))).toEqual(tags);
    expect(textToTags('')).toEqual({});
    expect(() => textToTags('kaputt')).toThrow();
  });

  it('formatBytes skaliert auf die passende Einheit', () => {
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(14_800_000)).toBe('14,8 MB');
    expect(formatBytes(2_000_000_000)).toBe('2 GB');
  });

  it('csvToList trimmt und filtert leere Einträge', () => {
    expect(csvToList(' deploy , root ,, ')).toEqual(['deploy', 'root']);
  });
});
