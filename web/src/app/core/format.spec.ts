import { describe, expect, it } from 'vitest';

import { csvToList, formatSeconds, tagsToText, textToTags } from './format';

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

  it('csvToList trimmt und filtert leere Einträge', () => {
    expect(csvToList(' deploy , root ,, ')).toEqual(['deploy', 'root']);
  });
});
