import { describe, expect, it } from 'vitest';

import { csvToList, formatBytes, formatSeconds, tagsToText, textToTags } from './format';

describe('format helpers', () => {
  it('formatSeconds picks the largest whole unit', () => {
    expect(formatSeconds(30 * 86400)).toBe('30 d');
    expect(formatSeconds(16 * 3600)).toBe('16 h');
    expect(formatSeconds(45 * 60)).toBe('45 min');
    expect(formatSeconds(90)).toBe('90 s');
  });

  it('textToTags parses key=value lists and round-trips with tagsToText', () => {
    const tags = textToTags('env=prod, role=web');
    expect(tags).toEqual({ env: 'prod', role: 'web' });
    expect(textToTags(tagsToText(tags))).toEqual(tags);
    expect(textToTags('')).toEqual({});
    expect(() => textToTags('broken')).toThrow();
  });

  it('formatBytes scales to the matching unit', () => {
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(14_800_000)).toBe('14.8 MB');
    expect(formatBytes(2_000_000_000)).toBe('2 GB');
  });

  it('csvToList trims and filters out empty entries', () => {
    expect(csvToList(' deploy , root ,, ')).toEqual(['deploy', 'root']);
  });
});
