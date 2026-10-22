import { describe, expect, it } from 'vitest';
import { datumDeutsch, datumIso, mitEinheit, zahl, zahlEingabe, zahlFlexibel } from '../../src/lib/format';

describe('format', () => {
  it('formats dates in German without time zone shifts', () => {
    expect(datumDeutsch('2026-10-22')).toBe('22. Oktober 2026');
    expect(datumDeutsch(new Date('2026-01-01'))).toBe('1. Januar 2026');
    expect(datumIso(new Date('2026-10-22'))).toBe('2026-10-22');
  });

  it('formats numbers in German', () => {
    expect(zahl(1234.5, 1)).toBe('1.234,5');
    expect(zahl(8.24, 1)).toBe('8,2');
    expect(zahlFlexibel(6)).toBe('6');
    expect(zahlFlexibel(6.4)).toBe('6,4');
    expect(zahlEingabe(7.5)).toBe('7,5');
    expect(mitEinheit(7.5, 'mm')).toBe('7,5 mm');
    expect(mitEinheit(5)).toBe('5');
  });
});
