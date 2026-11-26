// The central setting holds the decided site name as raw text (no HTML entities), and the
// structured data take it over unchanged. The built pages are checked in tests/e2e/seitenname.spec.ts.
import { describe, expect, it } from 'vitest';
import { SITE } from '../../src/site';
import { autorLd, ORGANISATION, VORSCHAUBILD } from '../../src/lib/jsonld';
import { SEITENNAME } from '../e2e/hilfen';

describe('site name', () => {
  it('is the decided name, written with a raw "&"', () => {
    expect(SITE.name).toBe(SEITENNAME);
  });

  it('goes unchanged into organisation, editorial author and image text', () => {
    expect(ORGANISATION.name).toBe(SEITENNAME);
    expect(autorLd('Redaktion')).toEqual(
      expect.objectContaining({ '@type': 'Organization', name: `Redaktion ${SEITENNAME}` }),
    );
    expect(VORSCHAUBILD.alt).toContain(SEITENNAME);
  });
});
