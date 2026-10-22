import { describe, expect, it } from 'vitest';
import daten from '../../src/data/rechner.json';
import {
  altersAnzeige,
  anteilAnnahmen,
  berechneLebensdauer,
  findeAltersgruppe,
  lebensdauerAnzeige,
  lebensdauerParameter,
  lebensdauerStandard,
  quellenAus,
  WOCHEN_PRO_JAHR,
  type LebensdauerParameter,
  type RechnerDaten,
} from '../../src/lib/rechner';

const DATEN = daten as RechnerDaten;

// Fixed parameters, independent of the (still preliminary) values in rechner.json.
const P: LebensdauerParameter = {
  dichte_g_cm3: 6,
  abtrag_mg_pro_zug: 5,
  rest_durchmesser_mm: 3,
  griff_laenge_mm: 25,
};

describe('berechneLebensdauer', () => {
  it('follows the documented formula step by step', () => {
    const e = { laenge_mm: 100, durchmesser_mm: 10, zuege_pro_zuendung: 5, zuendungen_pro_woche: 3 };
    const erg = berechneLebensdauer(e, P);
    const volumen = (Math.PI / 4) * (10 ** 2 - 3 ** 2) * 75; // mm³
    const masse = volumen * 6; // mm³ * g/cm³ = mg
    expect(erg.nutzbar).toBe(true);
    expect(erg.nutzbareLaenge_mm).toBe(75);
    expect(erg.volumen_mm3).toBeCloseTo(volumen, 6);
    expect(erg.masse_mg).toBeCloseTo(masse, 6);
    expect(erg.zuege).toBeCloseTo(masse / 5, 6);
    expect(erg.zuendungen).toBeCloseTo(masse / 5 / 5, 6);
    expect(erg.wochen).toBeCloseTo(masse / 5 / 5 / 3, 6);
    expect(erg.jahre).toBeCloseTo(erg.wochen / WOCHEN_PRO_JAHR, 9);
  });

  it('converts units correctly: 1 cm³ of a rod with density 1 weighs 1000 mg', () => {
    // d chosen so that pi/4 * d² * L = 1000 mm³ with L = 10 mm usable length
    const d = Math.sqrt(1000 / 10 / (Math.PI / 4));
    const erg = berechneLebensdauer(
      { laenge_mm: 10, durchmesser_mm: d, zuege_pro_zuendung: 1, zuendungen_pro_woche: 1 },
      { dichte_g_cm3: 1, abtrag_mg_pro_zug: 1, rest_durchmesser_mm: 0, griff_laenge_mm: 0 },
    );
    expect(erg.masse_mg).toBeCloseTo(1000, 6);
    expect(erg.zuege).toBeCloseTo(1000, 6);
  });

  it('doubles the strikes when the usable length doubles', () => {
    const a = berechneLebensdauer(
      { laenge_mm: 75, durchmesser_mm: 10, zuege_pro_zuendung: 5, zuendungen_pro_woche: 3 },
      P,
    );
    const b = berechneLebensdauer(
      { laenge_mm: 125, durchmesser_mm: 10, zuege_pro_zuendung: 5, zuendungen_pro_woche: 3 },
      P,
    );
    expect(b.zuege / a.zuege).toBeCloseTo(2, 9);
  });

  it.each([
    ['rod not longer than the grip', { laenge_mm: 25, durchmesser_mm: 10 }, 'laenge'],
    ['rod shorter than the grip', { laenge_mm: 10, durchmesser_mm: 10 }, 'laenge'],
    ['diameter equal to the rest diameter', { laenge_mm: 100, durchmesser_mm: 3 }, 'durchmesser'],
    ['diameter below the rest diameter', { laenge_mm: 100, durchmesser_mm: 2 }, 'durchmesser'],
  ] as const)('returns 0 with a reason for %s', (_, masse, grund) => {
    const erg = berechneLebensdauer({ ...masse, zuege_pro_zuendung: 5, zuendungen_pro_woche: 3 }, P);
    expect(erg.nutzbar).toBe(false);
    expect(erg.grund).toBe(grund);
    expect(erg.zuege).toBe(0);
    expect(erg.jahre).toBe(0);
  });

  it('never returns NaN or Infinity for invalid input', () => {
    const erg = berechneLebensdauer(
      { laenge_mm: 100, durchmesser_mm: 10, zuege_pro_zuendung: 0, zuendungen_pro_woche: 0 },
      { ...P, abtrag_mg_pro_zug: 0 },
    );
    expect(erg.grund).toBe('eingabe');
    for (const wert of Object.values(erg)) {
      if (typeof wert === 'number') expect(Number.isFinite(wert)).toBe(true);
    }
  });

  it('stays finite over the whole slider range', () => {
    const r = DATEN.lebensdauer.regler;
    const p = lebensdauerParameter(DATEN);
    for (const laenge_mm of [r.laenge_mm.min, r.laenge_mm.max]) {
      for (const durchmesser_mm of [r.durchmesser_mm.min, r.durchmesser_mm.max]) {
        for (const zuege_pro_zuendung of [r.zuege_pro_zuendung.min, r.zuege_pro_zuendung.max]) {
          for (const zuendungen_pro_woche of [r.zuendungen_pro_woche.min, r.zuendungen_pro_woche.max]) {
            const erg = berechneLebensdauer({ laenge_mm, durchmesser_mm, zuege_pro_zuendung, zuendungen_pro_woche }, p);
            const anzeige = lebensdauerAnzeige(
              { laenge_mm, durchmesser_mm, zuege_pro_zuendung, zuendungen_pro_woche },
              erg,
              p,
            );
            expect(anzeige.satz).not.toMatch(/NaN|undefined|Infinity/);
          }
        }
      }
    }
  });
});

describe('lebensdauerAnzeige', () => {
  it('formats German numbers and marks preliminary assumptions', () => {
    const e = { laenge_mm: 100, durchmesser_mm: 10, zuege_pro_zuendung: 5, zuendungen_pro_woche: 3 };
    const anzeige = lebensdauerAnzeige(e, berechneLebensdauer(e, P), P, { annahmen: true });
    // 6432 strikes -> rounded to tens, German thousands separator
    expect(anzeige.felder.zuege).toBe('6.430');
    expect(anzeige.felder.jahre).toBe('8,2');
    expect(anzeige.satz).toMatch(/^Mit den vorläufigen Annahmen/);
  });

  it('explains why the result is 0', () => {
    const e = { laenge_mm: 20, durchmesser_mm: 10, zuege_pro_zuendung: 5, zuendungen_pro_woche: 3 };
    const anzeige = lebensdauerAnzeige(e, berechneLebensdauer(e, P), P);
    expect(anzeige.satz).toContain('im Griff stecken');
  });
});

describe('rechner.json', () => {
  it('has slider defaults inside their range', () => {
    const regler = { ...DATEN.lebensdauer.regler, ...DATEN.stablaenge_nach_alter.regler };
    for (const [name, r] of Object.entries(regler)) {
      expect(r.min, name).toBeLessThan(r.max);
      expect(r.default, name).toBeGreaterThanOrEqual(r.min);
      expect(r.default, name).toBeLessThanOrEqual(r.max);
    }
  });

  it('assigns every age on the slider to exactly one group', () => {
    const { regler, altersgruppen } = DATEN.stablaenge_nach_alter;
    for (let alter = regler.alter.min; alter <= regler.alter.max; alter += regler.alter.step) {
      const treffer = altersgruppen.filter((g) => alter >= g.von && alter <= g.bis);
      expect(treffer, `Alter ${alter}`).toHaveLength(1);
    }
  });

  it('has min <= max in every range', () => {
    for (const g of DATEN.stablaenge_nach_alter.altersgruppen) {
      expect(g.laenge_mm.min).toBeLessThanOrEqual(g.laenge_mm.max);
      expect(g.durchmesser_mm.min).toBeLessThanOrEqual(g.durchmesser_mm.max);
    }
  });

  it('only uses known status values', () => {
    const alle = [...Object.values(DATEN.lebensdauer.parameter), ...DATEN.stablaenge_nach_alter.altersgruppen];
    for (const e of alle) expect(['annahme', 'quelle', 'gemessen']).toContain(e.status);
  });

  it('produces a usable default result', () => {
    const erg = berechneLebensdauer(lebensdauerStandard(DATEN), lebensdauerParameter(DATEN));
    expect(erg.nutzbar).toBe(true);
  });
});

describe('Altersrechner', () => {
  const gruppen = DATEN.stablaenge_nach_alter.altersgruppen;

  it('finds the group at its boundaries', () => {
    for (const g of gruppen) {
      expect(findeAltersgruppe(g.von, gruppen)).toBe(g);
      expect(findeAltersgruppe(g.bis, gruppen)).toBe(g);
    }
  });

  it('never presents an assumption as a recommendation', () => {
    for (const g of gruppen.filter((x) => x.status === 'annahme')) {
      const anzeige = altersAnzeige(g.von, gruppen);
      expect(anzeige.annahme).toBe(true);
      expect(anzeige.satz).toMatch(/Annahme/);
      expect(anzeige.satz).not.toMatch(/empfehl/i);
    }
  });

  it('handles an age outside all groups', () => {
    const anzeige = altersAnzeige(200, gruppen);
    expect(anzeige.gruppeIndex).toBe(-1);
    expect(anzeige.satz).toContain('noch kein Richtwert');
  });
});

describe('helpers', () => {
  it('counts assumptions', () => {
    expect(anteilAnnahmen([{ status: 'annahme' }, { status: 'annahme' }])).toBe('alle');
    expect(anteilAnnahmen([{ status: 'annahme' }, { status: 'quelle' }])).toBe('einige');
    expect(anteilAnnahmen([{ status: 'gemessen' }])).toBe('keine');
  });

  it('normalises sources in all supported shapes', () => {
    expect(quellenAus(null, '')).toEqual([]);
    expect(quellenAus('https://www.example.org/x')).toEqual([
      { titel: 'example.org', url: 'https://www.example.org/x' },
    ]);
    expect(quellenAus({ titel: 'DIN', url: 'javascript:alert(1)' })).toEqual([
      { titel: 'DIN', url: undefined, abgerufen: undefined },
    ]);
    expect(quellenAus([{ title: 'A', url: 'https://a.example' }, 'Buch'])).toHaveLength(2);
  });
});
