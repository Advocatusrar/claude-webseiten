// Calculation logic for both calculators. Used by the server rendering
// (components' frontmatter) and by the client scripts, so the formula exists once.
import { zahl, zahlFlexibel } from './format';

// ---------------------------------------------------------------------------
// Types for src/data/rechner.json (loose on purpose: optional fields such as
// begruendung, quelle, quellen or handmasse may be added at any time).
// ---------------------------------------------------------------------------

export type Status = 'annahme' | 'quelle' | 'gemessen' | (string & {});

export interface Parameter {
  label: string;
  einheit?: string;
  wert: number | null;
  status?: Status;
  quelle?: unknown;
  quellen?: unknown;
  hinweis?: string | null;
  begruendung?: string | null;
  [feld: string]: unknown;
}

export interface Regler {
  label: string;
  einheit?: string;
  min: number;
  max: number;
  step: number;
  default: number;
}

export interface Spanne {
  min: number;
  max: number;
}

export interface Altersgruppe {
  von: number;
  bis: number;
  laenge_mm: Spanne;
  durchmesser_mm: Spanne;
  aufsicht?: string;
  status?: Status;
  hinweis?: string | null;
  begruendung?: string | null;
  quelle?: unknown;
  quellen?: unknown;
  handmasse?: unknown;
  [feld: string]: unknown;
}

export interface RechnerDaten {
  stand?: string;
  lebensdauer: {
    parameter: Record<string, Parameter>;
    regler: Record<string, Regler>;
  };
  stablaenge_nach_alter: {
    regler: { alter: Regler } & Record<string, Regler>;
    altersgruppen: Altersgruppe[];
  };
}

// ---------------------------------------------------------------------------
// Status, sources and extra fields
// ---------------------------------------------------------------------------

export function statusText(status: Status | undefined | null): string {
  switch (status) {
    case 'annahme':
      return 'Annahme';
    case 'quelle':
      return 'Quelle';
    case 'gemessen':
      return 'Eigene Messung';
    default:
      return status ? String(status) : 'Ohne Angabe';
  }
}

export function istAnnahme(eintrag: { status?: Status | null }): boolean {
  return eintrag.status === 'annahme';
}

/** How many of the entries are still assumptions: 'alle', 'einige' or 'keine'. */
export function anteilAnnahmen(eintraege: { status?: Status | null }[]): 'alle' | 'einige' | 'keine' {
  const anzahl = eintraege.filter((e) => istAnnahme(e)).length;
  if (anzahl === 0) return 'keine';
  return anzahl === eintraege.length ? 'alle' : 'einige';
}

export interface QuelleAnzeige {
  titel: string;
  url?: string;
  abgerufen?: string;
}

function text(wert: unknown): string | undefined {
  if (typeof wert === 'string' && wert.trim()) return wert.trim();
  if (typeof wert === 'number') return String(wert);
  return undefined;
}

function hostname(adresse: string): string {
  try {
    return new URL(adresse).hostname.replace(/^www\./, '');
  } catch {
    return adresse;
  }
}

/** Normalises "quelle"/"quellen" (null, URL string, text, object or array) to a list. */
export function quellenAus(...werte: unknown[]): QuelleAnzeige[] {
  const liste: QuelleAnzeige[] = [];
  const add = (q: unknown): void => {
    if (q == null || q === '') return;
    if (Array.isArray(q)) {
      q.forEach(add);
      return;
    }
    if (typeof q === 'string') {
      const s = q.trim();
      if (/^https?:\/\//i.test(s)) liste.push({ titel: hostname(s), url: s });
      else if (s) liste.push({ titel: s });
      return;
    }
    if (typeof q === 'object') {
      const o = q as Record<string, unknown>;
      const adresse = text(o.url ?? o.link ?? o.href);
      const titel = text(o.titel ?? o.title ?? o.name) ?? (adresse ? hostname(adresse) : undefined);
      if (!titel) return;
      const gueltigeUrl = adresse && /^https?:\/\//i.test(adresse) ? adresse : undefined;
      liste.push({ titel, url: gueltigeUrl, abgerufen: text(o.abgerufen ?? o.abgerufen_am ?? o.datum) });
    }
  };
  werte.forEach(add);
  return liste;
}

const SCHLUESSEL: Record<string, string> = {
  handlaenge_cm: 'Handlänge (cm)',
  handlaenge_mm: 'Handlänge (mm)',
  handbreite_cm: 'Handbreite (cm)',
  handbreite_mm: 'Handbreite (mm)',
  laenge_mm: 'Länge (mm)',
  durchmesser_mm: 'Durchmesser (mm)',
  min: 'von',
  max: 'bis',
  quelle: 'Quelle',
  hinweis: 'Hinweis',
  begruendung: 'Begründung',
  status: 'Status',
  wert: 'Wert',
  einheit: 'Einheit',
};

function schluesselName(schluessel: string): string {
  if (SCHLUESSEL[schluessel]) return SCHLUESSEL[schluessel];
  const einheit = schluessel.match(/_(mm|cm|m|g|kg|mg)$/);
  const name = (einheit ? schluessel.slice(0, -einheit[0].length) : schluessel).replace(/_/g, ' ');
  const gross = name.charAt(0).toUpperCase() + name.slice(1);
  return einheit ? `${gross} (${einheit[1]})` : gross;
}

/** Readable text for an optional extra field of unknown shape (e.g. "handmasse"). */
export function beschreibeWert(wert: unknown): string {
  if (wert == null) return '';
  if (typeof wert === 'string') return wert;
  if (typeof wert === 'number') return zahlFlexibel(wert);
  if (typeof wert === 'boolean') return wert ? 'ja' : 'nein';
  if (Array.isArray(wert)) return wert.map(beschreibeWert).filter(Boolean).join('; ');
  if (typeof wert === 'object') {
    const o = wert as Record<string, unknown>;
    if (
      typeof o.min === 'number' &&
      typeof o.max === 'number' &&
      Object.keys(o).every((k) => ['min', 'max', 'einheit'].includes(k))
    ) {
      const einheit = typeof o.einheit === 'string' && o.einheit ? ` ${o.einheit}` : '';
      return o.min === o.max
        ? `${zahlFlexibel(o.min)}${einheit}`
        : `${zahlFlexibel(o.min)} bis ${zahlFlexibel(o.max)}${einheit}`;
    }
    return Object.entries(o)
      .filter(([, v]) => v != null && v !== '')
      .map(([k, v]) => `${schluesselName(k)}: ${beschreibeWert(v)}`)
      .join('; ');
  }
  return String(wert);
}

// ---------------------------------------------------------------------------
// Calculator 1: how long does a ferro rod last?
// ---------------------------------------------------------------------------

export interface LebensdauerParameter {
  dichte_g_cm3: number;
  abtrag_mg_pro_zug: number;
  rest_durchmesser_mm: number;
  griff_laenge_mm: number;
}

export interface LebensdauerEingabe {
  laenge_mm: number;
  durchmesser_mm: number;
  zuege_pro_zuendung: number;
  zuendungen_pro_woche: number;
}

export interface LebensdauerErgebnis {
  nutzbar: boolean;
  grund: 'laenge' | 'durchmesser' | 'eingabe' | null;
  nutzbareLaenge_mm: number;
  volumen_mm3: number;
  masse_mg: number;
  zuege: number;
  zuendungen: number;
  wochen: number;
  jahre: number;
}

export const WOCHEN_PRO_JAHR = 365.25 / 7;

function num(wert: unknown): number {
  const n = typeof wert === 'number' ? wert : Number(wert);
  return Number.isFinite(n) ? n : 0;
}

export function lebensdauerParameter(daten: RechnerDaten): LebensdauerParameter {
  const p = daten.lebensdauer.parameter;
  return {
    dichte_g_cm3: num(p.dichte_g_cm3?.wert),
    abtrag_mg_pro_zug: num(p.abtrag_mg_pro_zug?.wert),
    rest_durchmesser_mm: num(p.rest_durchmesser_mm?.wert),
    griff_laenge_mm: num(p.griff_laenge_mm?.wert),
  };
}

export function lebensdauerStandard(daten: RechnerDaten): LebensdauerEingabe {
  const r = daten.lebensdauer.regler;
  return {
    laenge_mm: num(r.laenge_mm?.default),
    durchmesser_mm: num(r.durchmesser_mm?.default),
    zuege_pro_zuendung: num(r.zuege_pro_zuendung?.default),
    zuendungen_pro_woche: num(r.zuendungen_pro_woche?.default),
  };
}

/**
 * Rough estimate, assumes the rod wears evenly:
 * usable length L_n = L - grip length
 * usable volume V = pi/4 * (d^2 - d_rest^2) * L_n            [mm^3]
 * mass m = V / 1000 [cm^3] * density [g/cm^3] * 1000          [mg]
 * strikes = m / wear per strike; ignitions = strikes / strikes per ignition;
 * weeks = ignitions / ignitions per week; years = weeks / (365.25 / 7)
 */
export function berechneLebensdauer(e: LebensdauerEingabe, p: LebensdauerParameter): LebensdauerErgebnis {
  const nutzbareLaenge = e.laenge_mm - p.griff_laenge_mm;
  const leer = (grund: LebensdauerErgebnis['grund']): LebensdauerErgebnis => ({
    nutzbar: false,
    grund,
    nutzbareLaenge_mm: Math.max(0, nutzbareLaenge),
    volumen_mm3: 0,
    masse_mg: 0,
    zuege: 0,
    zuendungen: 0,
    wochen: 0,
    jahre: 0,
  });
  if (!(nutzbareLaenge > 0)) return leer('laenge');
  if (!(e.durchmesser_mm > p.rest_durchmesser_mm)) return leer('durchmesser');
  if (!(p.abtrag_mg_pro_zug > 0 && p.dichte_g_cm3 > 0 && e.zuege_pro_zuendung > 0 && e.zuendungen_pro_woche > 0)) {
    return leer('eingabe');
  }
  const volumen = (Math.PI / 4) * (e.durchmesser_mm ** 2 - p.rest_durchmesser_mm ** 2) * nutzbareLaenge;
  const masse = (volumen / 1000) * p.dichte_g_cm3 * 1000;
  const zuege = masse / p.abtrag_mg_pro_zug;
  const zuendungen = zuege / e.zuege_pro_zuendung;
  const wochen = zuendungen / e.zuendungen_pro_woche;
  return {
    nutzbar: true,
    grund: null,
    nutzbareLaenge_mm: nutzbareLaenge,
    volumen_mm3: volumen,
    masse_mg: masse,
    zuege,
    zuendungen,
    wochen,
    jahre: wochen / WOCHEN_PRO_JAHR,
  };
}

function plural(n: number, einzahl: string, mehrzahl: string): string {
  return n === 1 ? einzahl : mehrzahl;
}

/** Whole numbers below 1000, tens from 1000 on (avoids false precision in a rough estimate). */
function sinnvollGerundet(n: number): number {
  return n >= 1000 ? Math.round(n / 10) * 10 : Math.round(n);
}

/** Below half a week the rounded value would be 0, which reads like the error case. */
const WENIGER_ALS_EINE_WOCHE = 0.5;
/** Below this, "0,0 Jahre" would be shown. */
const UNTER_EINEM_ZEHNTEL_JAHR = 0.05;

function wochenText(wochen: number): string {
  return wochen < WENIGER_ALS_EINE_WOCHE ? 'unter 1' : zahl(sinnvollGerundet(wochen));
}

/** One decimal below 10 years, whole years up to 100, then "über 100". */
function jahreText(jahre: number): string {
  if (jahre <= 0) return zahl(0, 1);
  if (jahre < UNTER_EINEM_ZEHNTEL_JAHR) return 'unter 0,1';
  if (Math.round(jahre * 10) / 10 < 10) return zahl(jahre, 1);
  if (Math.round(jahre) <= 100) return zahl(Math.round(jahre));
  return 'über 100';
}

export interface LebensdauerAnzeige {
  satz: string;
  felder: {
    zuege: string;
    zuendungen: string;
    wochen: string;
    jahre: string;
    masse_g: string;
    volumen_cm3: string;
    nutzbare_laenge_mm: string;
  };
}

/**
 * Rounded, German-formatted values plus a summary sentence.
 * With `annahmen`, the sentence says that it rests on preliminary assumptions.
 */
export function lebensdauerAnzeige(
  e: LebensdauerEingabe,
  erg: LebensdauerErgebnis,
  p: LebensdauerParameter,
  optionen: { annahmen?: boolean } = {},
): LebensdauerAnzeige {
  // Strikes and ignitions use the same rounding, so they agree at 1 strike per ignition.
  const felder = {
    zuege: zahl(sinnvollGerundet(erg.zuege)),
    zuendungen: zahl(sinnvollGerundet(erg.zuendungen)),
    wochen: erg.nutzbar ? wochenText(erg.wochen) : zahl(0),
    jahre: erg.nutzbar ? jahreText(erg.jahre) : zahl(0, 1),
    masse_g: zahl(erg.masse_mg / 1000, 1),
    volumen_cm3: zahl(erg.volumen_mm3 / 1000, 2),
    nutzbare_laenge_mm: zahlFlexibel(erg.nutzbareLaenge_mm),
  };
  const L = zahlFlexibel(e.laenge_mm);
  const d = zahlFlexibel(e.durchmesser_mm);
  let satz: string;
  if (erg.nutzbar) {
    const wochenGerundet = sinnvollGerundet(erg.wochen);
    let dauer: string;
    if (erg.wochen < WENIGER_ALS_EINE_WOCHE) dauer = 'weniger als eine Woche';
    else if (erg.jahre < UNTER_EINEM_ZEHNTEL_JAHR)
      dauer = `etwa ${felder.wochen} ${plural(wochenGerundet, 'Woche', 'Wochen')}`;
    else dauer = `etwa ${felder.wochen} Wochen oder ${felder.jahre} Jahre`;
    const anfang = optionen.annahmen
      ? `Mit den vorläufigen Annahmen reicht ein Stab mit ${L} mm Länge und ${d} mm Durchmesser`
      : `Ein Stab mit ${L} mm Länge und ${d} mm Durchmesser reicht`;
    satz =
      `${anfang} grob geschätzt für etwa ${felder.zuege} Züge. ` +
      `Bei ${zahlFlexibel(e.zuege_pro_zuendung)} ${plural(e.zuege_pro_zuendung, 'Zug', 'Zügen')} pro Zündung sind das rund ${felder.zuendungen} Zündungen, ` +
      `bei ${zahlFlexibel(e.zuendungen_pro_woche)} ${plural(e.zuendungen_pro_woche, 'Zündung', 'Zündungen')} pro Woche also ${dauer}.`;
  } else if (erg.grund === 'laenge') {
    satz =
      `Ergebnis: 0 Züge. Nach Abzug der ${zahlFlexibel(p.griff_laenge_mm)} mm, die im Griff stecken, ` +
      `bleibt bei ${L} mm Stablänge nichts zum Abziehen übrig.`;
  } else if (erg.grund === 'durchmesser') {
    satz =
      `Ergebnis: 0 Züge. Der Durchmesser von ${d} mm liegt nicht über dem Rest-Durchmesser von ` +
      `${zahlFlexibel(p.rest_durchmesser_mm)} mm, ab dem ein Stab als verbraucht gilt.`;
  } else {
    satz = 'Ergebnis: 0 Züge. Mit diesen Werten lässt sich nichts berechnen. Bitte prüfe die Eingaben.';
  }
  return { satz, felder };
}

// ---------------------------------------------------------------------------
// Calculator 2: rod size by age
// ---------------------------------------------------------------------------

export function findeAltersgruppe(alter: number, gruppen: Altersgruppe[]): Altersgruppe | undefined {
  return gruppen.find((g) => alter >= g.von && alter <= g.bis);
}

export function spanneText(s: Spanne | undefined, einheit = 'mm'): string {
  if (!s) return 'keine Angabe';
  return s.min === s.max
    ? `${zahlFlexibel(s.min)} ${einheit}`
    : `${zahlFlexibel(s.min)} bis ${zahlFlexibel(s.max)} ${einheit}`;
}

export function altersgruppeText(g: Altersgruppe, hoechstesAlter: number): string {
  return g.bis >= hoechstesAlter ? `ab ${g.von} Jahren` : `${g.von} bis ${g.bis} Jahre`;
}

export interface AltersAnzeige {
  satz: string;
  laenge: string;
  durchmesser: string;
  aufsicht: string;
  /** Label for the supervision line, marks it as an unchecked assumption. */
  aufsichtTitel: string;
  begruendung: string;
  handmasse: string;
  status: string;
  annahme: boolean;
  gruppeIndex: number;
}

export function altersAnzeige(alter: number, gruppen: Altersgruppe[]): AltersAnzeige {
  const gruppe = findeAltersgruppe(alter, gruppen);
  const jahre = `${zahlFlexibel(alter)} ${alter === 1 ? 'Jahr' : 'Jahre'}`;
  if (!gruppe) {
    return {
      satz: `Für ${jahre} liegt noch kein Richtwert vor.`,
      laenge: 'keine Angabe',
      durchmesser: 'keine Angabe',
      aufsicht: 'keine Angabe',
      aufsichtTitel: 'Aufsicht',
      begruendung: '',
      handmasse: '',
      status: '',
      annahme: false,
      gruppeIndex: -1,
    };
  }
  const laenge = spanneText(gruppe.laenge_mm);
  const durchmesser = spanneText(gruppe.durchmesser_mm);
  // As long as a group is an assumption, its values are no recommendation.
  const annahme = istAnnahme(gruppe);
  return {
    satz: annahme
      ? `Vorläufiger Richtwert für ${jahre} (Annahme, nicht belegt): Stablänge ${laenge}, Durchmesser ${durchmesser}.`
      : `Richtwert für ${jahre}: Stablänge ${laenge}, Durchmesser ${durchmesser}.`,
    laenge,
    durchmesser,
    aufsicht: gruppe.aufsicht ?? 'keine Angabe',
    aufsichtTitel: annahme ? 'Aufsicht (ungeprüfte Annahme)' : 'Aufsicht',
    begruendung: beschreibeWert(gruppe.begruendung),
    handmasse: beschreibeWert(gruppe.handmasse),
    status: statusText(gruppe.status),
    annahme,
    gruppeIndex: gruppen.indexOf(gruppe),
  };
}
