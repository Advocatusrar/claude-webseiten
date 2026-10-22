// Central site settings. Values in [eckigen Klammern] are placeholders the operators must fill in.
export const SITE = {
  // Working title, not final.
  name: 'Funkenschlag',
  // Shown in <title> and og:title of the start page; with the name below 60 characters.
  // Only say "getestet" again once products with own test results are published.
  claim: 'Feuerstahl und Striker unabhängig erklärt',
  sprache: 'de-DE',
  betreiber: {
    name: '[Vorname Nachname]',
    strasse: '[Straße Hausnummer]',
    ort: '[PLZ Ort]',
    email: '[kontakt@example.org]',
  },
} as const;

/** True for a value that is still a placeholder in [eckigen Klammern]. */
export function istPlatzhalter(wert: string): boolean {
  return /^\s*\[.*\]\s*$/.test(wert);
}
