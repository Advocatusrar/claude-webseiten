// German formatting for dates and numbers. Used on the server and in client scripts.

const datumFormat = new Intl.DateTimeFormat('de-DE', {
  day: 'numeric',
  month: 'long',
  year: 'numeric',
  // Dates from frontmatter ("2026-10-22") are parsed as UTC midnight.
  timeZone: 'UTC',
});

/** "22. Oktober 2026" */
export function datumDeutsch(datum: Date | string): string {
  return datumFormat.format(typeof datum === 'string' ? new Date(datum) : datum);
}

/** "2026-10-22" for the datetime attribute of <time>. */
export function datumIso(datum: Date | string): string {
  const d = typeof datum === 'string' ? new Date(datum) : datum;
  return d.toISOString().slice(0, 10);
}

/** German number format with a fixed number of decimals, e.g. zahl(8.24, 1) -> "8,2". */
export function zahl(wert: number, nachkommastellen = 0): string {
  return new Intl.NumberFormat('de-DE', {
    minimumFractionDigits: nachkommastellen,
    maximumFractionDigits: nachkommastellen,
  }).format(wert);
}

/** German number format that shows decimals only when needed (max. 2), e.g. 6 -> "6", 6.4 -> "6,4". */
export function zahlFlexibel(wert: number): string {
  return new Intl.NumberFormat('de-DE', { maximumFractionDigits: 2 }).format(wert);
}

/** Number for a text input field: German decimal comma, no thousands separator, e.g. 7.5 -> "7,5". */
export function zahlEingabe(wert: number): string {
  return String(wert).replace('.', ',');
}

/** Number with optional unit, e.g. mitEinheit(7.5, 'mm') -> "7,5 mm", mitEinheit(5, '') -> "5". */
export function mitEinheit(wert: number, einheit = ''): string {
  return einheit ? `${zahlFlexibel(wert)} ${einheit}` : zahlFlexibel(wert);
}
