// Client-side helpers for the calculators: keeps each range slider and its text
// field in sync, explains every correction next to the field and announces results
// to screen readers once the input pauses.
import { mitEinheit, zahlEingabe, zahlFlexibel } from './format';

/** Reads "7,5" or "7.5" (spaces ignored). Returns NaN for anything else. */
export function leseZahl(text: string): number {
  const t = text.replace(/\s+/g, '').replace(',', '.');
  return /^-?(?:\d+(?:\.\d*)?|\.\d+)$/.test(t) ? Number(t) : Number.NaN;
}

/**
 * Connects every <input type="range" data-regler="name"> inside root with its text
 * field <input data-zahl="name"> (type="text", inputmode="decimal", accepts a decimal
 * comma) and calls beiAenderung on every change of the value used for calculating.
 * A hint element [data-hinweis="name"] next to the field says when a value is invalid,
 * limited to the allowed range or rounded to the step; the field gets aria-invalid
 * while its text is not used. Returns a getter for the current value of a slider.
 */
export function verbindeRegler(root: HTMLElement, beiAenderung: () => void): (name: string) => number {
  const regler = new Map<string, HTMLInputElement>();

  root.querySelectorAll<HTMLInputElement>('input[type="range"][data-regler]').forEach((range) => {
    const name = range.dataset.regler ?? '';
    regler.set(name, range);
    const zahlFeld = root.querySelector<HTMLInputElement>(`input[data-zahl="${name}"]`);
    const hinweis = root.querySelector<HTMLElement>(`[data-hinweis="${name}"]`);
    const einheit = range.dataset.einheit ?? '';
    const min = Number(range.min);
    const max = Number(range.max);
    const step = Number(range.step) || 1;
    const text = (n: number) => mitEinheit(n, einheit);
    const bereich = `Erlaubt sind ${text(min)} bis ${text(max)}.`;

    const aktuell = () => Number(range.value);
    const setzeValuetext = () => range.setAttribute('aria-valuetext', text(aktuell()));

    function melde(meldung: string, ungueltig: boolean): void {
      if (hinweis && hinweis.textContent !== meldung) hinweis.textContent = meldung;
      if (!zahlFeld) return;
      if (ungueltig) zahlFeld.setAttribute('aria-invalid', 'true');
      else zahlFeld.removeAttribute('aria-invalid');
    }

    range.addEventListener('input', () => {
      if (zahlFeld) zahlFeld.value = zahlEingabe(aktuell());
      melde('', false);
      setzeValuetext();
      beiAenderung();
    });

    setzeValuetext();
    if (!zahlFeld) return;

    // While typing: use valid values at once (snapped to the step), explain the rest.
    zahlFeld.addEventListener('input', () => {
      if (zahlFeld.value.trim() === '') {
        melde(`Bitte eine Zahl eingeben. ${bereich}`, true);
        return;
      }
      const n = leseZahl(zahlFeld.value);
      if (!Number.isFinite(n)) {
        melde(`Keine gültige Zahl. ${bereich} Gerechnet wird weiter mit ${text(aktuell())}.`, true);
        return;
      }
      if (n < min || n > max) {
        melde(`Außerhalb des Bereichs. ${bereich} Gerechnet wird weiter mit ${text(aktuell())}.`, true);
        return;
      }
      range.value = String(n);
      const gerastet = aktuell();
      melde(gerastet !== n ? `Gerechnet wird mit ${text(gerastet)} (Schrittweite ${zahlFlexibel(step)}).` : '', false);
      setzeValuetext();
      beiAenderung();
    });

    // On leaving the field: limit to the range, snap to the step and say so.
    zahlFeld.addEventListener('change', () => {
      const n = leseZahl(zahlFeld.value);
      let meldung = '';
      if (!Number.isFinite(n)) {
        meldung = `Keine gültige Zahl, zurückgesetzt auf ${text(aktuell())}.`;
      } else {
        const begrenzt = Math.min(max, Math.max(min, n));
        range.value = String(begrenzt);
        if (begrenzt !== n) meldung = `Auf ${text(aktuell())} begrenzt. ${bereich}`;
        else if (aktuell() !== n) meldung = `Auf ${text(aktuell())} gerundet (Schrittweite ${zahlFlexibel(step)}).`;
      }
      zahlFeld.value = zahlEingabe(aktuell());
      melde(meldung, false);
      setzeValuetext();
      beiAenderung();
    });

    // Keep both fields equal if the browser restored form state (back button).
    zahlFeld.value = zahlEingabe(aktuell());
  });

  return (name: string) => Number(regler.get(name)?.value ?? Number.NaN);
}

export function setzeText(root: HTMLElement, feld: string, text: string): void {
  root.querySelectorAll<HTMLElement>(`[data-feld="${feld}"]`).forEach((el) => {
    if (el.textContent !== text) el.textContent = text;
  });
}

/**
 * Screen reader announcement via the visually hidden role="status" element
 * [data-ansage] inside root. Only announces once the input has paused for 400 ms,
 * so holding an arrow key does not queue up long sentences. The visible result
 * updates immediately elsewhere; the announcement is cleared again after a while
 * so it is not read twice when browsing the page.
 */
export function erstelleAnsage(root: HTMLElement, verzoegerung = 400): (text: string) => void {
  const region = root.querySelector<HTMLElement>('[data-ansage]');
  let warten: ReturnType<typeof setTimeout> | undefined;
  let leeren: ReturnType<typeof setTimeout> | undefined;
  return (text: string) => {
    if (!region) return;
    clearTimeout(warten);
    clearTimeout(leeren);
    warten = setTimeout(() => {
      region.textContent = text;
      leeren = setTimeout(() => {
        region.textContent = '';
      }, 7000);
    }, verzoegerung);
  };
}
