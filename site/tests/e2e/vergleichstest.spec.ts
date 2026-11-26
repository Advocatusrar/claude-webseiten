// The comparison page shows intro, test status, calculators, products and test method in this
// order; #rechner leads to the calculators, also from articles, and the meta description names them first.
import { expect, test } from '@playwright/test';
import { seitenAusSitemap } from './hilfen';

const REIHENFOLGE = ['Einleitung', 'Stand der Tests', 'Rechner', 'Produkte im Vergleich', 'So testen wir'];

test.describe('Vergleichstest', () => {
  test('shows intro, test status, calculators, products and test method in this order', async ({ page }) => {
    await page.goto('vergleichstest/');

    const bloecke = await page.evaluate(() => {
      const namen: string[] = [];
      for (let el = document.querySelector('main h1')?.nextElementSibling; el; el = el.nextElementSibling) {
        if (el.querySelector(':scope > p.lead')) namen.push('Einleitung');
        else if (el.matches('aside')) namen.push(el.getAttribute('aria-label') ?? 'aside');
        else if (el.matches('section')) namen.push(el.querySelector(':scope > h2')?.textContent?.trim() ?? 'section');
        else namen.push(el.tagName.toLowerCase());
      }
      return namen;
    });
    expect(bloecke).toEqual(REIHENFOLGE);

    // The visual order matches the document order (no CSS reordering).
    const teile = [
      page.locator('main p.lead'),
      page.locator('main aside[aria-label="Stand der Tests"]'),
      ...REIHENFOLGE.slice(2).map((titel) =>
        page.locator('main section').filter({ has: page.getByRole('heading', { level: 2, name: titel, exact: true }) }),
      ),
    ];
    const oben: number[] = [];
    for (const teil of teile) {
      await expect(teil).toHaveCount(1);
      oben.push((await teil.boundingBox())?.y ?? NaN);
    }
    for (let i = 1; i < oben.length; i++) expect(oben[i], REIHENFOLGE[i]).toBeGreaterThan(oben[i - 1]);
  });

  test('#rechner leads to the section with both calculators', async ({ page }) => {
    await page.goto('vergleichstest/#rechner');
    const ziel = page.locator('#rechner');

    await expect(ziel).toHaveCount(1);
    await expect(ziel).toHaveJSProperty('tagName', 'SECTION');
    await expect(ziel.getByRole('heading', { level: 2 })).toHaveText('Rechner');
    await expect(ziel.locator('[data-rechner="lebensdauer"]')).toHaveCount(1);
    await expect(ziel.locator('[data-rechner="alter"]')).toHaveCount(1);
    await expect(page.locator('[data-rechner]')).toHaveCount(2);

    await expect(page.locator(':target')).toHaveId('rechner');
    await expect.poll(async () => Math.abs((await ziel.boundingBox())?.y ?? NaN)).toBeLessThanOrEqual(1);
  });

  test('the meta description names the calculators first and has at most 155 characters', async ({ page }) => {
    await page.goto('vergleichstest/');
    const beschreibung = (await page.locator('meta[name="description"]').getAttribute('content')) ?? '';

    expect([...beschreibung].length).toBeGreaterThan(0);
    expect([...beschreibung].length).toBeLessThanOrEqual(155);
    const rechner = beschreibung.indexOf('Rechner');
    expect(rechner, 'Rechner').toBeGreaterThanOrEqual(0);
    for (const spaeter of ['Produkttabelle', 'Testmethode']) {
      expect(beschreibung.indexOf(spaeter), spaeter).toBeGreaterThan(rechner);
    }
    await expect(page.locator('meta[property="og:description"]')).toHaveAttribute('content', beschreibung);
  });

  test('links to #rechner from articles and other pages lead to the calculators', async ({ page, request }) => {
    test.setTimeout(60_000);
    const mitLink: string[] = [];

    for (const pfad of await seitenAusSitemap(request)) {
      await page.goto(pfad);
      // A link with a wrong path below /blog/ silently turns into "(Artikel folgt)" text.
      await expect(page.locator('.folgt', { hasText: 'Rechner' }), pfad).toHaveCount(0);
      const links = page.locator('a[href$="#rechner"]');
      const ziele = await links.evaluateAll((as) => as.map((a) => (a as HTMLAnchorElement).href));
      if (ziele.length === 0) continue;
      mitLink.push(pfad);

      for (const ziel of ziele) {
        expect(new URL(ziel).pathname, `${pfad}: ${ziel}`).toMatch(/\/vergleichstest\/$/);
      }

      await test.step(pfad, async () => {
        await links.first().click();
        await expect(page).toHaveURL(/\/vergleichstest\/#rechner$/);
        await expect(page.locator(':target')).toHaveId('rechner');
        await expect(page.getByRole('heading', { level: 2, name: 'Rechner', exact: true })).toBeInViewport();
      });
    }

    expect(
      mitLink.some((p) => /\/blog\/(?!zielgruppe\/)[^/]+\/$/.test(p)),
      `articles with a link to #rechner: ${mitLink.join(', ')}`,
    ).toBe(true);
  });
});
