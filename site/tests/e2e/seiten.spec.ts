// Every page from the sitemap: loads, has exactly one H1, no JS errors, no horizontal
// scrolling, and no WCAG 2.1 A/AA violations found by axe.
import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import { seitenAusSitemap } from './hilfen';

test('the sitemap lists the main pages', async ({ request }) => {
  const seiten = await seitenAusSitemap(request);
  for (const teil of ['/vergleichstest/', '/blog/', '/kontakt/', '/impressum/', '/datenschutz/']) {
    expect(
      seiten.some((s) => s.endsWith(teil)),
      teil,
    ).toBe(true);
  }
});

test('all pages are accessible and intact', async ({ page, request }) => {
  test.setTimeout(120_000);
  const seiten = await seitenAusSitemap(request);
  expect(seiten.length).toBeGreaterThan(5);

  for (const pfad of seiten) {
    await test.step(pfad, async () => {
      const fehler: string[] = [];
      page.removeAllListeners('pageerror');
      page.on('pageerror', (e) => fehler.push(e.message));

      const antwort = await page.goto(pfad);
      expect(antwort?.status(), pfad).toBe(200);
      await expect(page.locator('h1'), pfad).toHaveCount(1);

      const breite = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      expect(breite, `${pfad}: horizontales Scrollen`).toBeLessThanOrEqual(0);

      const axe = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
      const verstoesse = axe.violations.map((v) => `${v.id} (${v.nodes.length}x): ${v.help}`);
      expect(verstoesse, pfad).toEqual([]);

      expect(fehler, pfad).toEqual([]);
    });
  }
});
