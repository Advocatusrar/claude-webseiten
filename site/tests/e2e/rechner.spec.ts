// The calculators react to the sliders, work by keyboard and show a result without JavaScript.
import { expect, test } from '@playwright/test';

test.describe('Lebensdauer-Rechner', () => {
  test('updates the result when a slider moves', async ({ page }) => {
    await page.goto('vergleichstest/');
    const rechner = page.locator('[data-rechner="lebensdauer"]');
    const zuege = rechner.locator('[data-feld="zuege"]');
    const vorher = await zuege.textContent();

    await rechner.locator('#ld-laenge_mm').focus();
    await page.keyboard.press('ArrowRight');
    await page.keyboard.press('ArrowRight');

    await expect(zuege).not.toHaveText(vorher ?? '');
    await expect(rechner).not.toContainText(/NaN|undefined|Infinity/);
  });

  test('accepts a decimal comma and explains invalid input', async ({ page }) => {
    await page.goto('vergleichstest/');
    const rechner = page.locator('[data-rechner="lebensdauer"]');
    const feld = rechner.locator('#ld-durchmesser_mm-zahl');

    await feld.fill('7,5');
    await expect(rechner.locator('#ld-durchmesser_mm')).toHaveValue('7.5');

    await feld.fill('500');
    await expect(feld).toHaveAttribute('aria-invalid', 'true');
    await expect(rechner.locator('[data-hinweis="durchmesser_mm"]')).toContainText('Außerhalb des Bereichs');
    await expect(rechner).not.toContainText(/NaN|undefined|Infinity/);
  });
});

test.describe('Altersrechner', () => {
  test('marks the matching row and keeps assumptions visible', async ({ page }) => {
    await page.goto('vergleichstest/');
    const rechner = page.locator('[data-rechner="alter"]');
    await rechner.locator('#alt-alter').focus();
    await page.keyboard.press('End');
    await expect(rechner.locator('[data-feld="satz"]')).toContainText('Annahme');
    await expect(rechner.locator('tr.aktiv')).toHaveCount(1);
  });
});

test.describe('ohne JavaScript', () => {
  test.use({ javaScriptEnabled: false });

  test('shows the default results and the age table', async ({ page }) => {
    await page.goto('vergleichstest/');
    await expect(page.locator('[data-rechner="lebensdauer"] [data-feld="zuege"]')).toHaveText(/\d/);
    await expect(page.locator('[data-rechner="alter"] table tbody tr')).not.toHaveCount(0);
  });
});
