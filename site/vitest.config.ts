/// <reference types="vitest/config" />
// Unit tests for the logic in src/lib. getViteConfig gives the tests the same
// environment as the site build (import.meta.env.BASE_URL, SITE).
import { getViteConfig } from 'astro/config';

export default getViteConfig({
  test: {
    include: ['tests/unit/**/*.test.ts'],
  },
});
