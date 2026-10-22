import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { z } from 'astro/zod';

const themen = z.enum(['feuerstahl', 'striker', 'verbindung', 'sicherheit', 'recht']);
const zielgruppen = z.enum(['outdoor', 'bushcraft', 'selbstversorger', 'survival', 'eltern-kinder', 'linkshaender']);

const quelle = z.object({
  titel: z.string(),
  url: z.url(),
  abgerufen: z.coerce.date(),
});

const blog = defineCollection({
  loader: glob({ pattern: '**/[^_]*.md', base: './src/content/blog' }),
  schema: z.object({
    title: z.string().max(70),
    description: z.string().min(50).max(160),
    pubDate: z.coerce.date(),
    updatedDate: z.coerce.date().optional(),
    // Date the facts in this article were last checked; shown as "Stand" on the page.
    stand: z.coerce.date(),
    autor: z.string().default('Redaktion'),
    themen: z.array(themen).min(1),
    zielgruppen: z.array(zielgruppen).min(1),
    // true only if the article contains results from our own hands-on tests.
    testbasiert: z.boolean().default(false),
    quellen: z.array(quelle).min(1),
    faq: z.array(z.object({ frage: z.string(), antwort: z.string() })).default([]),
    draft: z.boolean().default(false),
  }),
});

// Products for the comparison. Measurement fields come ONLY from our own tests.
const produkte = defineCollection({
  loader: glob({ pattern: '**/[^_]*.json', base: './src/content/produkte' }),
  schema: z.object({
    name: z.string(),
    hersteller: z.string(),
    kategorie: z.enum(['feuerstahl', 'striker', 'set']),
    herstellerangaben: z.object({
      laenge_mm: z.number().positive().optional(),
      durchmesser_mm: z.number().positive().optional(),
      gewicht_g: z.number().positive().optional(),
      material: z.string().optional(),
      quelle_url: z.url().optional(),
    }),
    preis_eur: z.object({ wert: z.number().positive(), stand: z.coerce.date() }).optional(),
    linkshaender: z.enum(['ja', 'nein', 'eingeschraenkt', 'ungeprueft']).default('ungeprueft'),
    kinderfreundlich: z.enum(['ja', 'nein', 'eingeschraenkt', 'ungeprueft']).default('ungeprueft'),
    eigenerTest: z
      .object({
        getestet_am: z.coerce.date(),
        tester: z.string(),
        gemessen: z.object({
          laenge_mm: z.number().positive().optional(),
          durchmesser_mm: z.number().positive().optional(),
          gewicht_g: z.number().positive().optional(),
          abtrag_mg_pro_zug: z.number().positive().optional(),
          zuege_bis_zuendung_median: z.number().positive().optional(),
        }),
        bewertung: z.object({
          funken: z.number().int().min(1).max(5).optional(),
          handhabung: z.number().int().min(1).max(5).optional(),
          handschuhe: z.number().int().min(1).max(5).optional(),
          nass: z.number().int().min(1).max(5).optional(),
        }),
        notizen: z.string().optional(),
      })
      .optional(),
  }),
});

export const collections = { blog, produkte };
