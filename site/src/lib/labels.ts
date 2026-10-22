// Display names for schema values. Typed against the content schema, so a new
// value in src/content.config.ts without a label shows up as a type error.
import type { CollectionEntry } from 'astro:content';

export type Zielgruppe = CollectionEntry<'blog'>['data']['zielgruppen'][number];
export type Thema = CollectionEntry<'blog'>['data']['themen'][number];
type Produkt = CollectionEntry<'produkte'>['data'];

export const ZIELGRUPPEN: Record<Zielgruppe, { name: string; text: string }> = {
  outdoor: {
    name: 'Outdoor',
    text: 'Wandern, Paddeln, Zelten: Feuer machen unterwegs mit wenig Gewicht.',
  },
  bushcraft: {
    name: 'Bushcraft',
    text: 'Zunder aus der Natur, Technik üben, Feuer mit dem, was der Wald hergibt.',
  },
  selbstversorger: {
    name: 'Selbstversorger',
    text: 'Ausrüstung für Haus, Hof und Garten, die lange halten soll.',
  },
  survival: {
    name: 'Survival',
    text: 'Notfallausrüstung, auf die du dich auch bei Nässe und Kälte verlassen willst.',
  },
  'eltern-kinder': {
    name: 'Eltern und Kinder',
    text: 'Passende Größen, klare Regeln und Aufsicht beim ersten eigenen Funken.',
  },
  linkshaender: {
    name: 'Linkshänder',
    text: 'Striker und Griffe, die auch in der linken Hand gut funktionieren.',
  },
};

export const THEMEN: Record<Thema, { name: string; text: string }> = {
  feuerstahl: {
    name: 'Feuerstahl',
    text: 'Der Ferrocerium-Stab: Größen, Mischungen, Pflege und wie lange er hält.',
  },
  striker: {
    name: 'Striker',
    text: 'Der Schaber: Kante, Material, Griff und Technik beim Abziehen.',
  },
  verbindung: {
    name: 'Verbindung',
    text: 'Shockcord, Schnur oder Kette: wie Stab und Striker zusammenbleiben.',
  },
  sicherheit: {
    name: 'Sicherheit',
    text: 'Feuer sicher machen, beaufsichtigen und löschen.',
  },
  recht: {
    name: 'Recht',
    text: 'Wo Feuer erlaubt ist und was du beachten musst.',
  },
};

export const ZIELGRUPPEN_IDS = Object.keys(ZIELGRUPPEN) as Zielgruppe[];

export const KATEGORIEN: Record<Produkt['kategorie'], string> = {
  feuerstahl: 'Feuerstahl',
  striker: 'Striker',
  set: 'Set',
};

export const EIGNUNG: Record<Produkt['linkshaender'], string> = {
  ja: 'Ja',
  nein: 'Nein',
  eingeschraenkt: 'Eingeschränkt',
  ungeprueft: 'Noch nicht geprüft',
};
