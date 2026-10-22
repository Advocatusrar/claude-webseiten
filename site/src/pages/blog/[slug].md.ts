// Markdown version of every article at /blog/<id>.md, for AI agents and tools.
import type { APIRoute, GetStaticPaths } from 'astro';
import { alleArtikel, hatMarkdownFassung, type Artikel } from '../../lib/blog';
import { artikelAlsMarkdown } from '../../lib/markdown';

export const getStaticPaths = (async () => {
  const artikel = await alleArtikel();
  const ids = artikel.map((a) => a.id);
  return artikel.filter(hatMarkdownFassung).map((eintrag) => ({
    params: { slug: eintrag.id },
    props: { eintrag, ids },
  }));
}) satisfies GetStaticPaths;

export const GET: APIRoute = ({ props }) => {
  const { eintrag, ids } = props as { eintrag: Artikel; ids: string[] };
  return new Response(artikelAlsMarkdown(eintrag, ids), {
    headers: { 'Content-Type': 'text/markdown; charset=utf-8' },
  });
};
