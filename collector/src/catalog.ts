// The check catalogue sos-app ships (apps/sos-app/src/data/checks/<source>.json). The collector reads
// the same files so it never sends a check id the server would refuse with 400. The public package and
// mirror carry them without the control mappings (scripts/public-catalogue.mjs; Sagentix, 2026-10-17):
// sos-app maps checks to controls itself, so hub, ksis and coverage are absent there.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export interface CatalogCheck {
  id: string;
  title: string;
  hub?: string[];
  ksis?: string[];
  coverage?: "full" | "partial";
  evidenceType: string;
  scope: string;
  source: string;
}

/** The repo layout: collector/ sits beside apps/sos-app/. */
export const DEFAULT_CATALOG_DIR = fileURLToPath(new URL("../../apps/sos-app/src/data/checks/", import.meta.url));

export function loadCatalog(dir: string = DEFAULT_CATALOG_DIR): Map<string, CatalogCheck> {
  let files: string[];
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
  } catch (e) {
    throw new Error(`cannot read the check catalogue in ${dir} (${(e as NodeJS.ErrnoException).code ?? String(e)}); pass --catalog <dir>.`);
  }
  if (!files.length) throw new Error(`${dir} holds no <source>.json check catalogue; pass --catalog <dir>.`);
  const out = new Map<string, CatalogCheck>();
  for (const f of files) {
    const doc = JSON.parse(readFileSync(join(dir, f), "utf8")) as { source?: string; checks?: Omit<CatalogCheck, "source">[] };
    if (typeof doc.source !== "string" || !Array.isArray(doc.checks)) throw new Error(`${join(dir, f)} is not a check catalogue (source, checks[]).`);
    for (const c of doc.checks) {
      if (typeof c.id !== "string" || !c.id) throw new Error(`${join(dir, f)}: a check has no id.`);
      if (out.has(c.id)) throw new Error(`${join(dir, f)}: check ${c.id} is listed twice.`);
      out.set(c.id, { ...c, source: doc.source });
    }
  }
  return out;
}
