#!/usr/bin/env node
// Writes a Markdown file for the public mirror without Sagentix's control mappings (Sagentix, 2026-10-17):
// table columns "Hub controls", "KSIs" and "Coverage" go, and so does every paragraph or list item that
// names a hub control, a KSI or how a mapping was chosen. Used by stage-package.mjs and sync-public-repo.sh.
//   node collector/scripts/public-docs.mjs <in.md> <out.md>
import { readFileSync, writeFileSync } from "node:fs";

const DROP_COLS = new Set(["hub controls", "ksis", "ksi", "coverage", "hub", "controls"]);
const MAPPING = /KSI-[A-Z]{3}-[A-Z]{3}|\bhub control|hubBasis|ksiBasis|\b(?:ac|au|cm|ia|sc|si|ra|ca|cp|ir|sa|sr|pm|ps|mp|ma|at|pl)-\d+|\bCoverage is\b/i;
// Sentences that grade coverage ("Every check is `partial`.") go; the rest of the paragraph stays.
const COVERAGE = /[^.]*\bis `(?:full|partial)`[^.]*\.\s*/g;

const [from, to] = process.argv.slice(2);
if (!from || !to) { console.error("usage: public-docs.mjs <in.md> <out.md>"); process.exit(2); }
const cells = (l) => l.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
const out = [];
let drop = null, inCode = false, dropped = 0;
for (let line of readFileSync(from, "utf8").split("\n")) {
  if (line.startsWith("```")) inCode = !inCode;
  if (!inCode && line.trim().startsWith("|")) {
    const cs = cells(line);
    if (drop === null) drop = new Set(cs.flatMap((c, i) => (DROP_COLS.has(c.toLowerCase()) ? [i] : [])));
    out.push(`| ${cs.filter((_, i) => !drop.has(i)).join(" | ")} |`);
    continue;
  }
  drop = null;
  if (!inCode && COVERAGE.test(line)) { line = line.replace(COVERAGE, "").trimEnd(); if (!line) { dropped++; continue; } }
  if (!inCode && !line.startsWith("#") && MAPPING.test(line)) { dropped++; continue; }
  out.push(line);
}
writeFileSync(to, out.join("\n").replace(/\n{3,}/g, "\n\n"));
console.log(`${to}: ${dropped} lines naming mappings left out`);
