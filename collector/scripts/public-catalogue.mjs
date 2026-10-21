#!/usr/bin/env node
// Writes the check catalogues without Sagentix's control mappings (Sagentix, 2026-10-17). The collector
// needs a check's id to send it; sos-app maps checks to SP 800-53 controls and KSIs itself, and those
// mappings stay in the product. Used by stage-package.mjs, sync-public-repo.sh and runner/Dockerfile.
//   node collector/scripts/public-catalogue.mjs <catalogue dir> <output dir>
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const KEEP_DOC = ["source", "title", "readScopes", "engine", "provider", "profile"];
// retiredIn, removed and replacedBy are CISA's retirement facts, not Sagentix mappings: scuba.ts reads them to drop a
// policy from a ScubaGear 2.0.0 report (2026-10-21; the mirror's own tests caught the collector running without them).
const KEEP_CHECK = ["id", "title", "scope", "evidenceType", "severity", "retiredIn", "removed", "replacedBy"];
const pick = (o, keys) => Object.fromEntries(keys.filter((k) => o[k] !== undefined).map((k) => [k, o[k]]));

const [from, to] = process.argv.slice(2);
if (!from || !to) { console.error("usage: public-catalogue.mjs <catalogue dir> <output dir>"); process.exit(2); }
mkdirSync(to, { recursive: true });
let n = 0;
for (const f of readdirSync(from).filter((f) => f.endsWith(".json")).sort()) {
  const doc = JSON.parse(readFileSync(join(from, f), "utf8"));
  const out = { ...pick(doc, KEEP_DOC), checks: doc.checks.map((c) => pick(c, KEEP_CHECK)) };
  writeFileSync(join(to, f), `${JSON.stringify(out, null, 1)}\n`);
  n += out.checks.length;
}
console.log(`public catalogue: ${n} checks in ${to}, no control mappings`);
