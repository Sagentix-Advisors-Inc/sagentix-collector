// FedRAMP rules data, as sos-app ships it (apps/sos-app/src/data/fedramp_rules.json).
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export interface Ksi {
  id: string;
  theme: string;
  name: string;
  statement?: string;
  byClass?: Record<string, string>;
  controls: string[];
}

export interface Rules {
  info: { title: string; version: string; last_updated: string };
  ksis: Ksi[];
  classes: Record<string, { ksis: { id: string }[] }>;
  schemas: Record<string, Record<string, unknown>>;
}

export const CLASSES = ["A", "B", "C", "D"] as const;
export type FedClass = (typeof CLASSES)[number];

/** The repo layout: collector/ sits beside apps/sos-app/. */
export const DEFAULT_RULES_PATH = fileURLToPath(new URL("../../../apps/sos-app/src/data/fedramp_rules.json", import.meta.url));

export function loadRules(path: string = DEFAULT_RULES_PATH): Rules {
  const r = JSON.parse(readFileSync(path, "utf8")) as Rules;
  if (!r?.info?.version || !Array.isArray(r.ksis) || !r.classes || !r.schemas?.["security-decision-record"] || !r.schemas?.["common-definitions"]) {
    throw new Error(`${path} does not look like fedramp_rules.json (info.version, ksis, classes, schemas).`);
  }
  return r;
}

/** The KSI ids a class lists. */
export function classKsis(rules: Rules, cls: FedClass): Set<string> {
  const c = rules.classes[cls];
  if (!c) throw new Error(`class ${cls} is not in the rules file.`);
  return new Set(c.ksis.map((k) => k.id));
}
