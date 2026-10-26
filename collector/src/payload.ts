// The body sos-app's POST /api/collect accepts (format sagentix-collect/3: version 2 plus how each result was read),
// and the local checks that
// keep the server from refusing it: known check ids, (check, resource) unique, 1 to 5,000 results.

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import type { CatalogCheck } from "./catalog.ts";
import type { Read, Result } from "./types.ts";

export const FORMAT = "sagentix-collect/3";
export const MAX_RESULTS = 5000;
export const MAX_DETAIL = 1000;
export const MAX_RESOURCE = 300;

export const COLLECTOR_VERSION: string =
  (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version;

export interface Payload {
  format: typeof FORMAT;
  issuedAt: string;
  nonce: string;
  collector: { version: string; sources: { source: string; scope: string }[] };
  results: Result[];
}

/**
 * Drops results whose check id the catalogue does not know (the server would refuse the whole push)
 * and later duplicates of a (check, resource) pair; trims resource and detail to the server's limits.
 */
export function vet(results: Result[], catalog: Map<string, CatalogCheck>): { results: Result[]; unknown: string[]; duplicates: string[] } {
  const out: Result[] = [], unknown = new Set<string>(), duplicates: string[] = [], seen = new Set<string>();
  for (const r of results) {
    if (!catalog.has(r.check)) { unknown.add(r.check); continue; }
    const resource = (r.resource.trim() || "-").slice(0, MAX_RESOURCE);
    const key = `${r.check}|${resource}`;
    if (seen.has(key)) { duplicates.push(key); continue; }
    seen.add(key);
    out.push({ ...readOf(r), check: r.check, resource, result: r.result, detail: r.detail.trim().slice(0, MAX_DETAIL) });
  }
  return { results: out, unknown: [...unknown], duplicates };
}

const READ_KEYS = ["method", "observedAt", "expected", "observed", "itemsRead", "pagesRead", "complete", "apiError"] as const;
/** The provenance fields a result carries, without undefined ones (they would change nothing, but keep the JSON short). */
function readOf(r: Result): Read {
  const out: Record<string, unknown> = {};
  for (const k of READ_KEYS) if (r[k] !== undefined) out[k] = r[k];
  return out as Read;
}

/** sos-app refuses a body over 4 MB; the margin leaves room for the envelope around the results. */
export const MAX_BODY_BYTES = 4 * 1024 * 1024 - 64 * 1024;

/**
 * Splits results into pushes of at most `maxCount` results and about `maxBytes` of JSON each, in order.
 * Each push is signed and sent on its own, with its own nonce; (check, resource) stays unique overall.
 */
export function splitResults(results: Result[], maxCount: number = MAX_RESULTS, maxBytes: number = MAX_BODY_BYTES): Result[][] {
  const out: Result[][] = [];
  let cur: Result[] = [], size = 0;
  for (const r of results) {
    const n = Buffer.byteLength(JSON.stringify(r)) + 1;
    if (cur.length && (cur.length >= maxCount || size + n > maxBytes)) { out.push(cur); cur = []; size = 0; }
    cur.push(r); size += n;
  }
  if (cur.length) out.push(cur);
  return out;
}

export function buildPayload(o: { issuedAt: string; sources: { source: string; scope: string }[]; results: Result[]; nonce?: string }): Payload {
  return {
    format: FORMAT,
    issuedAt: o.issuedAt,
    nonce: o.nonce ?? randomUUID(),
    collector: { version: COLLECTOR_VERSION, sources: o.sources },
    results: o.results,
  };
}
