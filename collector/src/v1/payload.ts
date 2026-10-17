// From outcomes to the signed payload sos-app's /api/fedramp/collect accepts
// (format sagentix-fedramp-collect/1), with an SDR checked locally against FedRAMP's schema.

import { createRequire } from "node:module";
import { randomUUID } from "node:crypto";
import type { Outcome, EvidenceType } from "./outcome.ts";
import { classKsis, type FedClass, type Rules } from "./rules.ts";
import { registryById, type Method, type Status } from "./registry.ts";

export const COLLECT_FORMAT = "sagentix-fedramp-collect/1";
import { COLLECTOR_VERSION } from "../payload.ts";
const MAX_TESTS = 50, MAX_EVIDENCE = 50, MAX_TEST_LEN = 300;

export interface SdrEvidence {
  evidenceType: EvidenceType;
  evidenceDescription: string;
  evidenceText?: string;
  lastUpdated: string;
}

export interface Result {
  ksiId: string;
  method: Method;
  status: Status;
  passed: number;
  failed: number;
  tests: string[];
  evidence: SdrEvidence[];
  implementation?: string;
}

export interface Omitted { ksiId: string; reason: string }

const RANK: Record<Status, number> = { "Not Implemented": 0, "Partially Implemented": 1, Implemented: 2 };

function line(o: Outcome): string {
  const where = o.zone ? ` [zone ${o.zone}]` : "";
  return `${o.result.toUpperCase()} ${o.source} ${o.test}${where}: ${o.detail}`.slice(0, MAX_TEST_LEN);
}

/**
 * Group outcomes into one result per KSI. A KSI is reported only when it is in the registry, in
 * the target's class, and at least one of its tests passed or failed. Everything else is omitted
 * (and listed, so the dry-run shows what was not checked).
 */
export function aggregate(outcomes: Outcome[], rules: Rules, cls: FedClass, today: string): { results: Result[]; omitted: Omitted[] } {
  const inClass = classKsis(rules, cls);
  const byKsi = new Map<string, Outcome[]>();
  const omitted: Omitted[] = [];
  for (const o of outcomes) {
    if (!registryById.has(o.ksiId)) { omitted.push({ ksiId: o.ksiId, reason: "not in the collector's registry" }); continue; }
    if (!inClass.has(o.ksiId)) { omitted.push({ ksiId: o.ksiId, reason: `not a KSI of class ${cls}` }); continue; }
    byKsi.set(o.ksiId, [...(byKsi.get(o.ksiId) ?? []), o]);
  }
  const results: Result[] = [];
  for (const [ksiId, list] of byKsi) {
    const entry = registryById.get(ksiId)!;
    const ran = list.filter((o) => o.result !== "skipped");
    if (!ran.length) { omitted.push({ ksiId, reason: "every test was skipped" }); continue; }
    const passed = ran.filter((o) => o.result === "pass").length, failed = ran.length - passed;
    let status: Status = failed === 0 ? "Implemented" : passed === 0 ? "Not Implemented" : "Partially Implemented";
    if (entry.ceiling && RANK[status] > RANK[entry.ceiling]) status = entry.ceiling;
    results.push({
      ksiId,
      method: entry.method,
      status,
      passed,
      failed,
      tests: list.map(line).slice(0, MAX_TESTS),
      evidence: ran.slice(0, MAX_EVIDENCE).map((o) => ({
        evidenceType: o.evidenceType,
        evidenceDescription: `${o.source} ${o.test}${o.zone ? ` (zone ${o.zone})` : ""}: ${o.detail}`,
        ...(o.observed === undefined ? {} : { evidenceText: JSON.stringify(o.observed) }),
        lastUpdated: today,
      })),
      implementation: `${entry.implementation} Scope: ${entry.scope}`,
    });
  }
  results.sort((a, b) => a.ksiId.localeCompare(b.ksiId));
  // One line per omitted KSI.
  const seen = new Set<string>();
  return { results, omitted: omitted.filter((o) => (seen.has(o.ksiId) ? false : (seen.add(o.ksiId), true))) };
}

export function buildSdr(results: Result[], opts: { cpoUri: string; issuedAt: string; rulesVersion: string; provider: string }) {
  return {
    certificationPackageOverviewUri: opts.cpoUri,
    metadata: { version: `collector-${opts.issuedAt}`, lastUpdated: opts.issuedAt, updateSource: `sagentix-collector ${COLLECTOR_VERSION} (${opts.provider}), rules ${opts.rulesVersion}` },
    fedRampRequirements: [],
    keySecurityIndicators: results.map((r) => ({
      ksiId: r.ksiId,
      ksiImplementationStatus: r.status,
      ksiImplementation: r.implementation ? [r.implementation] : [],
      ksiValidation: [`Checked by the Sagentix collector (${r.method}): ${r.passed} passed, ${r.failed} failed.`],
      ksiAssessment: [],
      ksiTests: r.tests,
      ksiEvidence: r.evidence,
    })),
  };
}

interface AjvLike {
  addSchema(s: object): AjvLike;
  compile(s: object): ((d: unknown) => boolean) & { errors?: { instancePath: string; message?: string }[] | null };
}

/** A validator for FedRAMP's Security Decision Record schema (draft 2020-12), from the rules file. */
export function sdrValidator(rules: Rules): (doc: unknown) => string[] {
  const require = createRequire(import.meta.url);
  const { Ajv2020 } = require("ajv/dist/2020.js") as { Ajv2020: new (o: object) => AjvLike };
  const addFormats = require("ajv-formats") as (a: AjvLike) => AjvLike;
  // strict: false because FedRAMP's schemas carry their own keywords ($schemaVersion).
  const ajv = addFormats(new Ajv2020({ strict: false, allErrors: true }));
  ajv.addSchema(rules.schemas["common-definitions"]);
  const validate = ajv.compile(rules.schemas["security-decision-record"]);
  return (doc) => (validate(doc) ? [] : (validate.errors ?? []).slice(0, 20).map((e) => `${e.instancePath || "/"} ${e.message ?? "invalid"}`));
}

export interface Payload {
  format: string;
  targetId: string;
  issuedAt: string;
  rulesVersion: string;
  nonce: string;
  sdr: ReturnType<typeof buildSdr>;
  results: Result[];
}

export function buildPayload(results: Result[], opts: { targetId: string; issuedAt: string; rules: Rules; cpoUri: string; provider: string }): Payload {
  return {
    format: COLLECT_FORMAT,
    targetId: opts.targetId,
    issuedAt: opts.issuedAt,
    rulesVersion: opts.rules.info.version,
    nonce: randomUUID(),
    sdr: buildSdr(results, { cpoUri: opts.cpoUri, issuedAt: opts.issuedAt, rulesVersion: opts.rules.info.version, provider: opts.provider }),
    results,
  };
}
