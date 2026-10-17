// The v1 push (POST /api/fedramp/collect, format sagentix-fedramp-collect/1) for a FedRAMP target,
// behind `collector run --fedramp-target <id>`. It reuses the v2 results of the 11 checks the v1
// collector had, grouped into the five KSIs of src/v1/registry.ts, with an SDR validated locally.

import type { CatalogCheck } from "../catalog.ts";
import type { Result } from "../types.ts";
import type { EvidenceType, Outcome } from "./outcome.ts";
import { aggregate, buildPayload, sdrValidator, type Omitted, type Payload } from "./payload.ts";
import { checkRegistry } from "./registry.ts";
import { loadRules, type FedClass } from "./rules.ts";

export const V1_COLLECT_PATH = "/api/fedramp/collect";

/** The checks the v1 collector reported, and the KSI each fed. */
export const V1_KSI: Record<string, string> = {
  "cloudflare.min_tls_version": "KSI-SVC-SIN",
  "cloudflare.tls_1_3": "KSI-SVC-SIN",
  "cloudflare.always_use_https": "KSI-SVC-SIN",
  "cloudflare.automatic_https_rewrites": "KSI-SVC-SIN",
  "cloudflare.ssl_mode": "KSI-SVC-SIN",
  "cloudflare.hsts": "KSI-SVC-SIN",
  "cloudflare.dnssec": "KSI-SVC-VRI",
  "cloudflare.waf_managed_ruleset": "KSI-CNA-RNT",
  "cloudflare.account_enforces_2fa": "KSI-IAM-APM",
  "cloudflare.members_have_2fa": "KSI-IAM-APM",
  "cloudflare.audit_log_available": "KSI-CMT-LMC",
};

export function toOutcomes(results: Result[], catalog: Map<string, CatalogCheck>): Outcome[] {
  return results.filter((r) => V1_KSI[r.check]).map((r) => ({
    ksiId: V1_KSI[r.check],
    test: r.check.replace(/^cloudflare\./, ""),
    source: r.resource.startsWith("tofu ") ? "opa" as const : "cloudflare-api" as const,
    zone: r.resource,
    result: r.result,
    detail: r.detail,
    evidenceType: (catalog.get(r.check)?.evidenceType ?? "Configuration") as EvidenceType,
  }));
}

export function v1Payload(results: Result[], catalog: Map<string, CatalogCheck>, o: { targetId: string; cls: FedClass; issuedAt: string; cpoUri: string; rulesPath?: string }):
  { payload: Payload; omitted: Omitted[]; problems: string[] } {
  const rules = loadRules(o.rulesPath);
  checkRegistry(rules);
  const { results: ksis, omitted } = aggregate(toOutcomes(results, catalog), rules, o.cls, o.issuedAt.slice(0, 10));
  const payload = buildPayload(ksis, { targetId: o.targetId, issuedAt: o.issuedAt, rules, cpoUri: o.cpoUri, provider: "cloudflare" });
  return { payload, omitted, problems: sdrValidator(rules)(payload.sdr) };
}
