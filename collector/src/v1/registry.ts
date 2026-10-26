// Which KSIs this collector can give evidence for, and how far that evidence goes.
//
// Every id below exists in fedramp_rules.json (checked at start-up by checkRegistry). A KSI that
// is not listed here is never reported: the collector omits it and people attest it in sos-app.
// "partial" means the checks cover part of the KSI's statement; `scope` says which part.

import type { Rules } from "./rules.ts";

export type Method = "automated" | "partial";
export type Status = "Implemented" | "Partially Implemented" | "Not Implemented";

export interface KsiEntry {
  ksiId: string;
  method: Method;
  /** The best status these checks can support, when they cannot see the whole statement. */
  ceiling?: Status;
  /** Sent as the result's implementation text and the SDR ksiImplementation statement. */
  implementation: string;
  /** What part of the KSI statement the checks do not cover. */
  scope: string;
}

export const REGISTRY: readonly KsiEntry[] = [
  {
    // "Information is encrypted or otherwise secured from unwanted access or modification."
    ksiId: "KSI-SVC-SIN",
    method: "partial",
    implementation:
      "Cloudflare edge: minimum TLS 1.2, TLS 1.3 on, HTTP redirected to HTTPS, automatic HTTPS rewrites, HSTS of at least one year with subdomains, and Full (strict) or Strict (SSL-Only Origin Pull) TLS to the origin.",
    scope: "Data in transit through the Cloudflare proxy only. Encryption at rest and inside the vendor's network is attested in sos-app.",
  },
  {
    // "Use cryptographic methods to validate the integrity of machine-based information resources."
    ksiId: "KSI-SVC-VRI",
    method: "partial",
    implementation: "DNSSEC is active on the zone, so resolvers can validate the integrity of its DNS records.",
    scope: "DNS records only. Integrity of images, artifacts and other resources is attested in sos-app.",
  },
  {
    // "... appropriately configured to limit inbound and outbound network traffic."
    ksiId: "KSI-CNA-RNT",
    method: "partial",
    implementation: "A managed WAF ruleset is executed on every inbound HTTP(S) request to the zone (phase http_request_firewall_managed).",
    scope: "Inbound HTTP(S) through the Cloudflare proxy only. Outbound and non-HTTP traffic are attested in sos-app.",
  },
  {
    // "Secure passwordless methods ... otherwise strong passwords with phishing-resistant MFA is used."
    ksiId: "KSI-IAM-APM",
    method: "partial",
    ceiling: "Partially Implemented",
    implementation: "Cloudflare account: two-factor authentication is enforced for the account and enabled for every accepted member.",
    scope: "Cloudflare's API shows that 2FA is on, not which factor. Phishing resistance cannot be seen, so the best status reported is Partially Implemented.",
  },
  {
    // "Modifications to the cloud service offering are logged and monitored."
    ksiId: "KSI-CMT-LMC",
    method: "partial",
    implementation: "The Cloudflare account audit log is readable and records configuration changes.",
    scope: "Shows that Cloudflare configuration changes are logged, not that someone monitors them; monitoring is attested in sos-app.",
  },
];

export const registryById = new Map(REGISTRY.map((e) => [e.ksiId, e]));

/** Refuse to run when an id here is not a KSI in the rules file the run uses. */
export function checkRegistry(rules: Rules): void {
  const known = new Set(rules.ksis.map((k) => k.id));
  const unknown = REGISTRY.filter((e) => !known.has(e.ksiId)).map((e) => e.ksiId);
  if (unknown.length) throw new Error(`registry names KSIs that are not in rules ${rules.info.version}: ${unknown.join(", ")}`);
  for (const e of REGISTRY) {
    if (e.method !== "automated" && e.method !== "partial") throw new Error(`${e.ksiId}: method must be automated or partial.`);
  }
}
