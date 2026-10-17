// The v1 (FedRAMP KSI) result shape, built from v2 results by src/v1/index.ts.
export type Source = "opa" | "cloudflare-api";
export type EvidenceType = "Log" | "Report" | "Screenshot" | "Configuration" | "Policy" | "Procedure" | "Audit Record";

/** One test against one resource. "skipped" never counts as passed or failed. */
export interface Outcome {
  ksiId: string;
  test: string;
  source: Source;
  zone?: string;
  result: "pass" | "fail" | "skipped";
  detail: string;
  evidenceType: EvidenceType;
  observed?: unknown;
}
