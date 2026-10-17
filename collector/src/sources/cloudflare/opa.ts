// OPA/Rego policies (iac/policy/cloudflare) evaluated over `tofu show -json`, as a sub-source of
// Cloudflare. The policies are not in the public package or image; without them every OPA check is skipped. Results carry the same check ids as the API checks that test the same setting, with
// resource "tofu <resource address>". `opa` runs as a subprocess; when it is not on PATH or the state
// file is missing, every OPA check is skipped, never passed.

import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { Result } from "../../types.ts";

export const DEFAULT_POLICY_DIR = fileURLToPath(new URL("../../../../iac/policy/cloudflare", import.meta.url));
export const OPA_QUERY = "data.sagentix.cloudflare.checks";

/** Rule name in the Rego policies → the Terraform resource that holds the setting. */
export const OPA_RULES: Record<string, { type: string; setting?: string; phase?: string }> = {
  min_tls_version: { type: "cloudflare_zone_setting", setting: "min_tls_version" },
  tls_1_3: { type: "cloudflare_zone_setting", setting: "tls_1_3" },
  always_use_https: { type: "cloudflare_zone_setting", setting: "always_use_https" },
  automatic_https_rewrites: { type: "cloudflare_zone_setting", setting: "automatic_https_rewrites" },
  ssl_mode: { type: "cloudflare_zone_setting", setting: "ssl" },
  hsts: { type: "cloudflare_zone_setting", setting: "security_header" },
  dnssec: { type: "cloudflare_zone_dnssec" },
  waf_managed_ruleset: { type: "cloudflare_ruleset", phase: "http_request_firewall_managed" },
};
export const OPA_CHECKS = Object.keys(OPA_RULES).map((r) => `cloudflare.${r}`);

export interface OpaRun { code: number; stdout: string; stderr: string }
/** Runs `opa` with the given arguments. Rejects with an error whose code is ENOENT when opa is missing. */
export type OpaRunner = (args: string[]) => Promise<OpaRun>;

export function spawnOpa(env: NodeJS.ProcessEnv = process.env, bin = "opa"): OpaRunner {
  return (args) => new Promise((resolve, reject) => {
    const p = spawn(bin, args, { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    p.stdout.on("data", (b) => (stdout += b));
    p.stderr.on("data", (b) => (stderr += b));
    p.on("error", reject);
    p.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

const skipped = (detail: string): Result[] =>
  OPA_CHECKS.map((check) => ({ check, resource: "tofu state", result: "skipped" as const, detail }));

interface StateResource { address?: string; type?: string; mode?: string; values?: Record<string, unknown> }

/** Every managed resource in a `tofu show -json` document, at any module depth. */
function stateResources(state: unknown): StateResource[] {
  const out: StateResource[] = [];
  const walk = (m: unknown) => {
    if (!m || typeof m !== "object") return;
    const mod = m as { resources?: unknown; child_modules?: unknown };
    if (Array.isArray(mod.resources)) for (const r of mod.resources) if (r && typeof r === "object" && (r as StateResource).mode === "managed") out.push(r as StateResource);
    if (Array.isArray(mod.child_modules)) for (const c of mod.child_modules) walk(c);
  };
  walk((state as { values?: { root_module?: unknown } })?.values?.root_module);
  return out;
}

/** "tofu <address>" of the resource a rule judged, or a stand-in naming what is missing. */
export function addressFor(resources: StateResource[], rule: string, zone: string): string {
  const want = OPA_RULES[rule];
  const hit = want && resources.find((r) => r.type === want.type && r.values?.zone_id === zone
    && (want.setting === undefined || r.values?.setting_id === want.setting)
    && (want.phase === undefined || r.values?.phase === want.phase));
  if (hit?.address) return `tofu ${hit.address}`;
  return `tofu zone ${zone}: no ${want?.type ?? "resource"}${want?.setting ? ` ${want.setting}` : ""}${want?.phase ? ` ${want.phase}` : ""}`;
}

interface Check { rule: string; zone_id: string; pass: boolean; msg: string }

export async function opaChecks(runner: OpaRunner, policyDir: string, statePath: string | undefined): Promise<Result[]> {
  if (!statePath) return [];
  if (!existsSync(statePath)) return skipped(`state file ${statePath} not found`);
  // The public package carries no policies (Sagentix, 2026-10-17); Sagentix hands them to customers who use them.
  if (!existsSync(policyDir)) return skipped(`no OPA policies at ${policyDir}; pass --policy <dir>`);
  let resources: StateResource[];
  try { resources = stateResources(JSON.parse(readFileSync(statePath, "utf8"))); } catch { return skipped(`state file ${statePath} is not JSON (tofu show -json)`); }
  let run: OpaRun;
  try {
    run = await runner(["eval", "--format", "json", "--data", policyDir, "--input", statePath, OPA_QUERY]);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException)?.code;
    return skipped(code === "ENOENT" ? "opa is not on PATH" : `opa could not start: ${String(e)}`);
  }
  if (run.code !== 0) return skipped(`opa eval failed (exit ${run.code}): ${run.stderr.trim().slice(0, 500)}`);
  let value: unknown;
  try { value = JSON.parse(run.stdout)?.result?.[0]?.expressions?.[0]?.value; } catch { return skipped("opa output was not JSON"); }
  if (!Array.isArray(value)) return skipped("opa returned no checks for this query");
  const checks = value.filter((c): c is Check =>
    typeof c === "object" && c !== null && typeof c.rule === "string" && typeof c.zone_id === "string" && typeof c.pass === "boolean");
  if (!checks.length) return skipped("the state holds no Cloudflare zone resources");
  return checks.map((c) => ({
    check: `cloudflare.${c.rule}`,
    resource: addressFor(resources, c.rule, c.zone_id).slice(0, 300),
    result: c.pass ? "pass" as const : "fail" as const,
    detail: `${String(c.msg ?? "")} (policy ${OPA_QUERY}, zone ${c.zone_id})`,
  }));
}
