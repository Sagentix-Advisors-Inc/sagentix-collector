// Recorded replies for every source at once, for the end-to-end run (test/e2e.test.ts) and the timing script
// (scripts/bench-dry-run.mjs). Each source gets the same fakes its own suite uses (test/fixtures/), so a run of
// `--source <all>` reads the network nowhere: REST and cloud sources get fake transports, engines read report
// files written here, the host sources get fake command runners and the web source a fake network.
// `latencyMs` makes every fake call wait that long first, standing in for a provider's round trip.
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadCatalog } from "../src/catalog.ts";
import { STIG_PROFILES } from "../src/sources/stig.ts";
import type { OptionValue } from "../src/types.ts";
import { fakeCloudflare, missingOpa, NOW } from "./helpers.ts";
import { fakeRest, type Contract, type Routes } from "./rest_fakes.ts";
import type { RestApi } from "../src/sources/readonly_http.ts";
import { C as configmgr } from "./fixtures/rest/configmgr.ts";
import { C as defender } from "./fixtures/rest/defender_endpoint.ts";
import { C as endpointCentral } from "./fixtures/rest/endpoint_central.ts";
import { C as entra } from "./fixtures/rest/entra.ts";
import { C as fleet } from "./fixtures/rest/fleet.ts";
import { C as github } from "./fixtures/rest/github.ts";
import { C as googleEndpoints } from "./fixtures/rest/google_endpoints.ts";
import { C as googleWorkspace } from "./fixtures/rest/google_workspace.ts";
import { C as intune } from "./fixtures/rest/intune.ts";
import { C as ivanti } from "./fixtures/rest/ivanti_mdm.ts";
import { C as jamf } from "./fixtures/rest/jamf.ts";
import { C as jumpcloud } from "./fixtures/rest/jumpcloud.ts";
import { C as kandji } from "./fixtures/rest/kandji.ts";
import { C as ninjaone } from "./fixtures/rest/ninjaone.ts";
import { C as okta } from "./fixtures/rest/okta.ts";
import { C as pagerduty } from "./fixtures/rest/pagerduty.ts";
import { C as resend } from "./fixtures/rest/resend.ts";
import { C as stripe } from "./fixtures/rest/stripe.ts";
import { C as vercel } from "./fixtures/rest/vercel.ts";
import { C as workspaceOne } from "./fixtures/rest/workspace_one.ts";
import { fakeAws } from "./fixtures/cloud/aws.ts";
import { fake as fakeAzure } from "./fixtures/cloud/azure.ts";
import { fake as fakeGcp, P as GCP_PROJECT } from "./fixtures/cloud/gcp.ts";
import { fakeJira, OPTS as JIRA_OPTS, strong as jiraStrong } from "./fixtures/cloud/jira.ts";
import { bambooRoutes, BHR, BOPTS, OKTA, oktaUsers, q, RIP, ripRoutes, ROPTS } from "./fixtures/local/hris.ts";
import { fake as fakeMac } from "./fixtures/local/macos.ts";
import { fake as fakeWindows } from "./fixtures/local/windows.ts";
import { fake as fakeWeb, HOST, PRIVACY, TOKEN, URL_ } from "./fixtures/local/web.ts";

export const E2E_NOW = NOW;
export const ENDPOINT = "https://sos.example.test";
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();

/** Every REST source with a contract suite, by its source name. */
export const CONTRACTS: readonly Contract[] = [
  entra, okta, jumpcloud, googleWorkspace, github, vercel, pagerduty, stripe, resend,
  fleet, intune, jamf, kandji, defender, workspaceOne, configmgr, googleEndpoints, ivanti, ninjaone, endpointCentral,
];

/** fakeRest, and when it has no answer for a URL, the answer of a route on the same path (the doctor asks for a page of
 *  one where the source asks for a page of 100; the recorded reply serves both). */
export function lenientRest(base: string, routes: Routes): RestApi {
  const exact = fakeRest(base, routes);
  return {
    async get(url: string) {
      const r = await exact.get(url);
      if (r.status !== 404 || !String((r.body as { message?: string } | null)?.message ?? "").startsWith("no fake")) return r;
      const rel = (url.startsWith(base) ? url.slice(base.length) : url).split("?")[0];
      const key = Object.keys(routes).find((k) => k.split("?")[0] === rel);
      return key ? exact.get(key) : r;
    },
  };
}

/** A copy of `client` whose calls are counted under `name` and wait `ms` first (sleep, clock and plain data are left alone). */
export function slow<T>(client: T, ms: number, name = "?", counts?: Map<string, number>): T {
  if (client === null || client === undefined) return client;
  const wait = () => { counts?.set(name, (counts.get(name) ?? 0) + 1); return ms ? new Promise((r) => setTimeout(r, ms)) : Promise.resolve(); };
  if (typeof client === "function") return (async (...a: unknown[]) => { await wait(); return (client as (...x: unknown[]) => unknown)(...a); }) as T;
  if (typeof client !== "object") return client;
  return new Proxy(client as object, {
    get(t, k, r) {
      const v = Reflect.get(t, k, r);
      if (typeof v !== "function" || k === "sleep" || k === "clock") return typeof v === "object" && v !== null && k === "dns" ? slow(v, ms, name, counts) : v;
      return async (...a: unknown[]) => { await wait(); return (v as (...x: unknown[]) => unknown).apply(t, a); };
    },
  }) as T;
}

const json = (dir: string, name: string, body: unknown) => { const p = join(dir, name); writeFileSync(p, typeof body === "string" ? body : JSON.stringify(body)); return p; };

/** The report files the engine sources read, written once into `dir`. */
function reports(dir: string): Record<string, OptionValue> {
  const catalog = [...loadCatalog().values()];
  const ids = (prefix: string) => catalog.filter((c) => c.id.startsWith(prefix)).map((c) => c.id).sort();
  const rhel9 = ids("stig.rhel9.").slice(0, 6);
  const vid = (check: string) => check.split(".")[2].toUpperCase();
  const inspec = {
    platform: { name: "redhat", release: "9.6", target_id: "0f3c2a9e-7b1d-4c55-9a0e-1d2c3b4a5f60" },
    profiles: [{ name: STIG_PROFILES.rhel9.name, version: STIG_PROFILES.rhel9.version, controls: rhel9.map((c, i) => ({
      id: `S${vid(c)}`, title: "t", impact: 0.5, tags: { gid: vid(c), severity: "medium", nist: ["CM-6 b"] }, waiver_data: {},
      results: [{ status: i % 3 === 0 ? "failed" : "passed", code_desc: "a setting", start_time: daysAgo(1) }] })) }],
    statistics: { duration: 1.2 }, version: "7.2.1",
  };
  const ks = (id: string, status: string, p: number, f: number) => [id, { controlID: id, name: "n", status, statusInfo: { status },
    ResourceCounters: { passedResources: p, failedResources: f, skippedResources: 0, excludedResources: 0 }, subStatusCounters: { ignoredResources: 0, acknowledgedResources: 0 }, score: 0, scoreFactor: 0 }];
  const ksControls = ids("kubescape.").slice(0, 5).map((c, i) => ks(c.split(".").pop()!.toUpperCase(), i % 2 ? "failed" : "passed", 3, i % 2));
  const kubescape = { generationTime: daysAgo(1), clusterName: "", reportGUID: "g",
    summaryDetails: { controls: Object.fromEntries(ksControls), frameworks: [{ name: "NSA", version: "" }], status: "failed" },
    metadata: { scanMetadata: { targetType: "Framework", kubescapeVersion: "v4.0.15", formatVersion: "v2", scanningTarget: 4, targetNames: ["nsa"] } }, results: [] };
  const rec = (id: string, result: string, resource: string) => ({ check_id: id, check_name: "n", check_result: { result }, file_path: "/main.tf", resource });
  const ck = (recs: ReturnType<typeof rec>[]) => ({ check_type: "terraform",
    results: { passed_checks: recs.filter((r) => r.check_result.result === "PASSED"), failed_checks: recs.filter((r) => r.check_result.result === "FAILED"), skipped_checks: [], parsing_errors: [] },
    summary: { passed: 1, failed: 1, skipped: 0, parsing_errors: 0, resource_count: 2, checkov_version: "3.3.21" } });
  const trivy = { SchemaVersion: 2, CreatedAt: daysAgo(1), ArtifactName: "registry.example/app:1.4.2", ArtifactType: "container_image", Metadata: { ImageID: "sha256:abc" },
    Results: [{ Target: "registry.example/app:1.4.2 (alpine 3.20)", Class: "os-pkgs", Type: "alpine",
      Vulnerabilities: [{ VulnerabilityID: "CVE-2025-9", PkgName: "openssl", InstalledVersion: "3.0.1", FixedVersion: "3.0.2", Status: "fixed", Severity: "HIGH" }] }] };
  const grype = { matches: [{ vulnerability: { id: "CVE-1", severity: "Critical", fix: { versions: ["1.2.1"], state: "fixed", available: [{ version: "1.2.1", date: daysAgo(5).slice(0, 10) }] } },
    artifact: { name: "pkg", version: "1.0", type: "deb" } }], source: { type: "image", target: { userInput: "registry.example/app:1.4.2" } },
    descriptor: { name: "grype", version: "0.92.0", timestamp: daysAgo(1) } };
  const sbom = { bomFormat: "CycloneDX", specVersion: "1.6", version: 1, metadata: { timestamp: daysAgo(2), tools: { components: [{ type: "application", name: "syft", version: "1.20.0" }] } },
    components: [{ "bom-ref": "r0", type: "library", name: "a", version: "1", purl: "pkg:npm/a@1" }, { "bom-ref": "r1", type: "library", name: "b", version: "1" }] };
  const scorecard = { date: daysAgo(1), repo: { name: "github.com/acme/api", commit: "68bc59901773ab4c051dfcea0cc4201a1567ab32" }, scorecard: { version: "v5.2.1", commit: "ccbc5990" }, score: 7.1,
    checks: ["Branch-Protection", "Code-Review", "SAST", "Signed-Releases", "Dependency-Update-Tool", "Vulnerabilities", "Token-Permissions", "Pinned-Dependencies"]
      .map((name, i) => ({ details: [], score: i % 3 ? 10 : 5, reason: "r", name, documentation: { url: "u", short: "s" } })), metadata: [] };
  const ts = Math.floor(new Date(daysAgo(3)).getTime() / 1000);
  const nessus = `<?xml version="1.0" ?><NessusClientData_v2><Policy><policyName>Monthly</policyName></Policy><Report name="Monthly">` +
    ["10.0.0.5|web1.corp.example", "10.0.0.6|db1.corp.example"].map((h) => { const [ip, fqdn] = h.split("|"); return `<ReportHost name="${ip}"><HostProperties>` +
      `<tag name="HOST_END_TIMESTAMP">${ts}</tag><tag name="host-ip">${ip}</tag><tag name="host-fqdn">${fqdn}</tag></HostProperties>` +
      `<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" pluginName="Nessus Scan Information" pluginFamily="Settings"><plugin_output>Credentialed checks : yes\n</plugin_output></ReportItem></ReportHost>`; }).join("") +
    `</Report></NessusClientData_v2>`;
  const fixture = (name: string) => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));
  return {
    "cinc-report": json(dir, "stig.json", inspec),
    "kubescape-report": json(dir, "kubescape.json", kubescape),
    "checkov-report": json(dir, "checkov.json", ck([rec("CKV_AWS_3", "PASSED", "aws_ebs_volume.data"), rec("CKV_AWS_24", "FAILED", "aws_security_group.a")])),
    "trivy-report": [json(dir, "trivy.json", trivy)],
    "grype-report": json(dir, "grype.json", grype),
    "sbom-file": [json(dir, "sbom.cdx.json", sbom)],
    "gitleaks-report": json(dir, "gitleaks.json", []),
    "scorecard-result": json(dir, "scorecard.json", scorecard),
    "vulnscan-report": [json(dir, "scan.nessus", nessus)],
    "vulnscan-inventory": json(dir, "inventory.csv", "hostname,owner\nweb1.corp.example,ops\n10.0.0.6,ops\n"),
    "training-csv": json(dir, "training.csv", "person_id,course,completed_on\nE1,Security Awareness 2026,2026-03-01\nE2,Security awareness basics,2026-02-01\nE2,Role-based admin training,2026-04-01\n"),
    "roster-csv": json(dir, "roster.csv", "person_id,role\nE1,engineer\nE2,admin\n"),
    "prowler-provider": "aws",
    "prowler-output": fixture("prowler/prowler_aws.ocsf.json"),
    "scubagoggles-results": fixture("scubagoggles_ScubaResults.json"), "scubagoggles-max-age-days": "400",
    "scubagear-results": fixture("scubagear_ScubaResults.json"), "scubagear-max-age-days": "400",
  };
}

export interface E2eSetup {
  /** `run` arguments after "run": the sources, their options and the endpoint (add --dry-run or a key). */
  args: string[];
  clients: Record<string, unknown>;
  env: NodeJS.ProcessEnv;
  /** Where the report files were written; results naming a file name it under here. */
  dir: string;
  /** Calls each fake answered, by client name. */
  calls: Map<string, number>;
  sources: string[];
}

/** Options as command-line arguments. */
export function toArgs(opts: Record<string, OptionValue>): string[] {
  return Object.entries(opts).flatMap(([k, v]) => v === true ? [`--${k}`] : v === false || v === undefined ? [] : (Array.isArray(v) ? v : [v]).flatMap((x) => [`--${k}`, x]));
}

/** Every source at once against recorded replies. `latencyMs` delays each fake call (default 0). */
export function e2eSetup(o: { latencyMs?: number } = {}): E2eSetup {
  const ms = o.latencyMs ?? 0;
  const calls = new Map<string, number>();
  const wrap = <T>(c: T, name: string): T => slow(c, ms, name, calls);
  const dir = mkdtempSync(join(tmpdir(), "collector-e2e-"));
  const clients: Record<string, unknown> = { sleep: async () => {} };
  const opts: Record<string, OptionValue> = {};
  const env: NodeJS.ProcessEnv = {};
  const sources: string[] = [];
  for (const c of CONTRACTS) {
    let routes: Routes = c.strong();
    // The HR sources look leavers up in Okta: the same client answers both (as one run's clients do).
    if (c.clientKey === "okta") routes = { ...routes, "/api/v1/users": (url) => {
      const m = /profile\.email eq "([^"]+)"/.exec(q(url).get("search") ?? "");
      const u = m ? oktaUsers[m[1]] : undefined;
      return { status: 200, headers: {}, body: u ? [u] : [] };
    } };
    clients[c.clientKey] = wrap(lenientRest(c.base, routes), c.clientKey);
    Object.assign(opts, c.opts ?? {});
    Object.assign(env, c.env ?? {});
    sources.push(c.source.name);
  }
  if (OKTA !== okta.base) throw new Error("the HR fixtures and the Okta contract name different Okta orgs");
  clients.bamboohr = wrap(fakeRest(BHR, bambooRoutes()), "bamboohr");
  clients.rippling = wrap(fakeRest(RIP, ripRoutes()), "rippling");
  Object.assign(opts, BOPTS, ROPTS);
  Object.assign(env, { BAMBOOHR_API_KEY: "bhr-key-0123456789", RIPPLING_API_TOKEN: "rip-token-0123456789" });
  clients.cloudflare = wrap(fakeCloudflare(), "cloudflare");
  clients.opa = missingOpa;
  clients.aws = wrap(fakeAws(), "aws");
  clients.azure = wrap(fakeAzure(), "azure");
  clients.gcp = wrap(fakeGcp(), "gcp");
  clients.jira = wrap(fakeJira(jiraStrong()), "jira");
  clients.macos = wrap(fakeMac().exec, "macos");
  clients.windows = wrap(fakeWindows().exec, "windows");
  clients.web = wrap(fakeWeb(), "web");
  Object.assign(opts, { "azure-min-secure-score": "70", "gcp-project": [GCP_PROJECT], ...JIRA_OPTS,
    "web-url": URL_, "web-proof": `${HOST}=${TOKEN}`, "web-privacy-url": PRIVACY, "web-delay-ms": "200" }, reports(dir));
  sources.push("bamboohr", "rippling", "cloudflare", "aws", "azure", "gcp", "jira", "lms", "prowler", "scubagoggles", "scubagear",
    "trivy", "grype", "syft", "gitleaks", "scorecard", "stig", "kubescape", "checkov", "vulnscan", "macos", "windows", "web");
  return { args: ["--endpoint", ENDPOINT, "--source", sources.join(","), ...toArgs(opts)], clients, env, dir, sources, calls };
}
