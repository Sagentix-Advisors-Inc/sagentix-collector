// The GCP source against a fake transport: a pass and a fail case per check, "skipped" when Google
// refuses, pagination, retry on 429, no token in any result, and the fetch client's method guard.
import { test } from "node:test";
import assert from "node:assert/strict";
import { gcp } from "../src/sources/gcp.ts";
import { fetchGcpTransport, type GcpTransport } from "../src/sources/gcp/api.ts";
import type { HttpReply } from "../src/sources/shared-cloud.ts";
import type { OptionValue, Result } from "../src/types.ts";

const NOW = new Date("2026-10-15T12:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();
const P = "acme-prod";
const TOKEN = "ya29.fake-access-token-value-0123456789";

const CRM = `https://cloudresourcemanager.googleapis.com/v1/projects/${P}:getIamPolicy`;
const ORG = (c: string) => `https://orgpolicy.googleapis.com/v2/projects/${P}/policies/${c}:getEffectivePolicy`;
const SAS = `https://iam.googleapis.com/v1/projects/${P}/serviceAccounts`;
const SA = "ci@acme-prod.iam.gserviceaccount.com";
const KEYS = `${SAS}/${encodeURIComponent(SA)}/keys`;
const BUCKETS = "https://storage.googleapis.com/storage/v1/b";
const BIAM = `${BUCKETS}/acme-assets/iam`;
const SQL = `https://sqladmin.googleapis.com/v1/projects/${P}/instances`;
const FW = `https://compute.googleapis.com/compute/v1/projects/${P}/global/firewalls`;
const SUBNETS = `https://compute.googleapis.com/compute/v1/projects/${P}/aggregated/subnetworks`;
const SU = `https://serviceusage.googleapis.com/v1/projects/${P}/services/securitycenter.googleapis.com`;
const LOCS = `https://cloudkms.googleapis.com/v1/projects/${P}/locations`;
const RINGS = `${LOCS}/us-central1/keyRings`;
const RING = `projects/${P}/locations/us-central1/keyRings/main`;
const CKEYS = `https://cloudkms.googleapis.com/v1/${RING}/cryptoKeys`;
const CRM3 = "https://cloudresourcemanager.googleapis.com/v3";
const ANCESTRY = `https://cloudresourcemanager.googleapis.com/v1/projects/${P}:getAncestry`;
const FOLDER = `${CRM3}/folders/111`, ORGN = `${CRM3}/organizations/222`;
const INSTANCES = `https://compute.googleapis.com/compute/v1/projects/${P}/aggregated/instances`;
const VULNS = `https://osconfig.googleapis.com/v1/projects/${P}/locations/us-central1-a/instances/-/vulnerabilityReports`;
const vulnReport = (id: string, sev: string, updated = daysAgo(1)) => ({ name: `projects/123/locations/us-central1-a/instances/${id}/vulnerabilityReport`, highestUpgradableCveSeverity: sev, vulnerabilities: [{}, {}], updateTime: updated });
const NMCFG = `https://networkmanagement.googleapis.com/v1/projects/${P}/locations/global/vpcFlowLogsConfigs`;
const NMORG = `${NMCFG}:queryOrgVpcFlowLogsConfigs`;

type Route = unknown | ((url: string) => HttpReply);
const ok = (json: unknown): HttpReply => ({ status: 200, headers: {}, body: JSON.stringify(json) });
const err = (status: number, message = "The caller does not have permission"): HttpReply =>
  ({ status, headers: {}, body: JSON.stringify({ error: { code: status, message, status: "PERMISSION_DENIED" } }) });

function strong(): Record<string, Route> {
  return {
    [CRM]: { version: 3, bindings: [{ role: "roles/owner", members: ["user:alice@example.com"] }], auditConfigs: [{ service: "allServices", auditLogConfigs: [{ logType: "ADMIN_READ" }, { logType: "DATA_READ" }, { logType: "DATA_WRITE" }] }] },
    [ANCESTRY]: { ancestor: [{ resourceId: { type: "project", id: P } }, { resourceId: { type: "folder", id: "111" } }, { resourceId: { type: "organization", id: "222" } }] },
    [`${FOLDER}:getIamPolicy`]: { version: 3, bindings: [] },
    [`${ORGN}:getIamPolicy`]: { version: 3, bindings: [] },
    [NMCFG]: { vpcFlowLogsConfigs: [] },
    [NMORG]: { vpcFlowLogsConfigs: [] },
    [ORG("iam.disableServiceAccountKeyCreation")]: { name: "x", spec: { rules: [{ enforce: true }] } },
    [ORG("storage.publicAccessPrevention")]: { name: "y", spec: { rules: [{ enforce: true }] } },
    [SAS]: { accounts: [{ email: SA, uniqueId: "1" }] },
    [KEYS]: { keys: [{ name: "k1", keyType: "USER_MANAGED", validAfterTime: daysAgo(30) }] },
    [BUCKETS]: { items: [{ name: "acme-assets", iamConfiguration: { publicAccessPrevention: "inherited" } }] },
    [BIAM]: { bindings: [{ role: "roles/storage.objectViewer", members: ["serviceAccount:ci@acme-prod.iam.gserviceaccount.com"] }] },
    [SQL]: { items: [{ name: "db1", settings: { ipConfiguration: { ipv4Enabled: false, sslMode: "ENCRYPTED_ONLY", authorizedNetworks: [] } } }] },
    [FW]: { items: [{ name: "allow-https", direction: "INGRESS", sourceRanges: ["0.0.0.0/0"], allowed: [{ IPProtocol: "tcp", ports: ["443"] }] }, { name: "egress-all", direction: "EGRESS", destinationRanges: ["0.0.0.0/0"], allowed: [{ IPProtocol: "all" }] }] },
    [SU]: { name: "projects/123/services/securitycenter.googleapis.com", state: "ENABLED" },
    [LOCS]: { locations: [{ locationId: "us-central1", name: `projects/${P}/locations/us-central1` }] },
    [RINGS]: { keyRings: [{ name: RING }] },
    [CKEYS]: { cryptoKeys: [{ name: `${RING}/cryptoKeys/app`, purpose: "ENCRYPT_DECRYPT", rotationPeriod: "7776000s" }, { name: `${RING}/cryptoKeys/sign`, purpose: "ASYMMETRIC_SIGN" }] },
    [INSTANCES]: { items: { "zones/us-central1-a": { instances: [{ id: "4001", name: "web-1", zone: "https://x/zones/us-central1-a", status: "RUNNING" }, { id: "4002", name: "old", zone: "https://x/zones/us-central1-a", status: "TERMINATED" }] }, "zones/europe-west1-b": { warning: { code: "NO_RESULTS_ON_PAGE" } } } },
    [VULNS]: { vulnerabilityReports: [vulnReport("4001", "LOW")] },
    [SUBNETS]: { items: { "regions/us-central1": { subnetworks: [{ name: "app", region: "https://x/regions/us-central1", purpose: "PRIVATE", logConfig: { enable: true } }, { name: "proxy", region: "r/us-central1", purpose: "REGIONAL_MANAGED_PROXY" }] }, "regions/europe-west1": { warning: { code: "NO_RESULTS_ON_PAGE" } } } },
  };
}

interface Call { method: string; url: string; body?: unknown }
function fake(over: Record<string, Route> = {}, calls: Call[] = []): GcpTransport {
  const routes = { ...strong(), ...over };
  return {
    sleep: async () => {},
    async request(method, url, body) {
      calls.push({ method, url, body });
      const r = routes[url.split("?")[0]];
      if (r === undefined) return err(404, `no fake for ${url}`);
      return typeof r === "function" ? (r as (u: string) => HttpReply)(url) : ok(r);
    },
  };
}

async function run(t: GcpTransport | null, opts: Record<string, OptionValue> = { "gcp-project": [P] }, env: NodeJS.ProcessEnv = {}): Promise<Result[]> {
  return gcp.run({ opts, env, clients: { gcp: t }, now: NOW, warn: () => {} });
}
const of = (rs: Result[], check: string) => rs.filter((r) => r.check === `gcp.${check}`);

const FAILS: Record<string, Record<string, Route>> = {
  data_access_audit_logs: { [CRM]: { bindings: [], auditConfigs: [{ service: "allServices", auditLogConfigs: [{ logType: "ADMIN_READ" }] }] } },
  org_policy_enforced: { [ORG("iam.disableServiceAccountKeyCreation")]: { name: "x", spec: { rules: [{ enforce: false }] } } },
  sa_keys_rotated: { [KEYS]: { keys: [{ name: "k1", keyType: "USER_MANAGED", validAfterTime: daysAgo(200) }] } },
  bucket_not_public: { [BIAM]: { bindings: [{ role: "roles/storage.objectViewer", members: ["allUsers"] }] } },
  cloudsql_no_public_ip: { [SQL]: { items: [{ name: "db1", settings: { ipConfiguration: { ipv4Enabled: true, sslMode: "ENCRYPTED_ONLY", authorizedNetworks: [{ value: "0.0.0.0/0" }] } } }] } },
  cloudsql_ssl_required: { [SQL]: { items: [{ name: "db1", settings: { ipConfiguration: { ipv4Enabled: false, sslMode: "ALLOW_UNENCRYPTED_AND_ENCRYPTED", requireSsl: true } } }] } },
  firewall_no_open_admin_ports: { [FW]: { items: [{ name: "ssh-world", direction: "INGRESS", sourceRanges: ["0.0.0.0/0"], allowed: [{ IPProtocol: "tcp", ports: ["20-25"] }] }] } },
  scc_api_enabled: { [SU]: { state: "DISABLED" } },
  kms_rotation: { [CKEYS]: { cryptoKeys: [{ name: `${RING}/cryptoKeys/app`, purpose: "ENCRYPT_DECRYPT" }] } },
  vpc_flow_logs: { [SUBNETS]: { items: { "regions/us-central1": { subnetworks: [{ name: "app", region: "r/us-central1", logConfig: { enable: false } }] } } } },
  vm_os_vulnerabilities: { [VULNS]: { vulnerabilityReports: [vulnReport("4001", "CRITICAL")] } },
};

test("data_access_audit_logs: DATA_READ and DATA_WRITE set at the folder or organization count for the project (the hierarchy's union)", async () => {
  const projectOnlyAdmin = { [CRM]: { bindings: [], auditConfigs: [{ service: "allServices", auditLogConfigs: [{ logType: "ADMIN_READ" }] }] } };
  const orgSet = { [`${ORGN}:getIamPolicy`]: { version: 3, auditConfigs: [{ service: "allServices", auditLogConfigs: [{ logType: "DATA_READ" }, { logType: "DATA_WRITE" }] }] } };
  const viaOrg = of(await run(fake({ ...projectOnlyAdmin, ...orgSet })), "data_access_audit_logs")[0];
  assert.equal(viaOrg.result, "pass", viaOrg.detail);
  assert.match(viaOrg.detail, /organizations\/222/);
  const split = of(await run(fake({ ...projectOnlyAdmin,
    [`${FOLDER}:getIamPolicy`]: { auditConfigs: [{ service: "allServices", auditLogConfigs: [{ logType: "DATA_READ" }] }] },
    [`${ORGN}:getIamPolicy`]: { auditConfigs: [{ service: "allServices", auditLogConfigs: [{ logType: "DATA_WRITE" }] }] } })), "data_access_audit_logs")[0];
  assert.equal(split.result, "pass", split.detail);
  const hidden = of(await run(fake({ ...projectOnlyAdmin, [`${ORGN}:getIamPolicy`]: () => err(403) })), "data_access_audit_logs")[0];
  assert.equal(hidden.result, "skipped", hidden.detail);
});

test("vpc_flow_logs: a subnet off in Compute Engine passes when a Network Management API configuration covers it, its network or the organization", async () => {
  const off = { [SUBNETS]: { items: { "regions/us-central1": { subnetworks: [{ name: "app", region: "https://x/regions/us-central1", network: `https://www.googleapis.com/compute/v1/projects/${P}/global/networks/vpc1`, logConfig: { enable: false } }] } } } };
  const cfg = (c: Record<string, unknown>) => ({ vpcFlowLogsConfigs: [{ name: `projects/${P}/locations/global/vpcFlowLogsConfigs/c1`, state: "ENABLED", ...c }] });
  const r = async (over: Record<string, Route>) => of(await run(fake({ ...off, ...over })), "vpc_flow_logs")[0];
  assert.equal((await r({ [NMCFG]: cfg({ subnet: `projects/${P}/regions/us-central1/subnetworks/app` }) })).result, "pass");
  assert.equal((await r({ [NMCFG]: cfg({ network: `projects/${P}/global/networks/vpc1` }) })).result, "pass");
  assert.equal((await r({ [NMORG]: cfg({ name: "organizations/222/locations/global/vpcFlowLogsConfigs/o1" }) })).result, "pass");
  assert.equal((await r({ [NMCFG]: cfg({ network: `projects/${P}/global/networks/vpc1`, state: "DISABLED" }) })).result, "fail");
  assert.equal((await r({ [NMORG]: cfg({ filterExpr: "src_ip == '10.0.0.1'" }) })).result, "fail");
  assert.equal((await r({ [NMCFG]: () => err(403, "Network Management API has not been used in project 123 before or it is disabled"), [NMORG]: () => err(403, "Network Management API has not been used in project 123 before or it is disabled") })).result, "fail");
  assert.equal((await r({ [NMCFG]: () => err(403) })).result, "skipped");
});

test("every check the source declares has a pass and a fail case here", () => {
  assert.deepEqual(Object.keys(FAILS).sort(), gcp.emits.map((c) => c.replace(/^gcp\./, "")).sort());
});

test("a well-configured project passes every check", async () => {
  const rs = await run(fake());
  for (const check of Object.keys(FAILS)) {
    const mine = of(rs, check);
    assert.ok(mine.length >= 1, `${check}: no result`);
    for (const r of mine) assert.equal(r.result, "pass", `${check} [${r.resource}]: ${r.detail}`);
  }
});

for (const [check, over] of Object.entries(FAILS)) {
  test(`${check}: fail with the observed value when weakened`, async () => {
    const fail = of(await run(fake(over)), check);
    assert.ok(fail.some((r) => r.result === "fail"), `${check}: ${JSON.stringify(fail)}`);
    for (const r of fail) assert.ok(r.detail.length > 0 && r.detail.length <= 1000);
  });
}

test("firewall: 3389 via IPProtocol all, ::/0, and a disabled rule", async () => {
  const rs = of(await run(fake({ [FW]: { items: [
    { name: "all-v6", sourceRanges: ["::/0"], allowed: [{ IPProtocol: "all" }] },
    { name: "rdp-off", disabled: true, sourceRanges: ["0.0.0.0/0"], allowed: [{ IPProtocol: "tcp", ports: ["3389"] }] },
    { name: "rdp-internal", sourceRanges: ["10.0.0.0/8"], allowed: [{ IPProtocol: "tcp", ports: ["3389"] }] },
  ] } })), "firewall_no_open_admin_ports");
  const by = Object.fromEntries(rs.map((r) => [r.resource, r.result]));
  assert.deepEqual(by, { [`firewall ${P}/all-v6`]: "fail", [`firewall ${P}/rdp-off`]: "pass", [`firewall ${P}/rdp-internal`]: "pass" });
});

test("a bucket with public access prevention enforced passes without reading its IAM policy", async () => {
  const calls: Call[] = [];
  const rs = of(await run(fake({ [BUCKETS]: { items: [{ name: "locked", iamConfiguration: { publicAccessPrevention: "enforced" } }] } }, calls)), "bucket_not_public");
  assert.equal(rs[0].result, "pass");
  assert.ok(!calls.some((c) => c.url.includes("/b/locked/iam")));
});

test("a 403 from every API gives skipped, never pass, for every check", async () => {
  const t: GcpTransport = { sleep: async () => {}, request: async () => err(403) };
  const rs = await run(t);
  assert.ok(rs.length >= gcp.emits.length);
  for (const r of rs) {
    assert.equal(r.result, "skipped", `${r.check}: ${r.detail}`);
    assert.match(r.detail, /HTTP 403/);
  }
  assert.deepEqual(new Set(rs.map((r) => r.check)), new Set(gcp.emits));
});

test("no token: every check is skipped; no project: every check is skipped", async () => {
  for (const rs of [await run(null), await run(fake(), {})]) {
    assert.equal(rs.length, gcp.emits.length);
    for (const r of rs) assert.equal(r.result, "skipped");
  }
});

test("pageToken pagination: two pages of service accounts are both checked", async () => {
  const calls: Call[] = [];
  const SA2 = "batch@acme-prod.iam.gserviceaccount.com";
  const rs = of(await run(fake({
    [SAS]: (url: string) => url.includes("pageToken=p2") ? ok({ accounts: [{ email: SA2 }] }) : ok({ accounts: [{ email: SA }], nextPageToken: "p2" }),
    [`${SAS}/${encodeURIComponent(SA2)}/keys`]: { keys: [] },
  }, calls)), "sa_keys_rotated");
  assert.deepEqual(rs.map((r) => r.resource).sort(), [`service account ${SA2}`, `service account ${SA}`].sort());
  assert.equal(calls.filter((c) => c.url.split("?")[0] === SAS).length, 2);
});

test("429 is retried with backoff, then the answer is used", async () => {
  let n = 0; const waits: number[] = [];
  const t = fake({ [SU]: () => (++n < 3 ? { status: 429, headers: { "retry-after": "2" }, body: "{}" } : ok({ state: "ENABLED" })) });
  t.sleep = async (ms) => { waits.push(ms); };
  const rs = of(await run(t), "scc_api_enabled");
  assert.equal(rs[0].result, "pass");
  assert.equal(n, 3);
  assert.deepEqual(waits, [2000, 2000]);
});

test("throttling that never ends gives skipped", async () => {
  const rs = of(await run(fake({ [SU]: () => ({ status: 503, headers: {}, body: "" }) })), "scc_api_enabled");
  assert.equal(rs[0].result, "skipped");
});

test("no secret in any result: a token echoed in an error body is redacted; members are never reported", async () => {
  const rs = await run(fake({ [SU]: () => err(401, `invalid token ${TOKEN}`) }), { "gcp-project": [P] }, { GOOGLE_OAUTH_ACCESS_TOKEN: TOKEN });
  const all = JSON.stringify(rs);
  assert.ok(!all.includes(TOKEN));
  assert.ok(all.includes("[redacted]"));
  assert.ok(!all.includes("alice@example.com"));
});

test("getIamPolicy is a POST asking for policy version 3, getAncestry a POST with an empty body; everything else is GET", async () => {
  const calls: Call[] = [];
  await run(fake({ [CRM]: { bindings: [], auditConfigs: [] } }, calls));
  assert.ok(calls.some((c) => c.url === ANCESTRY), "the ancestry is read when the project falls short");
  for (const c of calls) {
    if (c.method === "POST" && c.url.endsWith(":getAncestry")) assert.deepEqual(c.body, {});
    else if (c.method === "POST") { assert.match(c.url, /:getIamPolicy$/); assert.deepEqual(c.body, { options: { requestedPolicyVersion: 3 } }); }
    else assert.equal(c.method, "GET");
  }
  assert.ok(!calls.some((c) => /\/v3\/(projects|folders)\/[^:]+$/.test(c.url)), "folders are never walked with folders.get");
});

test("data_access_audit_logs: an unreadable ancestry leaves the result skipped, not failed", async () => {
  const r = of(await run(fake({ [CRM]: { bindings: [], auditConfigs: [] }, [ANCESTRY]: () => err(403) })), "data_access_audit_logs")[0];
  assert.equal(r.result, "skipped", r.detail);
  assert.match(r.detail, /ancestry not readable/);
});

test("vm_os_vulnerabilities: a running VM without a report fails, a stale report fails, a stopped VM is not judged", async () => {
  const strongRun = of(await run(fake()), "vm_os_vulnerabilities");
  assert.deepEqual(strongRun.map((r) => [r.resource, r.result]), [[`instance ${P}/us-central1-a/web-1`, "pass"]]);
  const none = of(await run(fake({ [VULNS]: { vulnerabilityReports: [] } })), "vm_os_vulnerabilities");
  assert.equal(none[0].result, "fail");
  assert.match(none[0].detail, /no vulnerability report/);
  const stale = of(await run(fake({ [VULNS]: { vulnerabilityReports: [vulnReport("4001", "LOW", daysAgo(30))] } })), "vm_os_vulnerabilities");
  assert.equal(stale[0].result, "fail");
  const off = of(await run(fake({ [VULNS]: () => err(403, "OS Config API has not been used in project 123 before or it is disabled") })), "vm_os_vulnerabilities");
  assert.equal(off[0].result, "fail");
  assert.match(off[0].detail, /OS Config API is off/);
  const denied = of(await run(fake({ [VULNS]: () => err(403) })), "vm_os_vulnerabilities");
  assert.equal(denied[0].result, "skipped");
});

test("the fetch client sends the bearer token and refuses any POST but :getIamPolicy", async () => {
  const seen: { url: string; init: RequestInit }[] = [];
  const t = fetchGcpTransport(TOKEN, (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    return new Response("{}", { status: 200 });
  }) as unknown as typeof fetch);
  await t.request("GET", SU);
  assert.equal((seen[0].init.headers as Record<string, string>).authorization, `Bearer ${TOKEN}`);
  assert.equal(seen[0].init.body, undefined);
  await t.request("POST", CRM, { options: { requestedPolicyVersion: 3 } });
  assert.equal(seen[1].init.method, "POST");
  await t.request("POST", ANCESTRY, {});
  assert.equal(seen[2].init.method, "POST");
  await assert.rejects(t.request("POST", `https://cloudresourcemanager.googleapis.com/v1/projects/${P}:setIamPolicy`, {}), /refused/);
  assert.equal(seen.length, 3);
});
