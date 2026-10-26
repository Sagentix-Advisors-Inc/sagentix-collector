// The Azure source against a fake ARM transport: pass and fail per check, "skipped" when ARM refuses,
// nextLink paging, 429 backoff, secret scrubbing, and the fetch client's GET-only behaviour.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { azure } from "../src/sources/azure.ts";
import { API, ARM, fetchAzure, tokenFromEnv, type AzureTransport } from "../src/sources/azure/api.ts";
import { adminPortsIn, openAdminRules } from "../src/sources/azure/checks.ts";
import type { HttpReply } from "../src/sources/shared-cloud.ts";
import type { OptionValue, Result } from "../src/types.ts";

const NOW = new Date("2026-10-15T12:00:00Z");
const SUB = "11111111-2222-3333-4444-555555555555";
const S = `/subscriptions/${SUB}`;
const RG = `${S}/resourceGroups/prod`;

type Route = unknown | ((url: string) => HttpReply);
const json = (status: number, body: unknown, headers: Record<string, string> = {}): HttpReply => ({ status, headers, body: JSON.stringify(body) });
const list = (value: unknown[], nextLink?: string) => ({ value, ...(nextLink ? { nextLink } : {}) });
const armErr = (status: number, message: string) => json(status, { error: { code: status === 403 ? "AuthorizationFailed" : "Error", message } });

const rule = (name: string, props: Record<string, unknown>) => ({ name, properties: { direction: "Inbound", access: "Allow", protocol: "Tcp", sourceAddressPrefix: "10.0.0.0/8", destinationPortRange: "443", priority: 100, ...props } });

/** Resources - List answering `$filter=resourceType eq '<type>'` from a list of the types the subscription holds. */
const resources = (types: string[]) => (url: string): HttpReply => {
  const f = decodeURIComponent(/[?&]\$filter=([^&]*)/.exec(url)?.[1] ?? "");
  const want = /resourceType eq '([^']+)'/.exec(f)?.[1];
  return json(200, list(types.filter((t) => t === want).map((t, i) => ({ id: `${RG}/providers/${t}/r${i}`, type: t }))));
};
const VM = `${RG}/providers/Microsoft.Compute/virtualMachines/vm1`;
const patchView = (summary: Record<string, unknown> | undefined, power = "PowerState/running") => ({
  statuses: [{ code: "ProvisioningState/succeeded" }, { code: power }],
  ...(summary ? { patchStatus: { availablePatchSummary: summary } } : {}),
});
const goodPatch = { status: "Succeeded", criticalAndSecurityPatchCount: 0, otherPatchCount: 2, lastModifiedTime: "2026-10-14T03:00:00Z" };

/** A well-configured subscription: every check passes. Keyed by path without the query. */
function strong(): Record<string, Route> {
  return {
    "/subscriptions": list([{ subscriptionId: SUB, state: "Enabled" }]),
    [`${S}/providers/Microsoft.Security/pricings`]: list([
      { name: "VirtualMachines", properties: { pricingTier: "Standard" } },
      { name: "KubernetesService", properties: { pricingTier: "Free", deprecated: true } },
    ]),
    [`${S}/providers/Microsoft.Security/secureScores`]: list([{ name: "ascScore", properties: { score: { current: 30, max: 40, percentage: 0.75 } } }]),
    [`${S}/providers/Microsoft.Insights/diagnosticSettings`]: list([{ name: "to-law", properties: { workspaceId: `${RG}/providers/Microsoft.OperationalInsights/workspaces/law`, logs: [{ category: "Administrative", enabled: true }, { category: "Security", enabled: true }] } }]),
    [`${S}/providers/Microsoft.KeyVault/vaults`]: list([{ id: `${RG}/providers/Microsoft.KeyVault/vaults/kv1`, name: "kv1", properties: { enableSoftDelete: true, enablePurgeProtection: true } }]),
    [`${S}/providers/Microsoft.Storage/storageAccounts`]: list([{ id: `${RG}/providers/Microsoft.Storage/storageAccounts/st1`, name: "st1", properties: { supportsHttpsTrafficOnly: true, allowBlobPublicAccess: false, minimumTlsVersion: "TLS1_2" } }]),
    [`${S}/providers/Microsoft.Sql/servers`]: list([{ id: `${RG}/providers/Microsoft.Sql/servers/sql1`, name: "sql1" }]),
    [`${RG}/providers/Microsoft.Sql/servers/sql1/databases`]: list([
      { id: `${RG}/providers/Microsoft.Sql/servers/sql1/databases/master`, name: "master" },
      { id: `${RG}/providers/Microsoft.Sql/servers/sql1/databases/app`, name: "app" },
    ]),
    [`${RG}/providers/Microsoft.Sql/servers/sql1/databases/app/transparentDataEncryption/current`]: { name: "current", properties: { state: "Enabled" } },
    [`${S}/providers/Microsoft.Network/networkSecurityGroups`]: list([{ id: `${RG}/providers/Microsoft.Network/networkSecurityGroups/web`, name: "web", properties: { securityRules: [rule("https", { sourceAddressPrefix: "Internet" }), rule("ssh-vpn", { destinationPortRange: "22" })] } }]),
    [`${S}/providers/Microsoft.Authorization/policyAssignments`]: list([{ name: "asb", properties: { enforcementMode: "Default" } }]),
    [`${S}/providers/Microsoft.Compute/disks`]: list([{ id: `${RG}/providers/Microsoft.Compute/disks/os1`, name: "os1", properties: { encryption: { type: "EncryptionAtRestWithPlatformKey" } } }]),
    [`${S}/providers/Microsoft.RecoveryServices/vaults`]: list([{ id: `${RG}/providers/Microsoft.RecoveryServices/vaults/rsv`, name: "rsv" }]),
    [`${RG}/providers/Microsoft.RecoveryServices/vaults/rsv/backupProtectedItems`]: list([{ name: "VM;iaasvmcontainerv2;prod;vm1" }]),
    [`${S}/resources`]: resources(["Microsoft.Compute/virtualMachines"]),
    [`${RG}/providers/Microsoft.Sql/servers/sql1/firewallRules`]: list([
      { name: "AllowAllWindowsAzureIps", properties: { startIpAddress: "0.0.0.0", endIpAddress: "0.0.0.0" } },
      { name: "office", properties: { startIpAddress: "203.0.113.0", endIpAddress: "203.0.113.255" } },
    ]),
    [`${S}/providers/Microsoft.Compute/virtualMachines`]: list([{ id: VM, name: "vm1", properties: { osProfile: { linuxConfiguration: { patchSettings: { patchMode: "AutomaticByPlatform", assessmentMode: "AutomaticByPlatform" } } } } }]),
    [`${VM}/instanceView`]: patchView(goodPatch),
  };
}

function fake(over: Record<string, Route> = {}, calls: string[] = [], sleeps: number[] = []): AzureTransport {
  const routes = { ...strong(), ...over };
  return {
    async get(url: string) {
      calls.push(url);
      assert.ok(url.startsWith(`${ARM}/`), url);
      const path = url.slice(ARM.length).split("?")[0];
      const r = routes[path];
      if (r === undefined) return armErr(404, `no fake for ${path}`);
      if (typeof r === "function") return (r as (u: string) => HttpReply)(url);
      if (typeof r === "object" && r !== null && "status" in r && "body" in r) return r as HttpReply;
      return json(200, r);
    },
    sleep: async (ms) => { sleeps.push(ms); },
  };
}

async function run(t: AzureTransport | null, opts: Record<string, OptionValue> = {}, env: NodeJS.ProcessEnv = {}): Promise<Result[]> {
  return azure.run({ opts, env, clients: { azure: t }, now: NOW, warn: () => {} });
}
const of = (rs: Result[], check: string) => rs.filter((r) => r.check === `azure.${check}`);

const FAILS: Record<string, Record<string, Route>> = {
  defender_plans: { [`${S}/providers/Microsoft.Security/pricings`]: list([{ name: "VirtualMachines", properties: { pricingTier: "Free" } }]) },
  secure_score: { [`${S}/providers/Microsoft.Security/secureScores`]: list([{ name: "ascScore", properties: { score: { current: 10, max: 40, percentage: 0.25 } } }]) },
  activity_log_export: { [`${S}/providers/Microsoft.Insights/diagnosticSettings`]: list([{ name: "partial", properties: { workspaceId: "x", logs: [{ category: "Administrative", enabled: false }] } }]) },
  keyvault_recoverable: { [`${S}/providers/Microsoft.KeyVault/vaults`]: list([{ id: `${RG}/providers/Microsoft.KeyVault/vaults/kv1`, name: "kv1", properties: { enableSoftDelete: true } }]) },
  storage_secure_transfer: { [`${S}/providers/Microsoft.Storage/storageAccounts`]: list([{ id: `${RG}/x/st1`, name: "st1", properties: { supportsHttpsTrafficOnly: false, allowBlobPublicAccess: false, minimumTlsVersion: "TLS1_2" } }]) },
  storage_no_public_blob: { [`${S}/providers/Microsoft.Storage/storageAccounts`]: list([{ id: `${RG}/x/st1`, name: "st1", properties: { supportsHttpsTrafficOnly: true, allowBlobPublicAccess: true, minimumTlsVersion: "TLS1_2" } }]) },
  storage_min_tls: { [`${S}/providers/Microsoft.Storage/storageAccounts`]: list([{ id: `${RG}/x/st1`, name: "st1", properties: { supportsHttpsTrafficOnly: true, allowBlobPublicAccess: false } }]) },
  sql_tde: { [`${RG}/providers/Microsoft.Sql/servers/sql1/databases/app/transparentDataEncryption/current`]: { name: "current", properties: { state: "Disabled" } } },
  nsg_no_open_admin_ports: { [`${S}/providers/Microsoft.Network/networkSecurityGroups`]: list([{ id: `${RG}/x/web`, name: "web", properties: { securityRules: [rule("rdp", { sourceAddressPrefix: "*", destinationPortRange: "3000-4000" })] } }]) },
  policy_assignments: { [`${S}/providers/Microsoft.Authorization/policyAssignments`]: list([]) },
  disk_encryption: { [`${S}/providers/Microsoft.Compute/disks`]: list([{ id: `${RG}/x/os1`, name: "os1", properties: {} }]) },
  backup_protected_items: { [`${RG}/providers/Microsoft.RecoveryServices/vaults/rsv/backupProtectedItems`]: list([]) },
  sql_firewall_not_open: { [`${RG}/providers/Microsoft.Sql/servers/sql1/firewallRules`]: list([{ name: "any", properties: { startIpAddress: "0.0.0.0", endIpAddress: "255.255.255.255" } }]) },
  vm_patches_current: { [`${VM}/instanceView`]: patchView({ ...goodPatch, criticalAndSecurityPatchCount: 4 }) },
};

test("every check the source declares has a pass and a fail case here", () => {
  assert.deepEqual(Object.keys(FAILS).sort(), azure.emits.map((c) => c.replace(/^azure\./, "")).sort());
});

test("a well-configured subscription passes every check", async () => {
  const rs = await run(fake(), { "azure-min-secure-score": "70" });
  for (const check of Object.keys(FAILS)) {
    const mine = of(rs, check);
    assert.ok(mine.length >= 1, `${check}: no result`);
    for (const r of mine) assert.equal(r.result, "pass", `${check} [${r.resource}]: ${r.detail}`);
  }
});

for (const [check, over] of Object.entries(FAILS)) {
  test(`${check}: pass on the strong fixture, fail with the observed value when weakened`, async () => {
    const fail = of(await run(fake(over), { "azure-min-secure-score": "70" }), check);
    assert.ok(fail.some((r) => r.result === "fail"), `${check}: ${JSON.stringify(fail)}`);
    for (const r of fail) assert.ok(r.detail.length > 0 && r.detail.length <= 1000);
  });
}

test("a 403 from ARM gives skipped, never pass, for every check", async () => {
  const t: AzureTransport = { async get() { return armErr(403, "The client does not have authorization to perform action"); } };
  const rs = await run(t, { "azure-subscription": SUB });
  assert.deepEqual([...new Set(rs.map((r) => r.check))].sort(), [...azure.emits].sort());
  for (const r of rs) assert.equal(r.result, "skipped", `${r.check}: ${r.detail}`);
  assert.ok(rs.every((r) => /HTTP 403/.test(r.detail)));
});

test("no credential: every check is skipped", async () => {
  const rs = await run(null, { "azure-subscription": SUB });
  assert.equal(rs.length, azure.emits.length);
  for (const r of rs) assert.equal(r.result, "skipped");
  const rs2 = await azure.run({ opts: {}, env: {}, clients: {}, now: NOW, warn: () => {} });
  for (const r of rs2) assert.equal(r.result, "skipped");
});

test("nextLink pages are followed and both pages are judged", async () => {
  const page2 = `${ARM}${S}/providers/Microsoft.Storage/storageAccounts?api-version=${API.storage}&$skiptoken=abc`;
  const calls: string[] = [];
  const rs = await run(fake({
    [`${S}/providers/Microsoft.Storage/storageAccounts`]: (url: string) => url.includes("skiptoken")
      ? json(200, list([{ id: `${RG}/x/st2`, name: "st2", properties: { supportsHttpsTrafficOnly: true, minimumTlsVersion: "TLS1_0" } }]))
      : json(200, list([{ id: `${RG}/x/st1`, name: "st1", properties: { supportsHttpsTrafficOnly: true, minimumTlsVersion: "TLS1_2" } }], page2)),
  }, calls));
  const tls = of(rs, "storage_min_tls");
  assert.deepEqual(tls.map((r) => [r.resource, r.result]), [["storage account prod/st1", "pass"], ["storage account prod/st2", "fail"]]);
  assert.ok(calls.includes(page2));
});

test("a nextLink off management.azure.com is not followed", async () => {
  const calls: string[] = [];
  await run(fake({ [`${S}/providers/Microsoft.Compute/disks`]: list([], "https://evil.example/steal") }, calls));
  assert.ok(calls.every((c) => c.startsWith(`${ARM}/`)));
});

test("429 is retried after Retry-After, then the answer is used", async () => {
  let n = 0;
  const sleeps: number[] = [];
  const rs = await run(fake({
    [`${S}/providers/Microsoft.Authorization/policyAssignments`]: () => (++n < 3 ? json(429, { error: { code: "TooManyRequests" } }, { "retry-after": "2" }) : json(200, list([{ name: "a" }]))),
  }, [], sleeps));
  assert.equal(n, 3);
  assert.deepEqual(sleeps, [2000, 2000]);
  assert.equal(of(rs, "policy_assignments")[0].result, "pass");
});

test("throttling that never ends gives skipped, not pass", async () => {
  const rs = await run(fake({ [`${S}/providers/Microsoft.Authorization/policyAssignments`]: json(429, { error: { message: "slow down" } }) }));
  assert.equal(of(rs, "policy_assignments")[0].result, "skipped");
});

test("no secret value appears in any result", async () => {
  const env = { AZURE_ACCESS_TOKEN: "eyJ0eXAiOiJKV1QiLCJhbGciOi.secret-token-value", AZURE_CLIENT_SECRET: "cl1ent~s3cret~value" };
  const t: AzureTransport = { async get() { return armErr(401, `token ${env.AZURE_ACCESS_TOKEN} rejected for client secret ${env.AZURE_CLIENT_SECRET}`); } };
  const rs = await run(t, { "azure-subscription": SUB }, env);
  const all = JSON.stringify(rs);
  assert.ok(!all.includes(env.AZURE_ACCESS_TOKEN) && !all.includes(env.AZURE_CLIENT_SECRET));
  assert.match(all, /\[redacted\]/);
});

test("subscriptions are listed when none is given, and disabled ones are left out", async () => {
  const rs = await run(fake({ "/subscriptions": list([{ subscriptionId: SUB, state: "Enabled" }, { subscriptionId: "dead", state: "Disabled" }]) }));
  assert.ok(rs.length > 0 && rs.every((r) => !r.resource.includes("dead")));
});

test("NSG port parsing covers *, single ports and ranges", () => {
  assert.deepEqual(adminPortsIn("*"), [22, 3389]);
  assert.deepEqual(adminPortsIn("22"), [22]);
  assert.deepEqual(adminPortsIn("20-25"), [22]);
  assert.deepEqual(adminPortsIn("443"), []);
  assert.deepEqual(openAdminRules({ properties: { securityRules: [rule("x", { sourceAddressPrefixes: ["0.0.0.0/0"], destinationPortRanges: ["3389"] })] } }), ["x:3389"]);
  assert.deepEqual(openAdminRules({ properties: { securityRules: [rule("deny", { access: "Deny", sourceAddressPrefix: "*", destinationPortRange: "*" })] } }), []);
  assert.deepEqual(openAdminRules({ properties: { securityRules: [rule("udp", { protocol: "Udp", sourceAddressPrefix: "*", destinationPortRange: "*" })] } }), []);
});

test("resources name the subscription, plan, vault, account, database, NSG and disk; (check, resource) is unique", async () => {
  const rs = await run(fake());
  const res = new Set(rs.map((r) => r.resource));
  for (const want of [`subscription ${SUB}`, `defender plan VirtualMachines (subscription ${SUB})`, "key vault prod/kv1", "storage account prod/st1",
    "sql database prod/sql1/app", "nsg prod/web", "disk prod/os1", "recovery vault prod/rsv"]) assert.ok(res.has(want), want);
  const keys = rs.map((r) => `${r.check}|${r.resource}`);
  assert.equal(new Set(keys).size, keys.length);
  assert.ok(!rs.some((r) => r.resource.includes("master")), "master is excluded from TDE");
});

test("the fetch client sends GET with the bearer token, and refuses other hosts", async () => {
  const seen: { url: string; init: RequestInit }[] = [];
  const f = (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    return new Response(JSON.stringify({ value: [] }), { status: 200 });
  }) as unknown as typeof fetch;
  const t = fetchAzure(async () => "tok", f);
  await t.get(`${ARM}/subscriptions?api-version=${API.subscriptions}`);
  assert.equal(seen[0].init.method, "GET");
  assert.equal((seen[0].init.headers as Record<string, string>).authorization, "Bearer tok");
  assert.equal(seen[0].init.body, undefined);
  const r = await t.get("https://evil.example/x");
  assert.equal(r.status, 0);
  assert.equal(seen.length, 1);
});

test("client credentials: a federated token file is sent as client_assertion to login.microsoftonline.com", async () => {
  const dir = mkdtempSync(join(tmpdir(), "azure-test-"));
  const file = join(dir, "oidc");
  writeFileSync(file, "header.payload.sig\n");
  const seen: { url: string; init: RequestInit }[] = [];
  const f = (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    return new Response(JSON.stringify({ access_token: "arm-token", token_type: "Bearer" }), { status: 200 });
  }) as unknown as typeof fetch;
  const src = tokenFromEnv({ AZURE_TENANT_ID: "tenant-1", AZURE_CLIENT_ID: "app-1", AZURE_FEDERATED_TOKEN_FILE: file }, f)!;
  assert.equal(await src(), "arm-token");
  assert.equal(await src(), "arm-token");
  assert.equal(seen.length, 1, "the token is cached");
  assert.equal(seen[0].url, "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token");
  const body = new URLSearchParams(String(seen[0].init.body));
  assert.equal(body.get("client_assertion"), "header.payload.sig");
  assert.equal(body.get("client_assertion_type"), "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
  assert.equal(body.get("scope"), "https://management.azure.com/.default");
  assert.equal(tokenFromEnv({ AZURE_TENANT_ID: "t" }), undefined);
});

test("a refused token request makes every check skipped, with no secret in the detail", async () => {
  const f = (async () => new Response(JSON.stringify({ error: "invalid_client", error_description: "AADSTS7000215" }), { status: 401 })) as unknown as typeof fetch;
  const env = { AZURE_TENANT_ID: "t", AZURE_CLIENT_ID: "c", AZURE_CLIENT_SECRET: "very-secret-value-123" };
  const t = fetchAzure(tokenFromEnv(env, f)!, f);
  const rs = await run(t, { "azure-subscription": SUB }, env);
  for (const r of rs) assert.equal(r.result, "skipped");
  assert.ok(!JSON.stringify(rs).includes(env.AZURE_CLIENT_SECRET));
  assert.match(rs[0].detail, /invalid_client/);
});

test("defender_plans: a plan is demanded only where the subscription has resources it protects; Arm always", async () => {
  const pricings = list([
    { name: "VirtualMachines", properties: { pricingTier: "Free" } },
    { name: "StorageAccounts", properties: { pricingTier: "Free" } },
    { name: "Arm", properties: { pricingTier: "Free" } },
    { name: "CloudPosture", properties: { pricingTier: "Free" } },
  ]);
  const calls: string[] = [];
  const rs = of(await run(fake({ [`${S}/providers/Microsoft.Security/pricings`]: pricings }, calls)), "defender_plans");
  const by = Object.fromEntries(rs.map((r) => [r.resource.split(" ")[2], r]));
  assert.equal(by.VirtualMachines.result, "fail");
  assert.match(by.VirtualMachines.detail, /1 Microsoft.Compute\/virtualMachines/);
  assert.equal(by.StorageAccounts.result, "skipped");
  assert.match(by.StorageAccounts.detail, /no Microsoft.Storage\/storageAccounts, so the plan is not required/);
  assert.equal(by.Arm.result, "fail");
  assert.equal(by.CloudPosture.result, "skipped");
  assert.ok(calls.some((c) => c.includes(encodeURIComponent("resourceType eq 'Microsoft.HybridCompute/machines'"))), "Arc machines count for Defender for Servers");
  const denied = of(await run(fake({ [`${S}/providers/Microsoft.Security/pricings`]: pricings, [`${S}/resources`]: armErr(403, "no") })), "defender_plans");
  assert.equal(denied.find((r) => r.resource.includes("StorageAccounts"))?.result, "skipped");
});

test("sql_firewall_not_open: public network access off passes without reading rules; Allow Azure services is reported, not failed", async () => {
  const calls: string[] = [];
  const off = of(await run(fake({ [`${S}/providers/Microsoft.Sql/servers`]: list([{ id: `${RG}/providers/Microsoft.Sql/servers/sql1`, name: "sql1", properties: { publicNetworkAccess: "Disabled" } }]) }, calls)), "sql_firewall_not_open");
  assert.equal(off[0].result, "pass");
  assert.ok(!calls.some((c) => c.includes("/firewallRules")));
  const azureOnly = of(await run(fake()), "sql_firewall_not_open");
  assert.equal(azureOnly[0].result, "pass");
  assert.match(azureOnly[0].detail, /Allow Azure services/);
});

test("vm_patches_current: no assessment fails, a stale one fails, a stopped VM is skipped", async () => {
  const none = of(await run(fake({ [`${VM}/instanceView`]: patchView(undefined) })), "vm_patches_current");
  assert.equal(none[0].result, "fail");
  assert.match(none[0].detail, /patchMode "AutomaticByPlatform"; no patch assessment/);
  const stale = of(await run(fake({ [`${VM}/instanceView`]: patchView({ ...goodPatch, lastModifiedTime: "2026-09-01T00:00:00Z" }) })), "vm_patches_current");
  assert.equal(stale[0].result, "fail");
  const stopped = of(await run(fake({ [`${VM}/instanceView`]: patchView(goodPatch, "PowerState/deallocated") })), "vm_patches_current");
  assert.equal(stopped[0].result, "skipped");
});
