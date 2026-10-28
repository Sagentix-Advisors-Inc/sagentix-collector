// The ManageEngine Endpoint Central (cloud) source against a fake API shaped like the scan computers list, the disk
// encryption and firewall inventory endpoints and the patch system health report. Fixtures are written by hand from the
// documented field names and sample responses.
import { test } from "node:test";
import assert from "node:assert/strict";
import { PATCH_PAGE, acceptFor, endpoint_central, endpointCentralFromEnv, suffixOf } from "../src/sources/endpoint_central.ts";
import { contractSuite, fakeRest, of, res, runWith, type Contract, type Route, type Routes } from "./rest_fakes.ts";
import { NOW } from "./helpers.ts";

const BASE = "https://endpointcentral.manageengine.ca";
const SCAN = "/dcapi/inventory/viewData/scanComputers";
const HEALTH = "/dcapi/patch/reports/systemHealth";
const INV = "/dcapi/inventory/computers";
const ok = (b: unknown) => res(200, b);
const q = (url: string) => new URL(`https://x${url}`).searchParams;
const msAgo = (days: number) => String(NOW.getTime() - days * 86_400_000);

interface Over { platform?: string; version?: string; install?: string; contact?: string; drives?: [string, string][]; profiles?: [string, string, string];
  external?: string; missing?: string }
interface Pc { id: string; tag: string; name: string; o?: Over }

function computer(p: Pc): Record<string, unknown> {
  return {
    resource_id: p.id, servicetag: p.tag, resource_name: p.name, resource_name_transform: p.name, name: "Anna Chao", name_transform: "Anna Chao",
    fqdn_name: `${p.name.toUpperCase()}.ACME.EXAMPLE`, ip_address: "10.0.0.7", mac_address: "00:11:22:33:44:55", domain_netbios_name: "ACME",
    os_platform: p.o?.platform ?? "1", os_name: "Windows 11 Professional Edition (x64)", os_version: p.o?.version ?? "10.0.26200", build_number: "26200.8246",
    installation_status: p.o?.install ?? "22", agent_last_contact_time: p.o?.contact ?? msAgo(1), computer_live_status: "1", customer_id: "1",
  };
}

function fleet(pcs: Pc[], pageSize = 25): Routes {
  const r: Routes = {
    [SCAN]: (url) => {
      const page = Number(q(url).get("page") ?? "1");
      const rows = pcs.slice((page - 1) * pageSize, page * pageSize).map(computer);
      const pages = Math.max(1, Math.ceil(pcs.length / pageSize));
      return ok({ metadata: { limit: pageSize, page }, totalRecords: String(pcs.length), totalPages: pages, messageResponse: rows,
        Links: { next: page < pages ? `${SCAN}?toolID=2131&page=${page + 1}` : null, prev: null }, status: "success" });
    },
    [HEALTH]: (url) => {
      const page = Number(q(url).get("page"));
      const size = Number(q(url).get("pageLimit"));
      const rows = pcs.slice((page - 1) * size, page * size).map((p) => ({ ComputerName: p.name, Domain: "ACME", Health: Number(p.o?.missing ?? "0") ? "Vulnerable" : "Healthy",
        MissingOsPatches: p.o?.missing ?? "0", Critical: "0", Important: p.o?.missing ?? "0", Owner: "Anna Chao", OwnerEmail: "anna@acme.example", LoggedOnUsers: "achao" }));
      const pages = Math.max(1, Math.ceil(pcs.length / size));
      return ok({ metadata: { limit: size, page }, totalRecords: pcs.length, totalPages: pages, messageResponse: rows,
        Links: { next: page < pages ? `${HEALTH}?page=${page + 1}&pageLimit=${size}` : null, prev: null }, status: "success" });
    },
  };
  for (const p of pcs) {
    const drives = p.o?.drives ?? [["C:", "Encrypted"]];
    r[`${INV}/${p.id}/diskEncryptionStatus`] = ok({ diskEncryptionStatusDetails: drives.map(([d, s]) => ({ logicalDriveName: d, encryptionStatus: s, logicalDiskType: "Primary", encryptionMethod: s === "Encrypted" ? "XTS-AES 128" : "None" })) });
    const [dp, pp, pub] = p.o?.profiles ?? ["Enabled", "Enabled", "Enabled"];
    r[`${INV}/${p.id}/firewall`] = ok({
      windowsFirewallDetails: p.o?.platform && p.o.platform !== "1" ? [] : [{ isExternalFirewallEnabled: p.o?.external ? "true" : "false", domainProfileStatus: dp, externalFirewallName: "-", privateProfileStatus: pp, publicProfileStatus: pub }],
      externalFirewallDetails: p.o?.external ? [{ firewallName: "Sample Firewall", protectionStatus: p.o.external, installationPath: "C:\\Users\\achao\\fw", manufacturer: "Sample Security Corp" }] : [],
    });
  }
  return r;
}
const strong = () => fleet([{ id: "301", tag: "SAMPLE01", name: "anna-pc" }, { id: "302", tag: "SAMPLE02", name: "bob-pc" }]);
const weak = (o: Over) => fleet([{ id: "301", tag: "SAMPLE01", name: "anna-pc" }, { id: "302", tag: "SAMPLE02", name: "bob-pc", o }]);

const C: Contract = {
  source: endpoint_central, clientKey: "endpoint_central", base: BASE, prefix: "endpoint_central", strong,
  opts: { "endpoint-central-min-os": ["windows=10.0.26100"] },
  env: { ENDPOINT_CENTRAL_URL: BASE, ENDPOINT_CENTRAL_CLIENT_ID: "1000.CLIENT", ENDPOINT_CENTRAL_CLIENT_SECRET: "x", ENDPOINT_CENTRAL_REFRESH_TOKEN: "y" },
  rateLimited: { path: SCAN, check: "agent_installed" },
  fails: {
    disk_encryption: weak({ drives: [["C:", "Encrypted"], ["D:", "Not Encrypted"]] }),
    firewall: weak({ profiles: ["Enabled", "Enabled", "Disabled"] }),
    os_minimum: weak({ version: "10.0.19045" }),
    os_patches: weak({ missing: "4" }),
    last_contact: weak({ contact: msAgo(30) }),
    agent_installed: weak({ install: "29" }),
  },
};

contractSuite(C);

test("endpoint_central: GET only the four documented endpoints, each with its Accept type; no name, user, address or path reaches a result", async () => {
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(BASE, strong(), calls));
  assert.deepEqual([...new Set(calls.map((c) => c.split("?")[0].replace(/\/30\d\//, "/{id}/")))].sort(),
    [SCAN, HEALTH, `${INV}/{id}/diskEncryptionStatus`, `${INV}/{id}/firewall`].sort());
  assert.equal(q(calls[0]).get("toolID"), "2131");
  assert.equal(acceptFor(calls[0]), "application/InventoryMobileAPI.v1+json");
  assert.equal(acceptFor(`${INV}/301/diskEncryptionStatus`), "application/diskEncryptionStatus.v1+json");
  assert.equal(acceptFor(`${INV}/301/firewall`), "application/firewallInfo.v1+json");
  assert.equal(acceptFor(`${HEALTH}?page=1`), "application/json");
  const all = JSON.stringify(rs);
  for (const s of ["anna", "Anna", "bob-pc", "achao", "ACME.EXAMPLE", "10.0.0.7", "00:11:22"]) assert.ok(!all.includes(s), `${s} leaked`);
  assert.deepEqual(of(rs, "endpoint_central.firewall").map((r) => r.resource), ["endpoint_central computer 301 serial SAMPLE01", "endpoint_central computer 302 serial SAMPLE02"]);
});

test("endpoint_central: the scan list follows Links.next; the patch report pages by page and pageLimit", async () => {
  const calls: string[] = [];
  const pcs = Array.from({ length: PATCH_PAGE + 5 }, (_, i) => ({ id: String(1000 + i), tag: `T${i}`, name: `pc-${i}` }));
  const rs = await runWith(C, fakeRest(BASE, fleet(pcs, 60), calls), { opts: { "endpoint-central-max-computers": "1000" } });
  assert.deepEqual(calls.filter((c) => c.startsWith(SCAN)).map((c) => q(c).get("page")), [null, "2"]);
  assert.deepEqual(calls.filter((c) => c.startsWith(HEALTH)).map((c) => q(c).get("page")), ["1", "2"]);
  assert.equal(of(rs, "endpoint_central.os_patches").length, PATCH_PAGE + 5);
  assert.ok(of(rs, "endpoint_central.os_patches").every((r) => r.result === "pass"));
});

test("endpoint_central: per-computer calls are spaced by --endpoint-central-call-gap-ms and capped by --endpoint-central-max-computers", async () => {
  const calls: string[] = [];
  const waits: number[] = [];
  const pcs = Array.from({ length: 5 }, (_, i) => ({ id: String(500 + i), tag: `T${i}`, name: `pc-${i}` }));
  const rs = await runWith(C, fakeRest(BASE, fleet(pcs), calls), { opts: { "endpoint-central-max-computers": "3", "endpoint-central-call-gap-ms": "700" }, waits });
  assert.equal(of(rs, "endpoint_central.agent_installed").length, 3);
  assert.equal(calls.filter((c) => c.startsWith(INV)).length, 6);
  assert.deepEqual(waits, [700, 700, 700, 700, 700]);
  assert.ok(rs.every((r) => r.complete === false), "a capped list is marked incomplete");
});

test("endpoint_central: missing evidence is skipped, never passed; no --endpoint-central-min-os skips os_minimum once", async () => {
  const routes = fleet([{ id: "301", tag: "SAMPLE01", name: "anna-pc", o: { platform: "2", drives: [] } }]);
  routes[SCAN] = () => {
    const c = computer({ id: "301", tag: "SAMPLE01", name: "anna-pc", o: { platform: "2" } });
    c.installation_status = "77"; c.agent_last_contact_time = "-1";
    return ok({ totalPages: 1, messageResponse: [c], Links: { next: null } });
  };
  routes[HEALTH] = ok({ totalPages: 1, messageResponse: [{ ComputerName: "anna-pc", Domain: "ACME", Health: "Unknown" }], Links: { next: null } });
  const rs = await runWith(C, fakeRest(BASE, routes), { opts: { "endpoint-central-min-os": undefined } });
  for (const r of rs) assert.equal(r.result, "skipped", `${r.check}: ${r.detail}`);
  assert.equal(of(rs, "endpoint_central.os_minimum").length, 1);
  assert.match(of(rs, "endpoint_central.os_minimum")[0].detail, /--endpoint-central-min-os/);
});

test("endpoint_central: a Mac with no Windows profile is skipped for firewall; an enabled third-party firewall passes a Windows PC", async () => {
  const routes = fleet([{ id: "301", tag: "S1", name: "a", o: { platform: "2", version: "15.1" } }, { id: "302", tag: "S2", name: "b", o: { profiles: ["Disabled", "Disabled", "Disabled"], external: "Enabled" } }]);
  const rs = await runWith(C, fakeRest(BASE, routes), { opts: { "endpoint-central-min-os": ["macos=15.0", "windows=10.0.26100"] } });
  assert.deepEqual(of(rs, "endpoint_central.firewall").map((r) => r.result), ["skipped", "pass"]);
  assert.match(of(rs, "endpoint_central.firewall")[1].detail, /third-party/);
  assert.equal(of(rs, "endpoint_central.os_minimum")[0].result, "pass");
});

test("endpoint_central: two computers sharing a name and domain are not matched to a patch row", async () => {
  const rs = await runWith(C, fakeRest(BASE, fleet([{ id: "301", tag: "S1", name: "same" }, { id: "302", tag: "S2", name: "same" }])));
  assert.deepEqual(of(rs, "endpoint_central.os_patches").map((r) => r.result), ["skipped", "skipped"]);
  assert.match(of(rs, "endpoint_central.os_patches")[0].detail, /share this computer's name/);
});

test("endpoint_central: a 401 on disk encryption skips that check and stops its calls; a 403 on the patch report skips os_patches only", async () => {
  const calls: string[] = [];
  const routes = strong();
  routes[`${INV}/301/diskEncryptionStatus`] = res(401, { error_code: "UAC_UNAUTHORIZED", error_description: "Unauthorized access" });
  routes[HEALTH] = res(403, { error_code: "UAC_UNAUTHORIZED", error_description: "Unauthorized access" });
  const rs = await runWith(C, fakeRest(BASE, routes, calls));
  assert.ok(of(rs, "endpoint_central.disk_encryption").every((r) => r.result === "skipped" && /HTTP 401/.test(r.detail)));
  assert.equal(calls.filter((c) => c.endsWith("/diskEncryptionStatus")).length, 1);
  assert.deepEqual(of(rs, "endpoint_central.os_patches").map((r) => r.result), ["skipped"]);
  assert.ok(of(rs, "endpoint_central.firewall").every((r) => r.result === "pass"));
});

test("endpoint_central: a rejected token is reported as an error (skipped, HTTP 401), never as a failing computer", async () => {
  const rs = await runWith(C, fakeRest(BASE, { [SCAN]: res(401, { error_code: "UAC_UNAUTHORIZED", error_description: "Unauthorized access" }) }));
  assert.equal(rs.length, 6);
  for (const r of rs) { assert.equal(r.result, "skipped"); assert.match(r.detail, /HTTP 401/); }
});

test("endpoint_central: the real client refreshes at the data centre's Zoho accounts server, then sends GET with Zoho-oauthtoken to cloud hosts only", async () => {
  const seen: { url: string; init: RequestInit }[] = [];
  const f = (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    if (url.includes("/oauth/v2/token")) return new Response(JSON.stringify({ access_token: "1000.access-0123456789", api_domain: "https://www.zohoapis.eu", token_type: "Bearer", expires_in: 3600 }), { status: 200 });
    return new Response(JSON.stringify({ messageResponse: [], echo: "1000.access-0123456789" }), { status: 200 });
  }) as unknown as typeof fetch;
  const env = { ENDPOINT_CENTRAL_URL: "https://endpointcentral.manageengine.eu", ENDPOINT_CENTRAL_CLIENT_ID: "1000.CLIENT", ENDPOINT_CENTRAL_CLIENT_SECRET: "secret-0123456789", ENDPOINT_CENTRAL_REFRESH_TOKEN: "1000.refresh-0123456789" };
  const api = endpointCentralFromEnv(env, f);
  assert.ok(typeof api !== "string");
  const r = await api.get(`${INV}/301/firewall`);
  const tok = new URL(seen[0].url);
  assert.equal(tok.origin, "https://accounts.zoho.eu");
  assert.equal(tok.pathname, "/oauth/v2/token");
  assert.equal(tok.searchParams.get("grant_type"), "refresh_token");
  assert.equal(seen[0].init.method, "POST");
  assert.equal(seen[1].url, `https://endpointcentral.manageengine.eu${INV}/301/firewall`);
  assert.equal(seen[1].init.method, "GET");
  const h = seen[1].init.headers as Record<string, string>;
  assert.equal(h.authorization, "Zoho-oauthtoken 1000.access-0123456789");
  assert.equal(h.accept, "application/firewallInfo.v1+json");
  assert.ok(!JSON.stringify(r.body).includes("1000.access-0123456789"), "the bare access token is cut from an answer");
  // Canada's accounts server can be overridden (the serverinfo endpoint names accounts.zohocloud.ca).
  seen.length = 0;
  const ca = endpointCentralFromEnv({ ...env, ENDPOINT_CENTRAL_URL: "https://endpointcentral.manageengine.ca", ENDPOINT_CENTRAL_ACCOUNTS_URL: "https://accounts.zohocloud.ca" }, f);
  assert.ok(typeof ca !== "string");
  await ca.get(`${SCAN}?toolID=2131`);
  assert.equal(new URL(seen[0].url).origin, "https://accounts.zohocloud.ca");
  assert.equal(new URL(seen[1].url).origin, "https://endpointcentral.manageengine.ca");
  for (const bad of [{ ENDPOINT_CENTRAL_URL: "http://endpointcentral.manageengine.com" }, { ENDPOINT_CENTRAL_URL: "https://ec.acme.example:8383" },
    { ENDPOINT_CENTRAL_ACCOUNTS_URL: "https://accounts.evil.example" }, { ENDPOINT_CENTRAL_REFRESH_TOKEN: "" }]) {
    assert.equal(typeof endpointCentralFromEnv({ ...env, ...bad }), "string", JSON.stringify(bad));
  }
  assert.equal(suffixOf("endpointcentral.manageengine.com.au"), "com.au");
  assert.equal(suffixOf("endpointcentral.manageengine.evil"), undefined);
});

test("endpoint_central: a failed refresh names the accounts host and status, never the secret or refresh token", async () => {
  const f = (async () => new Response(JSON.stringify({ error: "invalid_code" }), { status: 400 })) as unknown as typeof fetch;
  const api = endpointCentralFromEnv({ ENDPOINT_CENTRAL_URL: BASE, ENDPOINT_CENTRAL_CLIENT_ID: "1000.CLIENT", ENDPOINT_CENTRAL_CLIENT_SECRET: "secret-0123456789", ENDPOINT_CENTRAL_REFRESH_TOKEN: "1000.refresh-0123456789" }, f);
  assert.ok(typeof api !== "string");
  const r = await api.get(`${SCAN}?toolID=2131`);
  assert.equal(r.status, 401);
  const text = JSON.stringify(r);
  assert.match(text, /accounts\.zoho\.ca/);
  for (const s of ["secret-0123456789", "1000.refresh-0123456789"]) assert.ok(!text.includes(s), `${s} leaked`);
});
