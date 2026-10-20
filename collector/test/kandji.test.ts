// The Iru Endpoint Management (formerly Kandji) source against a fake API shaped like the List Devices, Get Device
// Status and Prism references. Fixtures are written by hand from the documented field names.
import { test } from "node:test";
import assert from "node:assert/strict";
import { PAGE, kandji, kandjiFromEnv } from "../src/sources/kandji.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Route, type Routes } from "./rest_fakes.ts";

const BASE = "https://acme.api.kandji.io/api";
const DEV = "/v1/devices";
const ok = (b: unknown) => res(200, b);
const q = (url: string) => new URL(`https://x${url}`).searchParams;

interface Over { version?: string; checkin?: string; mdm?: boolean; filevault?: boolean; firewall?: boolean; gatekeeper?: boolean; sip?: boolean;
  item?: string; param?: string }

function mac(id: string, serial: string, o: Over = {}): Record<string, unknown> {
  return {
    device_id: id, device_name: "Anna's MacBook Air", model: "MacBook Air (M2, 2022)", serial_number: serial, platform: "Mac",
    os_version: o.version ?? "15.1", last_check_in: o.checkin ?? daysAgo(1),
    user: { email: "anna@acme.example", name: "Anna Chao", id: "u-1", is_archived: false },
    blueprint_id: "bp-1", blueprint_name: "All Staff", mdm_enabled: o.mdm ?? true, agent_installed: true, is_missing: false, is_removed: false,
  };
}
const prismRow = (id: string, serial: string, fields: Record<string, unknown>) => ({
  device_id: id, device__name: "Anna's MacBook Air", device__family: "Mac", device__user_name: "Anna Chao", device__user_email: "anna@acme.example",
  serial_number: serial, ...fields,
});
const status = (o: Over = {}) => ok({
  device_id: "x",
  library_items: [
    { id: 1, item_id: "li-1", name: "FileVault", status: o.item ?? "PASS", type: "filevault", last_audit_log: "user achao", log: "user achao" },
    { id: 2, item_id: "li-2", name: "Zoom", status: "PENDING", type: "custom-app", last_audit_log: null, log: "" },
  ],
  parameters: [{ status: o.param ?? "PASS", item_id: "p-1", name: "Disable the \"root\" user", category: "User Accounts & Authentication", subcategory: "User Accounts" }],
});

/** Routes for a fleet of Macs: the device list (filtered by filevault_enabled when asked), Prism categories, statuses. */
function fleet(macs: { id: string; serial: string; o?: Over }[]): Routes {
  const list: Route = (url) => {
    const fv = q(url).get("filevault_enabled"), off = Number(q(url).get("offset"));
    const rows = macs.filter((m) => fv === null || String(m.o?.filevault ?? true) === fv).map((m) => mac(m.id, m.serial, m.o));
    return ok(rows.slice(off, off + PAGE));
  };
  const prism = (field: keyof Over, key: string): Route => () => ok({ offset: null, limit: PAGE, total: macs.length, cursor: null,
    data: macs.map((m) => prismRow(m.id, m.serial, { [key]: m.o?.[field] ?? true })) });
  const r: Routes = {
    [DEV]: list,
    "/v1/prism/application_firewall": prism("firewall", "status"),
    "/v1/prism/gatekeeper_and_xprotect": prism("gatekeeper", "gatekeeper_status"),
    "/v1/prism/startup_settings": prism("sip", "sip"),
  };
  for (const m of macs) r[`${DEV}/${m.id}/status`] = status(m.o);
  return r;
}
const strong = () => fleet([{ id: "d-1", serial: "C02TEST0001" }, { id: "d-2", serial: "C02TEST0002" }]);
const weak = (o: Over) => fleet([{ id: "d-1", serial: "C02TEST0001" }, { id: "d-2", serial: "C02TEST0002", o }]);

const C: Contract = {
  source: kandji, clientKey: "kandji", base: BASE, prefix: "kandji", strong,
  opts: { "kandji-min-os": "14.0" },
  env: { KANDJI_API_URL: "https://acme.api.kandji.io", KANDJI_API_TOKEN: "x" },
  rateLimited: { path: DEV, check: "managed" },
  fails: {
    filevault: weak({ filevault: false }),
    os_minimum: weak({ version: "13.6.9" }),
    last_checkin: weak({ checkin: daysAgo(30) }),
    managed: weak({ mdm: false }),
    library_items: weak({ item: "ERROR" }),
    parameters: weak({ param: "WARNING" }),
    firewall: weak({ firewall: false }),
    gatekeeper: weak({ gatekeeper: false }),
    sip: weak({ sip: false }),
  },
};

contractSuite(C);

test("kandji: GET only Macs and the five documented endpoints; no device name, user or log reaches a result", async () => {
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(BASE, strong(), calls));
  assert.ok(calls.filter((c) => c.startsWith(`${DEV}?`)).every((c) => q(c).get("platform") === "Mac" && q(c).get("limit") === String(PAGE)));
  assert.deepEqual([...new Set(calls.map((c) => c.split("?")[0].replace(/d-\d/, "{id}")))].sort(),
    [DEV, `${DEV}/{id}/status`, "/v1/prism/application_firewall", "/v1/prism/gatekeeper_and_xprotect", "/v1/prism/startup_settings"].sort());
  assert.deepEqual(calls.filter((c) => c.startsWith(`${DEV}?`)).map((c) => q(c).get("filevault_enabled")), [null, "true", "false"]);
  const all = JSON.stringify(rs);
  for (const s of ["Anna", "anna@", "achao", "MacBook"]) assert.ok(!all.includes(s), `${s} leaked`);
  assert.deepEqual(of(rs, "kandji.sip").map((r) => r.resource), ["kandji device d-1 serial C02TEST0001", "kandji device d-2 serial C02TEST0002"]);
});

test("kandji: List Devices pages by offset; Prism follows its cursor until null", async () => {
  const calls: string[] = [];
  const macs = Array.from({ length: PAGE + 1 }, (_, i) => ({ id: `d-${i + 1}`, serial: `SN${i + 1}` }));
  const routes = fleet(macs);
  routes["/v1/prism/startup_settings"] = (url) => {
    const cur = q(url).get("cursor");
    const half = cur === "" ? macs.slice(0, PAGE) : macs.slice(PAGE);
    return ok({ limit: PAGE, data: half.map((m) => prismRow(m.id, m.serial, { sip: true })), cursor: cur === "" ? "MjAyNC0w+/==" : null });
  };
  const rs = await runWith(C, fakeRest(BASE, routes, calls));
  assert.deepEqual(calls.filter((c) => c.startsWith(`${DEV}?`) && !q(c).has("filevault_enabled")).map((c) => q(c).get("offset")), ["0", String(PAGE)]);
  assert.deepEqual(calls.filter((c) => c.startsWith("/v1/prism/startup_settings")).map((c) => q(c).get("cursor")), ["", "MjAyNC0w+/=="]);
  assert.equal(of(rs, "kandji.managed").length, PAGE + 1);
  assert.ok(of(rs, "kandji.sip").every((r) => r.result === "pass"));
});

test("kandji: --kandji-max-devices caps the Macs read and the status calls", async () => {
  const calls: string[] = [];
  const macs = Array.from({ length: 5 }, (_, i) => ({ id: `d-${i + 1}`, serial: `SN${i + 1}` }));
  const rs = await runWith(C, fakeRest(BASE, fleet(macs), calls), { opts: { "kandji-max-devices": "2" } });
  assert.equal(of(rs, "kandji.managed").length, 2);
  assert.equal(calls.filter((c) => c.endsWith("/status")).length, 2);
});

test("kandji: missing evidence is skipped, never passed; no --kandji-min-os skips os_minimum once", async () => {
  const routes = fleet([{ id: "d-1", serial: "C02TEST0001" }]);
  routes[DEV] = (url) => {
    const fv = q(url).get("filevault_enabled");
    if (fv !== null) return ok([]);
    const m = mac("d-1", "C02TEST0001");
    delete m.last_check_in; delete m.mdm_enabled;
    return ok([m]);
  };
  routes["/v1/prism/application_firewall"] = ok({ data: [prismRow("d-1", "C02TEST0001", { status: null })], cursor: null });
  routes["/v1/prism/gatekeeper_and_xprotect"] = ok({ data: [], cursor: null });
  routes["/v1/prism/startup_settings"] = ok({ data: [prismRow("d-1", "C02TEST0001", {})], cursor: null });
  routes[`${DEV}/d-1/status`] = ok({ device_id: "d-1", library_items: [{ name: "Zoom", status: "PENDING" }, { name: "Chrome", status: "EXCLUDED" }], parameters: [{ name: "x", status: "INCOMPATIBLE" }] });
  const rs = await runWith(C, fakeRest(BASE, routes), { opts: { "kandji-min-os": undefined } });
  for (const r of rs) assert.equal(r.result, "skipped", `${r.check}: ${r.detail}`);
  assert.equal(of(rs, "kandji.os_minimum").length, 1);
  assert.match(of(rs, "kandji.os_minimum")[0].detail, /--kandji-min-os/);
  assert.match(of(rs, "kandji.gatekeeper")[0].detail, /no Prism row/);
});

test("kandji: a failing library item names the item and its status, never its log", async () => {
  const rs = await runWith(C, fakeRest(BASE, weak({ item: "failed" })));
  const f = of(rs, "kandji.library_items").find((r) => r.result === "fail")!;
  assert.match(f.detail, /"FileVault" failed/);
  assert.ok(!f.detail.includes("achao"));
});

test("kandji: a token without one Prism permission skips that check only; a 403 on device status skips once, then stops calling", async () => {
  const calls: string[] = [];
  const routes = strong();
  routes["/v1/prism/startup_settings"] = res(403, { detail: "You do not have permission to perform this action." });
  routes[`${DEV}/d-1/status`] = res(403, { detail: "You do not have permission to perform this action." });
  const rs = await runWith(C, fakeRest(BASE, routes, calls));
  assert.deepEqual(of(rs, "kandji.sip").map((r) => r.result), ["skipped"]);
  assert.match(of(rs, "kandji.sip")[0].detail, /HTTP 403/);
  assert.ok(of(rs, "kandji.firewall").every((r) => r.result === "pass"));
  assert.ok(of(rs, "kandji.library_items").every((r) => r.result === "skipped" && /HTTP 403/.test(r.detail)));
  assert.equal(calls.filter((c) => c.endsWith("/status")).length, 1);
});

test("kandji: a rejected token is reported as an error (skipped, HTTP 401), never as a failing Mac", async () => {
  const rs = await runWith(C, fakeRest(BASE, { [DEV]: res(401, { detail: "Invalid token." }) }));
  assert.equal(rs.length, 9);
  for (const r of rs) { assert.equal(r.result, "skipped"); assert.match(r.detail, /HTTP 401/); }
});

test("kandji: the real client sends GET with the Bearer token to the tenant API URL, over https only", async () => {
  const seen: { url: string; init: RequestInit }[] = [];
  const f = (async (url: string, init: RequestInit) => { seen.push({ url, init }); return new Response("[]", { status: 200 }); }) as unknown as typeof fetch;
  const api = kandjiFromEnv({ KANDJI_API_URL: "https://acme.api.eu.kandji.io", KANDJI_API_TOKEN: "tok-0123456789" }, f);
  assert.ok(typeof api !== "string");
  await api.get("/v1/devices?platform=Mac");
  assert.equal(seen[0].url, "https://acme.api.eu.kandji.io/api/v1/devices?platform=Mac");
  assert.equal(seen[0].init.method, "GET");
  assert.equal((seen[0].init.headers as Record<string, string>).authorization, "Bearer tok-0123456789");
  assert.equal(typeof kandjiFromEnv({ KANDJI_API_URL: "http://acme.api.kandji.io", KANDJI_API_TOKEN: "a" }), "string");
  assert.equal(typeof kandjiFromEnv({ KANDJI_API_URL: "https://acme.api.kandji.io" }), "string");
});
