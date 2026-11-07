// The Jamf Pro source against a fake Jamf Pro API shaped like the computers-inventory reference.
// Fixtures are written by hand from the documented field names.
import { test } from "node:test";
import assert from "node:assert/strict";
import { PAGE, inventoryPath, jamf, jamfFromEnv } from "../src/sources/jamf.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "./rest_fakes.ts";

const BASE = "https://acme.jamfcloud.com/api";
const INV = "/v4/computers-inventory";
const CMD = "/v2/mdm/commands";
const ok = (b: unknown) => res(200, b);

function computer(id: string, serial: string, over: { state?: string; version?: string; report?: string; managed?: boolean } = {}): Record<string, unknown> {
  return {
    id, udid: `UDID-${id}`,
    general: { name: "Anna's MacBook Air", managementId: `mgmt-${id}`, reportDate: over.report ?? daysAgo(1), lastContact: daysAgo(1), remoteManagement: { managed: over.managed ?? true },
      lastLoggedInUsernameBinary: "achao" },
    diskEncryption: { fileVault2Enabled: true, fileVault2EnabledUserNames: ["achao"],
      bootPartitionEncryptionDetails: { partitionName: "Macintosh HD (Boot Partition)", partitionFileVault2State: over.state ?? "ENCRYPTED", partitionFileVault2Percent: 100 } },
    operatingSystem: { name: "macOS", version: over.version ?? "15.1", build: "24B83" },
    hardware: { serialNumber: serial, model: "MacBook Air (M2, 2022)" },
  };
}
const inv = (results: unknown[], total = results.length) => ok({ totalCount: total, results });
/** One erase per row; the username and device name are there to prove they never reach a result. */
const erase = (mgmt: string, state: string, sent: string) => ({ uuid: `u-${mgmt}`, dateSent: sent, dateCompleted: state === "ACKNOWLEDGED" ? sent : null,
  client: { managementId: mgmt, clientType: "COMPUTER" }, commandState: state, commandType: "ERASE_DEVICE", username: "it.admin", deviceName: "Anna's MacBook Air" });
const cmds = (rows: unknown[]) => ok({ totalCount: rows.length, results: rows });
const strong = (): Routes => ({ [INV]: inv([computer("1", "C02TEST0001"), computer("2", "C02TEST0002")]),
  [CMD]: cmds([erase("mgmt-2", "ACKNOWLEDGED", daysAgo(10)), erase("mgmt-gone", "ACKNOWLEDGED", daysAgo(60))]) });
const withComputer = (over: Parameters<typeof computer>[2]): Routes => ({ [INV]: inv([computer("1", "C02TEST0001"), computer("2", "C02TEST0002", over)]) });

const C: Contract = {
  source: jamf, clientKey: "jamf", base: BASE, prefix: "jamf", strong,
  opts: { "jamf-min-os": "14.0" },
  env: { JAMF_URL: "https://acme.jamfcloud.com", JAMF_CLIENT_ID: "client-1", JAMF_CLIENT_SECRET: "x" },
  rateLimited: { path: INV, check: "filevault" },
  fails: {
    filevault: withComputer({ state: "UNENCRYPTED" }),
    os_minimum: withComputer({ version: "13.6.9" }),
    last_inventory: withComputer({ report: daysAgo(30) }),
    managed: withComputer({ managed: false }),
    device_wipe_recorded: { [CMD]: cmds([erase("mgmt-3", "ERROR", daysAgo(2))]) },
  },
};

contractSuite(C);

test("jamf: asks only for the GENERAL, DISK_ENCRYPTION, OPERATING_SYSTEM and HARDWARE sections; no computer name or username reaches a result", async () => {
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(BASE, strong(), calls));
  const q = new URL(`https://x${calls[0]}`).searchParams;
  assert.deepEqual(q.getAll("section"), ["GENERAL", "DISK_ENCRYPTION", "OPERATING_SYSTEM", "HARDWARE"]);
  const all = JSON.stringify(rs);
  for (const s of ["Anna", "achao", "MacBook"]) assert.ok(!all.includes(s), `${s} leaked`);
  assert.deepEqual(of(rs, "jamf.filevault").map((r) => r.resource), ["jamf computer 1 serial C02TEST0001", "jamf computer 2 serial C02TEST0002"]);
});

test("jamf: pages follow totalCount", async () => {
  const calls: string[] = [];
  const first = Array.from({ length: PAGE }, (_, i) => computer(String(i + 1), `SN${i + 1}`));
  const routes: Routes = { [INV]: (url) => (new URL(`https://x${url}`).searchParams.get("page") === "0" ? inv(first, PAGE + 1) : inv([computer("999", "SN999")], PAGE + 1)) };
  const rs = await runWith(C, fakeRest(BASE, routes, calls));
  const inventory = calls.filter((c) => c.startsWith(INV));
  assert.equal(inventory.length, 2);
  assert.equal(new URL(`https://x${inventory[1]}`).searchParams.get("page"), "1");
  assert.equal(of(rs, "jamf.managed").length, PAGE + 1);
});

test("jamf: a server without v4 answers on the next older inventory version", async () => {
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(BASE, { "/v3/computers-inventory": inv([computer("1", "C02TEST0001")]), [CMD]: cmds([erase("mgmt-1", "ACKNOWLEDGED", daysAgo(3))]) }, calls));
  assert.deepEqual(calls.map((c) => c.split("?")[0]), ["/v4/computers-inventory", "/v3/computers-inventory", CMD]);
  assert.equal(calls[1], inventoryPath("v3", 0));
  assert.ok(rs.every((r) => r.result === "pass"));
  assert.match(of(rs, "jamf.filevault")[0].detail, /Jamf Pro API v3/);
});

test("jamf: missing evidence is skipped, never passed; no --jamf-min-os skips os_minimum once", async () => {
  const c = computer("1", "C02TEST0001", { state: "UNKNOWN" });
  delete (c.diskEncryption as Record<string, unknown>).fileVault2Enabled;
  delete (c.general as Record<string, unknown>).reportDate;
  delete (c.general as Record<string, unknown>).remoteManagement;
  const rs = await runWith(C, fakeRest(BASE, { [INV]: inv([c]) }), { opts: { "jamf-min-os": undefined } });
  for (const r of rs) assert.equal(r.result, "skipped", `${r.check}: ${r.detail}`);
  assert.equal(of(rs, "jamf.os_minimum").length, 1);
  assert.match(of(rs, "jamf.os_minimum")[0].detail, /--jamf-min-os/);
  // fileVault2Enabled answers when the partition state is unknown.
  const c2 = computer("1", "C02TEST0001", { state: "UNKNOWN" });
  assert.equal(of(await runWith(C, fakeRest(BASE, { [INV]: inv([c2]) })), "jamf.filevault")[0].result, "pass");
});

test("jamf: a rejected token is reported as an error (skipped, HTTP 401), never as a failing Mac", async () => {
  const denied = res(401, { httpStatus: 401, errors: [{ code: "INVALID_TOKEN", description: "Unauthorized" }] });
  const rs = await runWith(C, fakeRest(BASE, { [INV]: denied, [CMD]: denied }));
  assert.equal(rs.length, 5);
  for (const r of rs) { assert.equal(r.result, "skipped"); assert.match(r.detail, /HTTP 401/); }
});

test("jamf: the real client gets a client-credentials token (falling back to /api/oauth/token), then sends GET with Bearer over https only", async () => {
  const seen: { url: string; init: RequestInit }[] = [];
  const f = (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    if (url.endsWith("/api/v1/oauth/token")) return new Response("{}", { status: 404 });
    if (url.endsWith("/api/oauth/token")) return new Response(JSON.stringify({ access_token: "jat-0123456789", token_type: "Bearer", expires_in: 60 }), { status: 200 });
    return new Response("{\"totalCount\":0,\"results\":[]}", { status: 200 });
  }) as unknown as typeof fetch;
  const api = jamfFromEnv({ JAMF_URL: "https://acme.jamfcloud.com", JAMF_CLIENT_ID: "client-1", JAMF_CLIENT_SECRET: "secret-0123456789" }, f);
  assert.ok(typeof api !== "string");
  await api.get(INV);
  assert.equal(seen[0].init.method, "POST");
  assert.match(String(seen[0].init.body), /grant_type=client_credentials/);
  assert.equal(seen[1].url, "https://acme.jamfcloud.com/api/oauth/token");
  assert.equal(seen[2].url, `${BASE}${INV}`);
  assert.equal(seen[2].init.method, "GET");
  assert.equal((seen[2].init.headers as Record<string, string>).authorization, "Bearer jat-0123456789");
  assert.equal(typeof jamfFromEnv({ JAMF_URL: "http://acme.jamfcloud.com", JAMF_CLIENT_ID: "a", JAMF_CLIENT_SECRET: "b" }), "string");
});

test("jamf.device_wipe_recorded: erases of the period, named by computer id and serial when the inventory has the management id", async () => {
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(BASE, strong(), calls));
  const w = of(rs, "jamf.device_wipe_recorded");
  assert.deepEqual(w.map((r) => [r.resource, r.result]), [["jamf computer 2 serial C02TEST0002", "pass"], ["jamf computer management id mgmt-gone", "pass"]]);
  const q = new URL(`https://x${calls.find((c) => c.startsWith(CMD))!}`).searchParams;
  assert.match(q.get("filter")!, /^command==ERASE_DEVICE;dateSent=ge=\d{4}-/);
  assert.ok(!JSON.stringify(w).includes("it.admin") && !JSON.stringify(w).includes("Anna"));
  // A pending erase older than the grace days fails; none in the period is skipped, never a pass.
  assert.equal(of(await runWith(C, fakeRest(BASE, { ...strong(), [CMD]: cmds([erase("mgmt-1", "PENDING", daysAgo(20))]) })), "jamf.device_wipe_recorded")[0].result, "fail");
  assert.deepEqual(of(await runWith(C, fakeRest(BASE, { ...strong(), [CMD]: cmds([]) })), "jamf.device_wipe_recorded").map((r) => r.result), ["skipped"]);
});
