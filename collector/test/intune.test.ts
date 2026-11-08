// The Intune source against a fake Microsoft Graph v1.0, shaped like the managedDevice and
// deviceCompliancePolicy reference pages. Fixtures are written by hand from the documented field names.
import { test } from "node:test";
import assert from "node:assert/strict";
import { GRAPH_BASE } from "../src/sources/entra.ts";
import { DEVICE_SELECT, REMOTE_ACTION_AUDITS, intune, intuneFromEnv } from "../src/sources/intune.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "./rest_fakes.ts";
import { ok, page, P, D, winPolicy, macPolicy, devices, audits, withAudit, assigned, strong, withPolicy, withDevice, C } from "./fixtures/rest/intune.ts";

contractSuite(C);

test("intune: the device list asks for exactly the fields used, and no name, UPN or email reaches a result", async () => {
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(GRAPH_BASE, strong(), calls));
  const q = new URL(`https://x${calls.find((c) => c.startsWith(D))!}`).searchParams;
  assert.equal(q.get("$select"), DEVICE_SELECT);
  assert.ok(!/deviceName|userPrincipalName|emailAddress|userDisplayName/.test(DEVICE_SELECT));
  const all = JSON.stringify(rs);
  for (const s of ["Anna", "Bob", "acme.example", "MacBook"]) assert.ok(!all.includes(s), `${s} leaked`);
  assert.deepEqual(of(rs, "intune.device_encrypted").map((r) => r.resource), ["intune device d-win-1 serial PF3TEST0002", "intune device d-mac-1 serial C02TEST0001"]);
  // Policies are judged per laptop platform; the iOS policy is not read for assignments.
  assert.deepEqual(of(rs, "intune.policy_min_os").map((r) => r.resource), ["intune tenant tenant-1 Windows", "intune tenant tenant-1 macOS"]);
  assert.ok(!calls.includes(`${P}/pi/assignments`));
});

test("intune: device pages follow @odata.nextLink", async () => {
  const calls: string[] = [];
  const [w, m] = devices();
  const routes = { ...strong(), [D]: (_u: string, n: number) => (n === 1 ? page([w], `${GRAPH_BASE}${D}?$skiptoken=abc`) : page([m])) };
  const rs = await runWith(C, fakeRest(GRAPH_BASE, routes, calls));
  assert.ok(calls.includes(`${D}?$skiptoken=abc`));
  assert.equal(of(rs, "intune.device_last_sync").length, 2);
});

test("intune: the OS floor comes from the assigned policies unless --intune-min-os names one; an unassigned policy does not count", async () => {
  let rs = await runWith(C, fakeRest(GRAPH_BASE, strong()), { opts: { "intune-min-os": ["macOS=15.0"] } });
  const mac = of(rs, "intune.device_os_minimum").find((r) => r.resource.includes("d-mac-1"))!;
  assert.equal(mac.result, "fail"); assert.match(mac.detail, /14\.5 is below the minimum 15\.0 \(--intune-min-os\)/);
  assert.equal(of(rs, "intune.policy_min_os").find((r) => r.resource.endsWith("macOS"))!.result, "fail");   // 14.0 is under the 15.0 asked for
  rs = await runWith(C, fakeRest(GRAPH_BASE, { ...strong(), [`${P}/pm/assignments`]: ok({ value: [] }) }));
  assert.equal(of(rs, "intune.policy_requires_encryption").find((r) => r.resource.endsWith("macOS"))!.result, "fail");
  assert.equal(of(rs, "intune.device_os_minimum").find((r) => r.resource.includes("d-mac-1"))!.result, "skipped");
});

test("intune: missing evidence is skipped, never passed", async () => {
  const ds = devices();
  ds[0].complianceState = "unknown";
  delete ds[1].isEncrypted;
  delete ds[1].lastSyncDateTime;
  const rs = await runWith(C, fakeRest(GRAPH_BASE, { ...strong(), [D]: page(ds), [`${P}/pm/assignments`]: res(403, { error: { code: "Forbidden", message: "no" } }) }));
  const on = (c: string, id: string) => of(rs, `intune.${c}`).find((r) => r.resource.includes(id))!;
  assert.equal(on("device_compliant", "d-win-1").result, "skipped");
  assert.equal(on("device_encrypted", "d-mac-1").result, "skipped");
  assert.equal(on("device_last_sync", "d-mac-1").result, "skipped");
  const macPol = of(rs, "intune.policy_requires_encryption").find((r) => r.resource.endsWith("macOS"))!;
  assert.equal(macPol.result, "skipped"); assert.match(macPol.detail, /HTTP 403/);
  // Only Windows devices: no macOS policy is required.
  const rs2 = await runWith(C, fakeRest(GRAPH_BASE, { ...strong(), [D]: page([devices()[0]]) }));
  assert.deepEqual(of(rs2, "intune.policy_requires_screen_lock").map((r) => r.resource), ["intune tenant tenant-1 Windows"]);
});

test("intune: a token or licence refusal is reported as an error (skipped), never as a failing device", async () => {
  const rs = await runWith(C, fakeRest(GRAPH_BASE, {
    [D]: res(401, { error: { code: "InvalidAuthenticationToken", message: "Access token has expired." } }),
    [P]: res(403, { error: { code: "Forbidden", message: "Application is not authorized to perform this operation." } }),
    [REMOTE_ACTION_AUDITS]: res(403, { error: { code: "Forbidden", message: "Application is not authorized to perform this operation." } }),
  }));
  assert.equal(rs.length, 8);
  for (const r of rs) { assert.equal(r.result, "skipped"); assert.match(r.detail, /HTTP 40[13]/); }
});

test("intune: credentials come from INTUNE_* or fall back to ENTRA_*; the token request is the only POST", async () => {
  assert.equal(typeof intuneFromEnv({}), "string");
  const seen: { url: string; init: RequestInit }[] = [];
  const f = (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    return url.includes("login.microsoftonline.com") ? new Response(JSON.stringify({ access_token: "at-0123456789", expires_in: 3600 }), { status: 200 }) : new Response("{\"value\":[]}", { status: 200 });
  }) as unknown as typeof fetch;
  const api = intuneFromEnv({ ENTRA_TENANT_ID: "t1", ENTRA_CLIENT_ID: "c1", ENTRA_CLIENT_SECRET: "s-0123456789" }, f);
  assert.ok(typeof api !== "string");
  await api.get(D);
  assert.match(seen[0].url, /login\.microsoftonline\.com\/t1\/oauth2\/v2\.0\/token/);
  assert.equal(seen[0].init.method, "POST");
  assert.equal(seen[1].url, `${GRAPH_BASE}${D}`);
  assert.equal(seen[1].init.method, "GET");
  assert.equal((seen[1].init.headers as Record<string, string>).authorization, "Bearer at-0123456789");
});

test("intune.device_wipe_recorded: one result per device with a wipe, retire or delete in the period; names stay out", async () => {
  const rs = await runWith(C, fakeRest(GRAPH_BASE, strong()));
  const w = of(rs, "intune.device_wipe_recorded");
  assert.deepEqual(w.map((r) => [r.resource, r.result]), [["intune device d-old-1", "pass"], ["intune device d-old-2", "pass"]]);
  assert.match(w[0].detail, /factoryReset done/);
  const all = JSON.stringify(w);
  for (const s of ["Carol", "carol@", "it.admin"]) assert.ok(!all.includes(s), `${s} leaked`);
  // A failed wipe fails; a recent pending one waits; an old pending one fails.
  const one = async (state: string, age: number) => of(await runWith(C, fakeRest(GRAPH_BASE, { ...strong(),
    [REMOTE_ACTION_AUDITS]: page([{ managedDeviceId: "d-x", action: "factoryReset", actionState: state, requestDateTime: daysAgo(age) }]) })), "intune.device_wipe_recorded")[0].result;
  assert.equal(await one("failed", 2), "fail");
  assert.equal(await one("pending", 2), "skipped");
  assert.equal(await one("pending", 30), "fail");
  // Nothing in the period: skipped, never pass.
  const none = of(await runWith(C, fakeRest(GRAPH_BASE, { ...strong(), [REMOTE_ACTION_AUDITS]: page([]) })), "intune.device_wipe_recorded");
  assert.deepEqual(none.map((r) => r.result), ["skipped"]);
});
