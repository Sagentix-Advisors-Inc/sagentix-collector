// Fixtures for the intune source, shared by test/intune.test.ts and the end-to-end run (test/e2e.test.ts).
import { GRAPH_BASE } from "../../../src/sources/entra.ts";
import { DEVICE_SELECT, REMOTE_ACTION_AUDITS, intune, intuneFromEnv } from "../../../src/sources/intune.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "../../rest_fakes.ts";

export const ok = (b: unknown) => res(200, b);
export const page = (value: unknown[], next?: string) => ok({ value, ...(next ? { "@odata.nextLink": next } : {}) });
export const P = "/deviceManagement/deviceCompliancePolicies";
export const D = "/deviceManagement/managedDevices";

export function winPolicy(): Record<string, unknown> {
  return { "@odata.type": "#microsoft.graph.windows10CompliancePolicy", id: "pw", displayName: "Windows laptops", version: 3,
    passwordRequired: true, passwordMinutesOfInactivityBeforeLock: 10, osMinimumVersion: "10.0.22631", bitLockerEnabled: true, storageRequireEncryption: true };
}
export function macPolicy(): Record<string, unknown> {
  return { "@odata.type": "#microsoft.graph.macOSCompliancePolicy", id: "pm", displayName: "Mac laptops", version: 2,
    passwordRequired: true, passwordMinutesOfInactivityBeforeLock: 5, osMinimumVersion: "14.0", storageRequireEncryption: true, firewallEnabled: true };
}
/** Graph would not return the user fields under $select; they are here to prove they are never used. */
export function devices(): Record<string, unknown>[] {
  return [
    { id: "d-win-1", serialNumber: "PF3TEST0002", operatingSystem: "Windows", osVersion: "10.0.22631.4602", complianceState: "compliant", isEncrypted: true, lastSyncDateTime: daysAgo(1),
      deviceName: "Bob Smith's PC", userPrincipalName: "bob.smith@acme.example", emailAddress: "bob.smith@acme.example", userDisplayName: "Bob Smith" },
    { id: "d-mac-1", serialNumber: "C02TEST0001", operatingSystem: "macOS", osVersion: "14.5", complianceState: "compliant", isEncrypted: true, lastSyncDateTime: daysAgo(2),
      deviceName: "Anna's MacBook Pro", userPrincipalName: "anna.chao@acme.example", userDisplayName: "Anna Chao" },
  ];
}
/** Remote action audit rows (Graph beta), with the person fields the source must never read into a result. */
export function audits(): Record<string, unknown>[] {
  return [
    { id: "ra1", managedDeviceId: "d-old-1", action: "factoryReset", actionState: "done", requestDateTime: daysAgo(20), deviceDisplayName: "Carol's Surface", userName: "carol@acme.example",
      initiatedByUserPrincipalName: "it.admin@acme.example", deviceOwnerUserPrincipalName: "carol@acme.example" },
    { id: "ra2", managedDeviceId: "d-old-2", action: "removeCompanyData", actionState: "done", requestDateTime: daysAgo(40) },
    { id: "ra3", managedDeviceId: "d-old-2", action: "delete", actionState: "done", requestDateTime: daysAgo(39) },
    { id: "ra4", managedDeviceId: "d-win-1", action: "syncDevice", actionState: "done", requestDateTime: daysAgo(1) },
    { id: "ra5", managedDeviceId: "d-ancient", action: "delete", actionState: "done", requestDateTime: daysAgo(500) },
  ];
}
export const withAudit = (change: (a: Record<string, unknown>[]) => void): Routes => { const a = audits(); change(a); return { [REMOTE_ACTION_AUDITS]: page(a) }; };
export const assigned = ok({ value: [{ id: "a1", target: { "@odata.type": "#microsoft.graph.allDevicesAssignmentTarget" } }] });

export function strong(): Routes {
  return {
    [D]: page(devices()),
    [P]: page([winPolicy(), macPolicy(), { "@odata.type": "#microsoft.graph.iosCompliancePolicy", id: "pi", displayName: "Phones" }]),
    [`${P}/pw/assignments`]: assigned,
    [`${P}/pm/assignments`]: assigned,
    [REMOTE_ACTION_AUDITS]: page(audits()),
  };
}
export const withPolicy = (which: "pw" | "pm", change: (p: Record<string, unknown>) => void): Routes => {
  const w = winPolicy(), m = macPolicy();
  change(which === "pw" ? w : m);
  return { [P]: page([w, m]) };
};
export const withDevice = (i: number, change: (d: Record<string, unknown>) => void): Routes => {
  const ds = devices();
  change(ds[i]);
  return { [D]: page(ds) };
};

export const C: Contract = {
  source: intune, clientKey: "intune", base: GRAPH_BASE, prefix: "intune", strong,
  env: { INTUNE_TENANT_ID: "tenant-1", INTUNE_CLIENT_ID: "app-1", INTUNE_CLIENT_SECRET: "x" },
  rateLimited: { path: D, check: "device_encrypted" },
  fails: {
    policy_requires_encryption: withPolicy("pw", (p) => { p.storageRequireEncryption = false; p.bitLockerEnabled = false; }),
    policy_requires_screen_lock: withPolicy("pm", (p) => { p.passwordMinutesOfInactivityBeforeLock = 30; }),
    policy_min_os: withPolicy("pw", (p) => { delete p.osMinimumVersion; }),
    device_compliant: withDevice(0, (d) => { d.complianceState = "noncompliant"; }),
    device_encrypted: withDevice(1, (d) => { d.isEncrypted = false; }),
    device_os_minimum: withDevice(1, (d) => { d.osVersion = "13.6.1"; }),
    device_last_sync: withDevice(0, (d) => { d.lastSyncDateTime = daysAgo(40); }),
    device_wipe_recorded: withAudit((a) => { a.push({ id: "ra6", managedDeviceId: "d-lost", action: "delete", actionState: "done", requestDateTime: daysAgo(3) }); }),
  },
};
