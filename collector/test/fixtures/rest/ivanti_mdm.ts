// Fixtures for the ivanti_mdm source, shared by test/ivanti_mdm.test.ts and the end-to-end run (test/e2e.test.ts).
import { PAGE, detailPath, ivanti_mdm, ivantiMdmFromEnv } from "../../../src/sources/ivanti_mdm.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Route, type Routes } from "../../rest_fakes.ts";

export const BASE = "https://mdm.example.com/api/v1";
export const DEV = "/device";
export const META = "/metadata/tenant";
export const SPACE = 23071;
export const ok = (result: unknown) => res(200, { errors: null, result });
export const q = (url: string) => new URL(`https://x${url}`).searchParams;
export const ms = (iso: string) => Date.parse(iso);

export interface Over { compliant?: boolean; version?: string; checkin?: string; passcode?: boolean; fde?: boolean; firewall?: boolean; sip?: boolean;
  state?: string; bitlocker?: string | null }
export interface Dev { id: number; serial: string; plat: string; o?: Over }

export function row(d: Dev): Record<string, unknown> {
  const o = d.o ?? {};
  return {
    id: d.id, guid: `guid-${d.id}`, deviceName: "Anna's MacBook Pro", displayName: "Anna Chao", firstName: "Anna", lastName: "Chao",
    emailAddress: "anna@acme.example", uid: "achao", phoneNumber: "+15555550100", imei: "490154203237518",
    platformType: d.plat, platformVersion: o.version ?? (d.plat === "IOS" ? "18.1" : "15.1"),
    lastCheckin: ms(o.checkin ?? daysAgo(1)), registrationState: o.state ?? "ACTIVE", serialNumber: d.serial,
    complianceState: o.compliant ?? true,
    passcodeCompliant: d.plat === "IOS" ? (o.passcode ?? true) : null,
    passcodeCompliantWithProfiles: d.plat === "IOS" || d.plat === "ANDROID" ? (o.passcode ?? true) : null,
    bitLockerEncryptionStatus: o.bitlocker ?? null, dmPartitionId: SPACE, dmPartitionName: "Default Space",
  };
}
export function detail(d: Dev): Record<string, unknown> {
  const o = d.o ?? {};
  return { ...row(d), lastCheckin: daysAgo(1), osxFdeEnabled: o.fde ?? true, osxSystemIntegrityProtectionEnabled: o.sip ?? true,
    osxFirewallSettings: { allowSigned: true, allowSignedApp: true, applicationsList: [], blockAllIncoming: false, enableLogging: true, firewallEnabled: o.firewall ?? true, stealthMode: true } };
}

/** Routes for a device space: tenant metadata, the id-sorted search paged with searchAfterValues, and each Mac's details. */
export function space(devs: Dev[], pageSize = PAGE): Routes {
  const sorted = [...devs].sort((a, b) => a.id - b.id);
  const search: Route = (url) => {
    const after = q(url).get("searchAfterValues[0]");
    const rest = after === null ? sorted : sorted.filter((d) => d.id > Number(after));
    return ok({ totalCount: sorted.length, searchResults: rest.slice(0, pageSize).map(row) });
  };
  const r: Routes = { [META]: ok({ defaultDmPartitionId: SPACE, defaultCmPartitionId: 1 }), [DEV]: search };
  for (const d of devs) r[detailPath(String(d.id))] = ok(detail(d));
  return r;
}
export const MAC = { id: 101, serial: "C02TEST0001", plat: "OSX" }, IPHONE = { id: 102, serial: "F2LTEST0002", plat: "IOS" };
export const strong = () => space([MAC, IPHONE]);
export const weakMac = (o: Over) => space([{ ...MAC, o }, IPHONE]);
export const weakPhone = (o: Over) => space([MAC, { ...IPHONE, o }]);

export const C: Contract = {
  source: ivanti_mdm, clientKey: "ivanti_mdm", base: BASE, prefix: "ivanti_mdm", strong,
  opts: { "ivanti-mdm-min-os": ["osx=14.0", "ios=17.0"] },
  env: { IVANTI_MDM_URL: "https://mdm.example.com", IVANTI_MDM_USERNAME: "collector@acme.example", IVANTI_MDM_PASSWORD: "x" },
  rateLimited: { path: DEV, check: "device_compliant" },
  fails: {
    device_compliant: weakPhone({ compliant: false }),
    disk_encryption: weakMac({ fde: false }),
    os_minimum: weakPhone({ version: "16.7.10" }),
    last_checkin: weakMac({ checkin: daysAgo(30) }),
    passcode_compliant: weakPhone({ passcode: false }),
    firewall: weakMac({ firewall: false }),
    system_integrity: weakMac({ sip: false }),
  },
};
