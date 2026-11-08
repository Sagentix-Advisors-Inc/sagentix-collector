// Fixtures for the ninjaone source, shared by test/ninjaone.test.ts and the end-to-end run (test/e2e.test.ts).
import { PAGE, contactDate, ninjaone, ninjaoneFromEnv } from "../../../src/sources/ninjaone.ts";
import { contractSuite, fakeRest, of, res, runWith, type Contract, type Route, type Routes } from "../../rest_fakes.ts";
import { NOW } from "../../helpers.ts";

export const BASE = "https://ca.ninjarmm.com";
export const DEV = "/v2/devices";
export const Q = "/v2/queries";
export const ok = (b: unknown) => res(200, b);
export const q = (url: string) => new URL(`https://x${url}`).searchParams;
export const secsAgo = (days: number) => Math.floor((NOW.getTime() - days * 86_400_000) / 1000);

export interface Over { nodeClass?: string; approval?: string; contact?: number; conv?: string; prot?: string; build?: string; osName?: string;
  failed?: number; pending?: number }
export interface Dev { id: number; serial: string; o?: Over }

export function node(d: Dev): Record<string, unknown> {
  return {
    id: d.id, uid: `uid-${d.id}`, organizationId: 1, locationId: 1, nodeClass: d.o?.nodeClass ?? "WINDOWS_WORKSTATION",
    approvalStatus: d.o?.approval ?? "APPROVED", offline: false, displayName: "Anna's ThinkPad", systemName: "ANNA-T14",
    dnsName: "anna-t14.acme.example", netbiosName: "ANNA-T14", lastContact: d.o?.contact ?? secsAgo(1), lastUpdate: secsAgo(1),
    userData: { owner: "anna@acme.example" }, tags: ["Anna Chao"],
  };
}

/** Routes for a set of devices; each query report is answered in one page plus an empty one behind a cursor. */
export function fleet(devs: Dev[]): Routes {
  const list: Route = (url) => {
    const after = q(url).get("after");
    const rows = devs.filter((d) => after === null || d.id > Number(after)).slice(0, Number(q(url).get("pageSize")));
    return ok(rows.map(node));
  };
  const reportOf = (rows: () => unknown[]): Route => (url) =>
    q(url).get("cursor") ? ok({ cursor: { name: "c-1", offset: 1, count: 0, expires: 0 }, results: [] })
      : ok({ cursor: { name: "c-1", offset: 0, count: devs.length, expires: 0 }, results: rows() });
  return {
    [DEV]: list,
    [`${Q}/computer-systems`]: reportOf(() => devs.map((d) => ({ deviceId: d.id, name: "ANNA-T14", serialNumber: d.serial, manufacturer: "LENOVO", domain: "acme" }))),
    [`${Q}/volumes`]: reportOf(() => devs.flatMap((d) => [
      { deviceId: d.id, name: "C:\\", driveLetter: "C:", label: "Windows", bitLockerStatus: { conversionStatus: d.o?.conv ?? "FULLY_ENCRYPTED", protectionStatus: d.o?.prot ?? "PROTECTED", encryptionMethod: "XTS_AES_128", lockStatus: "UNLOCKED" } },
      { deviceId: d.id, name: "D:\\", driveLetter: "D:", label: "USB", bitLockerStatus: { conversionStatus: "FULLY_DECRYPTED", protectionStatus: "UNPROTECTED" } },
    ])),
    [`${Q}/operating-systems`]: reportOf(() => devs.map((d) => ({ deviceId: d.id, name: d.o?.osName ?? "Windows 11 Professional Edition", buildNumber: d.o?.build ?? "26100", releaseId: "24H2", needsReboot: false }))),
    [`${Q}/device-health`]: reportOf(() => devs.map((d) => ({ deviceId: d.id, failedOSPatchesCount: d.o?.failed ?? 0, pendingOSPatchesCount: d.o?.pending ?? 0, healthStatus: "HEALTHY" }))),
  };
}
export const strong = () => fleet([{ id: 11, serial: "PF3TEST01" }, { id: 12, serial: "PF3TEST02" }]);
export const weak = (o: Over) => fleet([{ id: 11, serial: "PF3TEST01" }, { id: 12, serial: "PF3TEST02", o }]);

export const C: Contract = {
  source: ninjaone, clientKey: "ninjaone", base: BASE, prefix: "ninjaone", strong,
  opts: { "ninjaone-min-os": ["windows=10.0.22631"] },
  env: { NINJAONE_URL: BASE, NINJAONE_CLIENT_ID: "client-1", NINJAONE_CLIENT_SECRET: "x" },
  rateLimited: { path: DEV, check: "approved" },
  fails: {
    disk_encryption: weak({ conv: "ENCRYPTION_PAUSED" }),
    os_minimum: weak({ build: "19045" }),
    os_patches: weak({ failed: 2 }),
    last_contact: weak({ contact: secsAgo(30) }),
    approved: weak({ approval: "PENDING" }),
  },
};
