// Fixtures for the google_endpoints source, shared by test/google_endpoints.test.ts and the end-to-end run (test/e2e.test.ts).
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEVICES_BASE, DEVICES_SCOPE, PAGE, devicesPath, googleDevicesFromEnv, googleEndpoints } from "../../../src/sources/google_endpoints.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "../../rest_fakes.ts";

export const LIST = "/v1/devices";
export const ok = (b: unknown) => res(200, b);
export const q = (url: string) => new URL(`https://x${url}`).searchParams;

export interface Over { type?: string; os?: string; enc?: string; fw?: boolean | null; sync?: string; comp?: string }

export function device(n: number, o: Over = {}): Record<string, unknown> {
  const d: Record<string, unknown> = {
    name: `devices/dev${n}`, deviceId: `dev${n}`, serialNumber: `SNGOOG${n}`, deviceType: o.type ?? "MAC_OS", osVersion: o.os ?? "MacOS 15.1.0",
    lastSyncTime: o.sync ?? daysAgo(1), encryptionState: o.enc ?? "ENCRYPTED", compromisedState: o.comp ?? "UNCOMPROMISED",
    hostname: "annas-macbook.acme.example", otherAccounts: ["anna@gmail.com"], wifiMacAddresses: ["aa:bb:cc:dd:ee:ff"], model: "MacBookPro18,1", ownerType: "COMPANY",
  };
  if (o.fw !== null) d.endpointVerificationSpecificAttributes = { additionalSignals: { is_os_native_firewall_enabled: o.fw ?? true, windows_domain_name: "ACME" },
    browserAttributes: [{ chromeProfileId: "anna-profile", chromeBrowserInfo: { browserVersion: "130.0" } }] };
  return d;
}
export const page = (devs: Record<string, unknown>[], next?: string) => ok({ devices: devs, ...(next ? { nextPageToken: next } : {}) });
export const strong = (): Routes => ({ [LIST]: page([device(1), device(2, { type: "WINDOWS", os: "Windows 10.0.26100" })]) });
export const weak = (o: Over): Routes => ({ [LIST]: page([device(1), device(2, o)]) });

export const C: Contract = {
  source: googleEndpoints, clientKey: "google_endpoints", base: DEVICES_BASE, prefix: "google_endpoints", strong,
  opts: { "google-endpoints-min-os": ["mac_os=14.0", "windows=10.0.22631"] },
  env: { GOOGLE_SA_KEY_FILE: "/nonexistent/sa.json", GOOGLE_ADMIN_EMAIL: "reader@acme.example" },
  rateLimited: { path: LIST, check: "disk_encryption" },
  fails: {
    disk_encryption: weak({ enc: "NOT_ENCRYPTED" }),
    firewall: weak({ fw: false }),
    os_minimum: weak({ os: "MacOS 13.6.9" }),
    last_sync: weak({ sync: daysAgo(40) }),
    compromised: weak({ comp: "COMPROMISED" }),
  },
};
