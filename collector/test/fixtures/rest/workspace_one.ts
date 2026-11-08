// Fixtures for the workspace_one source, shared by test/workspace_one.test.ts and the end-to-end run (test/e2e.test.ts).
import { PAGE, encryptionPath, searchPath, workspaceOne, ws1FromEnv } from "../../../src/sources/workspace_one.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "../../rest_fakes.ts";

export const BASE = "https://as1234.awmdm.com/api";
export const SEARCH = "/mdm/devices/search";
export const ok = (b: unknown) => res(200, b);
export const q = (url: string) => new URL(`https://x${url}`).searchParams;

export interface Over { type?: string; os?: string; seen?: string; enroll?: string; compliance?: string; compromised?: boolean; encrypted?: boolean }

export function device(n: number, o: Over = {}): Record<string, unknown> {
  return {
    udid: `UDID${n}`, serial_number: `C02WS1000${n}`, mac_address: "aa:bb:cc:dd:ee:ff", imei: "",
    device_friendly_name: "Anna's MacBook Pro", device_reported_name: "Anna-MBP",
    enrollment_user_name: "achao", enrollment_user_email_address: "anna@acme.example",
    ownership: "CORPORATE", platform_name: "Apple macOS", device_type: o.type ?? "APPLE_OS_X", model: "MacBook Pro",
    operating_system: o.os ?? "15.1.0", last_seen: o.seen ?? daysAgo(1), enrollment_status: o.enroll ?? "ENROLLED",
    compliance_status: o.compliance ?? "COMPLIANT", compromised_status: o.compromised ?? false, wifi_ssid: "AcmeCorp",
    Id: { Value: n }, Uuid: `0000000${n}-0000-0000-0000-00000000000${n}`,
  };
}
export const uuid = (n: number) => `0000000${n}-0000-0000-0000-00000000000${n}`;
export const search = (devs: Record<string, unknown>[], total = devs.length) => ok({ devices: devs, page: 0, page_size: PAGE, total });

export function fleet(devs: { n: number; o?: Over }[]): Routes {
  const r: Routes = { [SEARCH]: search(devs.map((d) => device(d.n, d.o))) };
  for (const d of devs) r[encryptionPath(uuid(d.n))] = ok({ encryption_status: d.o?.encrypted ?? true });
  return r;
}
export const strong = () => fleet([{ n: 1 }, { n: 2, o: { type: "WINDOWS_PC", os: "10.0.26100.1000" } }]);
export const weak = (o: Over) => fleet([{ n: 1 }, { n: 2, o }]);

export const C: Contract = {
  source: workspaceOne, clientKey: "workspace_one", base: BASE, prefix: "workspace_one", strong,
  opts: { "workspace-one-min-os": ["macos=14.0", "windows=10.0.22631"] },
  env: { WS1_API_URL: "https://as1234.awmdm.com", WS1_TOKEN_URL: "https://na.uemauth.workspaceone.com/connect/token", WS1_CLIENT_ID: "client-1", WS1_CLIENT_SECRET: "x" },
  rateLimited: { path: SEARCH, check: "enrolled" },
  fails: {
    disk_encryption: weak({ encrypted: false }),
    os_minimum: weak({ os: "13.6.9" }),
    last_seen: weak({ seen: daysAgo(30) }),
    enrolled: weak({ enroll: "PENDING_AGENT" }),
    compliant: weak({ compliance: "NOT_COMPLIANT" }),
    compromised: weak({ compromised: true }),
  },
};
