// Fixtures for the fleet source, shared by test/fleet.test.ts and the end-to-end run (test/e2e.test.ts).
import { fleet, fleetFromEnv, PAGE } from "../../../src/sources/fleet.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "../../rest_fakes.ts";

export const BASE = "https://fleet.example.com/api/v1/fleet";
export const ok = (b: unknown) => res(200, b);

export const pol = (id: number, name: string, response: string, platform = "") => ({ id, name, query: "SELECT 1;", platform, response, critical: false });

/** A Mac and a Windows laptop, both well configured. Display names and end users carry a person on purpose. */
export function hosts(): Record<string, unknown>[] {
  return [
    {
      id: 1, hostname: "Annas-MacBook-Pro.local", computer_name: "Anna's MacBook Pro", display_name: "Anna's MacBook Pro",
      hardware_serial: "C02TEST0001", platform: "darwin", os_version: "macOS 15.2", seen_time: daysAgo(1), disk_encryption_enabled: true,
      mdm: { enrollment_status: "On (automatic)", name: "Fleet", server_url: "https://fleet.example.com/mdm/apple/mdm" },
      end_users: [{ idp_username: "anna.chao@acme.example", idp_full_name: "Anna Chao" }],
      policies: [
        pol(10, "Screen lock enabled (macOS)", "pass", "darwin"), pol(11, "Firewall enabled (macOS)", "pass", "darwin"),
        pol(12, "Antivirus healthy (XProtect)", "pass", "darwin"), pol(13, "Operating system up to date (macOS)", "pass", "darwin"),
        pol(14, "Gatekeeper enabled", "fail", "darwin"),
      ],
    },
    {
      id: 2, hostname: "DESKTOP-BOB", computer_name: "Bob Smith's PC", display_name: "Bob Smith's PC",
      hardware_serial: "PF3TEST0002", platform: "windows", os_version: "Microsoft Windows 11 Pro 23H2 10.0.22631.4602", seen_time: daysAgo(3), disk_encryption_enabled: true,
      mdm: { enrollment_status: "On (manual)", name: "Microsoft Intune" },
      policies: [
        pol(20, "Screen lock enabled (Windows)", "pass", "windows"), pol(21, "Windows Firewall on", "pass", "windows"),
        pol(22, "CrowdStrike Falcon running", "pass", "windows"), pol(23, "Windows OS up to date", "pass", "windows"),
      ],
    },
  ];
}

export const hostRoute = (list: Record<string, unknown>[]) => ok({ hosts: list });
export function withHost(i: number, change: (h: Record<string, unknown>) => void): Routes {
  const list = hosts();
  change(list[i]);
  return { "/hosts": hostRoute(list) };
}
export const setPolicy = (id: number, response: string) => (h: Record<string, unknown>) => {
  for (const p of h.policies as { id: number; response: string }[]) if (p.id === id) p.response = response;
};

export const C: Contract = {
  source: fleet, clientKey: "fleet", base: BASE, prefix: "fleet",
  strong: () => ({ "/hosts": hostRoute(hosts()) }),
  env: { FLEET_URL: "https://fleet.example.com", FLEET_API_TOKEN: "x" },
  rateLimited: { path: "/hosts", check: "disk_encryption" },
  fails: {
    disk_encryption: withHost(0, (h) => { h.disk_encryption_enabled = false; }),
    screen_lock: withHost(0, setPolicy(10, "fail")),
    os_up_to_date: withHost(1, setPolicy(23, "fail")),
    firewall: withHost(1, setPolicy(21, "fail")),
    edr_present: withHost(1, setPolicy(22, "fail")),
    mdm_enrolled: withHost(0, (h) => { h.mdm = { enrollment_status: "Off", name: null }; }),
    last_seen: withHost(1, (h) => { h.seen_time = daysAgo(40); }),
  },
};
