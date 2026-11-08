// Fixtures for the configmgr source, shared by test/configmgr.test.ts and the end-to-end run (test/e2e.test.ts).
import { PATHS, cmDate, configmgr, configmgrFromEnv, getScript } from "../../../src/sources/configmgr.ts";
import type { Run } from "../../../src/sources/windows.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "../../rest_fakes.ts";

export const BASE = "https://cm01.corp.example.com/AdminService/wmi";
export const ok = (value: unknown[], next?: string) => res(200, { "@odata.context": `${BASE}/$metadata#X`, value, ...(next ? { "@odata.nextLink": next } : {}) });

export interface Over { client?: boolean; active?: string | null; ep?: boolean | null; av?: boolean; sig?: string; late?: boolean; unknown?: boolean; baseline?: number }

export function device(id: number, o: Over = {}): Record<string, unknown> {
  return {
    ResourceID: id, SerialNumber: `PF3CM00${id}`, Name: "ANNA-LAPTOP", UserName: "achao", UserDomainName: "CORP", DeviceOS: "Microsoft Windows NT Workstation 10.0",
    IsClient: o.client ?? true, IsObsolete: false, Unknown: false, ClientActiveStatus: 1,
    LastActiveTime: o.active === null ? null : (o.active ?? daysAgo(1)), LastPolicyRequest: daysAgo(2),
    EPEnabled: o.ep === null ? null : (o.ep ?? true), EPAntivirusEnabled: o.av ?? true, EPAntivirusSignatureLastUpdateDateTime: o.sig ?? daysAgo(1),
  };
}
export const UPDATES = [
  { CI_ID: 101, ArticleID: "5044284", IsDeployed: true, IsExpired: false, DatePosted: daysAgo(60), SeverityName: "Critical", LocalizedDisplayName: "2026-08 Cumulative Update" },
  { CI_ID: 102, ArticleID: "5046617", IsDeployed: true, IsExpired: false, DatePosted: daysAgo(5), SeverityName: "Important", LocalizedDisplayName: "2026-10 Cumulative Update" },
];

export function site(devs: { id: number; o?: Over }[]): Routes {
  const status: unknown[] = [];
  const ci: unknown[] = [];
  for (const d of devs) {
    status.push({ MachineID: d.id, CI_ID: 102, Status: 2, ArticleID: "5046617" });   // recent: within the grace period
    if (d.o?.late) status.push({ MachineID: d.id, CI_ID: 101, Status: 2, ArticleID: "5044284" });
    if (d.o?.unknown) status.push({ MachineID: d.id, CI_ID: 101, Status: 0, ArticleID: "5044284" });
    ci.push({ ResourceID: d.id, CI_ID: 900, LocalizedDisplayName: "CIS Windows 11 baseline", ComplianceState: d.o?.baseline ?? 1, UserName: "achao" });
  }
  return {
    [PATHS.devices]: ok(devs.map((d) => device(d.id, d.o))),
    [PATHS.updates]: ok(UPDATES),
    [PATHS.updateStatus]: ok(status),
    [PATHS.baselines]: ok(ci),
  };
}
export const strong = () => site([{ id: 16777219 }, { id: 16777220 }]);
export const weak = (o: Over) => site([{ id: 16777219 }, { id: 16777220, o }]);

export const C: Contract = {
  source: configmgr, clientKey: "configmgr", base: BASE, prefix: "configmgr", strong,
  env: { CONFIGMGR_PROVIDER: "cm01.corp.example.com" },
  rateLimited: { path: PATHS.devices, check: "client_installed" },
  fails: {
    client_installed: weak({ client: false }),
    last_seen: weak({ active: daysAgo(40) }),
    antimalware_enabled: weak({ av: false }),
    antimalware_signatures_current: weak({ sig: daysAgo(20) }),
    updates_installed: weak({ late: true }),
    baselines_compliant: weak({ baseline: 2 }),
  },
};
