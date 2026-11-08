// Fixtures for the defender_endpoint source, shared by test/defender_endpoint.test.ts and the end-to-end run (test/e2e.test.ts).
import { DEFENDER_BASE, DEFENDER_SCOPE, defenderChecks, defenderFromEnv, defender_endpoint } from "../../../src/sources/defender_endpoint.ts";
import { withRetry } from "../../../src/sources/readonly_http.ts";
import { NOW } from "../../helpers.ts";
import { contractSuite, daysAgo, fakeRest, of, res, runWith, type Contract, type Routes } from "../../rest_fakes.ts";

export const ok = (b: unknown) => res(200, b);
export const page = (value: unknown[], next?: string) => ok({ value, ...(next ? { "@odata.nextLink": next } : {}) });
export const M = "/api/machines";
export const AV = "/api/deviceavinfo";
export const V = "/api/vulnerabilities/machinesVulnerabilities";
export const R = "/api/recommendations";
export const TAMPER_ID = "sca-_-tamper-example";

/** computerDnsName and the IP addresses come back (no $select); they are here to prove they never reach a result. */
export function machines(): Record<string, unknown>[] {
  return [
    { id: "1e5bc9d7e413ddd7902c2932e418702b84d0cc07", computerDnsName: "annas-laptop.acme.example", osPlatform: "Windows11", onboardingStatus: "Onboarded",
      healthStatus: "Active", lastSeen: daysAgo(1), exposureLevel: "Low", lastIpAddress: "172.17.230.209", lastExternalIpAddress: "167.220.196.71", machineTags: ["Bob Smith"] },
    { id: "30a8fa2826abf24d24379b23f8a44d471f00feab", computerDnsName: "bob-macbook.acme.example", osPlatform: "macOS", onboardingStatus: "Onboarded",
      healthStatus: "Active", lastSeen: daysAgo(2), exposureLevel: "Medium", lastIpAddress: "10.0.0.8" },
  ];
}
export function avRows(): Record<string, unknown>[] {
  return [
    { id: "1e5bc9d7e413ddd7902c2932e418702b84d0cc07", machineId: "1e5bc9d7e413ddd7902c2932e418702b84d0cc07", computerDnsName: "annas-laptop", osKind: "windows",
      avMode: "0", avIsSignatureUpToDate: "True", avIsEngineUpToDate: "True", avIsPlatformUpToDate: "True", lastSeenTime: daysAgo(1), rbacGroupName: "Laptops" },
    { id: "30a8fa2826abf24d24379b23f8a44d471f00feab", machineId: "30a8fa2826abf24d24379b23f8a44d471f00feab", computerDnsName: "bob-macbook", osKind: "mac",
      avMode: "0", avIsSignatureUpToDate: "True", avIsEngineUpToDate: "True", avIsPlatformUpToDate: "True", lastSeenTime: daysAgo(2) },
  ];
}
export const tamperRec = (exposed: number, status = "Active") => ({ id: TAMPER_ID, recommendationName: "Turn on Tamper Protection", recommendationCategory: "SecurityControls",
  status, exposedMachinesCount: exposed, totalMachineCount: 2 });
export const otherRec = { id: "sca-_-scid-91", recommendationName: "Turn on Microsoft Defender Antivirus", recommendationCategory: "SecurityControls", status: "Active", exposedMachinesCount: 0 };

export function strong(): Routes {
  return {
    [M]: page(machines()),
    [AV]: page(avRows()),
    [V]: page([]),
    [R]: page([otherRec, tamperRec(0)]),
  };
}
export const withMachine = (i: number, change: (m: Record<string, unknown>) => void): Routes => {
  const ms = machines(); change(ms[i]); return { [M]: page(ms) };
};
export const withAv = (i: number, change: (m: Record<string, unknown>) => void): Routes => {
  const rs = avRows(); change(rs[i]); return { [AV]: page(rs) };
};

export const C: Contract = {
  source: defender_endpoint, clientKey: "defender_endpoint", base: DEFENDER_BASE, prefix: "defender_endpoint", strong,
  env: { DEFENDER_TENANT_ID: "tenant-1", DEFENDER_CLIENT_ID: "app-1", DEFENDER_CLIENT_SECRET: "x" },
  rateLimited: { path: AV, check: "av_signatures_current" },
  fails: {
    device_onboarded: withMachine(1, (m) => { m.onboardingStatus = "CanBeOnboarded"; }),
    sensor_healthy: withMachine(0, (m) => { m.healthStatus = "Inactive"; }),
    av_active_mode: withAv(1, (r) => { r.avMode = "1"; }),
    av_signatures_current: withAv(0, (r) => { r.avIsSignatureUpToDate = "False"; }),
    high_exposure_devices: withMachine(1, (m) => { m.exposureLevel = "High"; }),
    critical_vulnerability_devices: { [V]: page([{ id: "x", cveId: "CVE-2016-3348", machineId: "1e5bc9d7e413ddd7902c2932e418702b84d0cc07", fixingKbId: "3185911", severity: "Critical" }]) },
    tamper_protection: { [R]: page([tamperRec(1)]), [`${R}/${TAMPER_ID}/machineReferences`]: page([{ id: "30a8fa2826abf24d24379b23f8a44d471f00feab", computerDnsName: "bob-macbook" }]) },
  },
};
