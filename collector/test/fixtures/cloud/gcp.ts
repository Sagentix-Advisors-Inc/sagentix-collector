// Fixtures for the gcp source, shared by test/gcp.test.ts and the end-to-end run (test/e2e.test.ts).
import { gcp } from "../../../src/sources/gcp.ts";
import { fetchGcpTransport, type GcpTransport } from "../../../src/sources/gcp/api.ts";
import type { HttpReply } from "../../../src/sources/shared-cloud.ts";
import type { OptionValue, Result } from "../../../src/types.ts";

export const NOW = new Date("2026-10-15T12:00:00Z");
export const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();
export const P = "acme-prod";
export const TOKEN = "ya29.fake-access-token-value-0123456789";

export const CRM = `https://cloudresourcemanager.googleapis.com/v1/projects/${P}:getIamPolicy`;
export const ORG = (c: string) => `https://orgpolicy.googleapis.com/v2/projects/${P}/policies/${c}:getEffectivePolicy`;
export const SAS = `https://iam.googleapis.com/v1/projects/${P}/serviceAccounts`;
export const SA = "ci@acme-prod.iam.gserviceaccount.com";
export const KEYS = `${SAS}/${encodeURIComponent(SA)}/keys`;
export const BUCKETS = "https://storage.googleapis.com/storage/v1/b";
export const BIAM = `${BUCKETS}/acme-assets/iam`;
export const SQL = `https://sqladmin.googleapis.com/v1/projects/${P}/instances`;
export const FW = `https://compute.googleapis.com/compute/v1/projects/${P}/global/firewalls`;
export const SUBNETS = `https://compute.googleapis.com/compute/v1/projects/${P}/aggregated/subnetworks`;
export const SU = `https://serviceusage.googleapis.com/v1/projects/${P}/services/securitycenter.googleapis.com`;
export const LOCS = `https://cloudkms.googleapis.com/v1/projects/${P}/locations`;
export const RINGS = `${LOCS}/us-central1/keyRings`;
export const RING = `projects/${P}/locations/us-central1/keyRings/main`;
export const CKEYS = `https://cloudkms.googleapis.com/v1/${RING}/cryptoKeys`;
export const CRM3 = "https://cloudresourcemanager.googleapis.com/v3";
export const ANCESTRY = `https://cloudresourcemanager.googleapis.com/v1/projects/${P}:getAncestry`;
export const FOLDER = `${CRM3}/folders/111`, ORGN = `${CRM3}/organizations/222`;
export const INSTANCES = `https://compute.googleapis.com/compute/v1/projects/${P}/aggregated/instances`;
export const VULNS = `https://osconfig.googleapis.com/v1/projects/${P}/locations/us-central1-a/instances/-/vulnerabilityReports`;
export const vulnReport = (id: string, sev: string, updated = daysAgo(1)) => ({ name: `projects/123/locations/us-central1-a/instances/${id}/vulnerabilityReport`, highestUpgradableCveSeverity: sev, vulnerabilities: [{}, {}], updateTime: updated });
export const NMCFG = `https://networkmanagement.googleapis.com/v1/projects/${P}/locations/global/vpcFlowLogsConfigs`;
export const NMORG = `${NMCFG}:queryOrgVpcFlowLogsConfigs`;
export const RUNS = `${SQL}/db1/backupRuns`;
export const LOGB = `https://logging.googleapis.com/v2/projects/${P}/locations/-/buckets`;

export type Route = unknown | ((url: string) => HttpReply);
export const ok = (json: unknown): HttpReply => ({ status: 200, headers: {}, body: JSON.stringify(json) });
export const err = (status: number, message = "The caller does not have permission"): HttpReply =>
  ({ status, headers: {}, body: JSON.stringify({ error: { code: status, message, status: "PERMISSION_DENIED" } }) });

export function strong(): Record<string, Route> {
  return {
    [CRM]: { version: 3, bindings: [{ role: "roles/owner", members: ["user:alice@example.com"] }], auditConfigs: [{ service: "allServices", auditLogConfigs: [{ logType: "ADMIN_READ" }, { logType: "DATA_READ" }, { logType: "DATA_WRITE" }] }] },
    [ANCESTRY]: { ancestor: [{ resourceId: { type: "project", id: P } }, { resourceId: { type: "folder", id: "111" } }, { resourceId: { type: "organization", id: "222" } }] },
    [`${FOLDER}:getIamPolicy`]: { version: 3, bindings: [] },
    [`${ORGN}:getIamPolicy`]: { version: 3, bindings: [] },
    [NMCFG]: { vpcFlowLogsConfigs: [] },
    [NMORG]: { vpcFlowLogsConfigs: [] },
    [ORG("iam.disableServiceAccountKeyCreation")]: { name: "x", spec: { rules: [{ enforce: true }] } },
    [ORG("storage.publicAccessPrevention")]: { name: "y", spec: { rules: [{ enforce: true }] } },
    [SAS]: { accounts: [{ email: SA, uniqueId: "1" }] },
    [KEYS]: { keys: [{ name: "k1", keyType: "USER_MANAGED", validAfterTime: daysAgo(30) }] },
    [BUCKETS]: { items: [{ name: "acme-assets", iamConfiguration: { publicAccessPrevention: "inherited" } }] },
    [BIAM]: { bindings: [{ role: "roles/storage.objectViewer", members: ["serviceAccount:ci@acme-prod.iam.gserviceaccount.com"] }] },
    [SQL]: { items: [{ name: "db1", settings: { ipConfiguration: { ipv4Enabled: false, sslMode: "ENCRYPTED_ONLY", authorizedNetworks: [] } } }] },
    [RUNS]: { items: [{ status: "FAILED", windowStartTime: daysAgo(2) }, { status: "SUCCESSFUL", windowStartTime: daysAgo(1) }, { status: "SUCCESSFUL", windowStartTime: daysAgo(30) }] },
    [LOGB]: { buckets: [{ name: `projects/${P}/locations/global/buckets/_Required`, retentionDays: 400, locked: true }, { name: `projects/${P}/locations/global/buckets/_Default`, retentionDays: 400 }] },
    [FW]: { items: [{ name: "allow-https", direction: "INGRESS", sourceRanges: ["0.0.0.0/0"], allowed: [{ IPProtocol: "tcp", ports: ["443"] }] }, { name: "egress-all", direction: "EGRESS", destinationRanges: ["0.0.0.0/0"], allowed: [{ IPProtocol: "all" }] }] },
    [SU]: { name: "projects/123/services/securitycenter.googleapis.com", state: "ENABLED" },
    [LOCS]: { locations: [{ locationId: "us-central1", name: `projects/${P}/locations/us-central1` }] },
    [RINGS]: { keyRings: [{ name: RING }] },
    [CKEYS]: { cryptoKeys: [{ name: `${RING}/cryptoKeys/app`, purpose: "ENCRYPT_DECRYPT", rotationPeriod: "7776000s" }, { name: `${RING}/cryptoKeys/sign`, purpose: "ASYMMETRIC_SIGN" }] },
    [INSTANCES]: { items: { "zones/us-central1-a": { instances: [{ id: "4001", name: "web-1", zone: "https://x/zones/us-central1-a", status: "RUNNING" }, { id: "4002", name: "old", zone: "https://x/zones/us-central1-a", status: "TERMINATED" }] }, "zones/europe-west1-b": { warning: { code: "NO_RESULTS_ON_PAGE" } } } },
    [VULNS]: { vulnerabilityReports: [vulnReport("4001", "LOW")] },
    [SUBNETS]: { items: { "regions/us-central1": { subnetworks: [{ name: "app", region: "https://x/regions/us-central1", purpose: "PRIVATE", logConfig: { enable: true } }, { name: "proxy", region: "r/us-central1", purpose: "REGIONAL_MANAGED_PROXY" }] }, "regions/europe-west1": { warning: { code: "NO_RESULTS_ON_PAGE" } } } },
  };
}

export interface Call { method: string; url: string; body?: unknown }
export function fake(over: Record<string, Route> = {}, calls: Call[] = []): GcpTransport {
  const routes = { ...strong(), ...over };
  return {
    sleep: async () => {},
    async request(method, url, body) {
      calls.push({ method, url, body });
      const r = routes[url.split("?")[0]];
      if (r === undefined) return err(404, `no fake for ${url}`);
      return typeof r === "function" ? (r as (u: string) => HttpReply)(url) : ok(r);
    },
  };
}
