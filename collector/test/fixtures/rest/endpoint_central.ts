// Fixtures for the endpoint_central source, shared by test/endpoint_central.test.ts and the end-to-end run (test/e2e.test.ts).
import { PATCH_PAGE, acceptFor, endpoint_central, endpointCentralFromEnv, suffixOf } from "../../../src/sources/endpoint_central.ts";
import { contractSuite, fakeRest, of, res, runWith, type Contract, type Route, type Routes } from "../../rest_fakes.ts";
import { NOW } from "../../helpers.ts";

export const BASE = "https://endpointcentral.manageengine.ca";
export const SCAN = "/dcapi/inventory/viewData/scanComputers";
export const HEALTH = "/dcapi/patch/reports/systemHealth";
export const INV = "/dcapi/inventory/computers";
export const ok = (b: unknown) => res(200, b);
export const q = (url: string) => new URL(`https://x${url}`).searchParams;
export const msAgo = (days: number) => String(NOW.getTime() - days * 86_400_000);

export interface Over { platform?: string; version?: string; install?: string; contact?: string; drives?: [string, string][]; profiles?: [string, string, string];
  external?: string; missing?: string }
export interface Pc { id: string; tag: string; name: string; o?: Over }

export function computer(p: Pc): Record<string, unknown> {
  return {
    resource_id: p.id, servicetag: p.tag, resource_name: p.name, resource_name_transform: p.name, name: "Anna Chao", name_transform: "Anna Chao",
    fqdn_name: `${p.name.toUpperCase()}.ACME.EXAMPLE`, ip_address: "10.0.0.7", mac_address: "00:11:22:33:44:55", domain_netbios_name: "ACME",
    os_platform: p.o?.platform ?? "1", os_name: "Windows 11 Professional Edition (x64)", os_version: p.o?.version ?? "10.0.26200", build_number: "26200.8246",
    installation_status: p.o?.install ?? "22", agent_last_contact_time: p.o?.contact ?? msAgo(1), computer_live_status: "1", customer_id: "1",
  };
}

export function fleet(pcs: Pc[], pageSize = 25): Routes {
  const r: Routes = {
    [SCAN]: (url) => {
      const page = Number(q(url).get("page") ?? "1");
      const rows = pcs.slice((page - 1) * pageSize, page * pageSize).map(computer);
      const pages = Math.max(1, Math.ceil(pcs.length / pageSize));
      return ok({ metadata: { limit: pageSize, page }, totalRecords: String(pcs.length), totalPages: pages, messageResponse: rows,
        Links: { next: page < pages ? `${SCAN}?toolID=2131&page=${page + 1}` : null, prev: null }, status: "success" });
    },
    [HEALTH]: (url) => {
      const page = Number(q(url).get("page"));
      const size = Number(q(url).get("pageLimit"));
      const rows = pcs.slice((page - 1) * size, page * size).map((p) => ({ ComputerName: p.name, Domain: "ACME", Health: Number(p.o?.missing ?? "0") ? "Vulnerable" : "Healthy",
        MissingOsPatches: p.o?.missing ?? "0", Critical: "0", Important: p.o?.missing ?? "0", Owner: "Anna Chao", OwnerEmail: "anna@acme.example", LoggedOnUsers: "achao" }));
      const pages = Math.max(1, Math.ceil(pcs.length / size));
      return ok({ metadata: { limit: size, page }, totalRecords: pcs.length, totalPages: pages, messageResponse: rows,
        Links: { next: page < pages ? `${HEALTH}?page=${page + 1}&pageLimit=${size}` : null, prev: null }, status: "success" });
    },
  };
  for (const p of pcs) {
    const drives = p.o?.drives ?? [["C:", "Encrypted"]];
    r[`${INV}/${p.id}/diskEncryptionStatus`] = ok({ diskEncryptionStatusDetails: drives.map(([d, s]) => ({ logicalDriveName: d, encryptionStatus: s, logicalDiskType: "Primary", encryptionMethod: s === "Encrypted" ? "XTS-AES 128" : "None" })) });
    const [dp, pp, pub] = p.o?.profiles ?? ["Enabled", "Enabled", "Enabled"];
    r[`${INV}/${p.id}/firewall`] = ok({
      windowsFirewallDetails: p.o?.platform && p.o.platform !== "1" ? [] : [{ isExternalFirewallEnabled: p.o?.external ? "true" : "false", domainProfileStatus: dp, externalFirewallName: "-", privateProfileStatus: pp, publicProfileStatus: pub }],
      externalFirewallDetails: p.o?.external ? [{ firewallName: "Sample Firewall", protectionStatus: p.o.external, installationPath: "C:\\Users\\achao\\fw", manufacturer: "Sample Security Corp" }] : [],
    });
  }
  return r;
}
export const strong = () => fleet([{ id: "301", tag: "SAMPLE01", name: "anna-pc" }, { id: "302", tag: "SAMPLE02", name: "bob-pc" }]);
export const weak = (o: Over) => fleet([{ id: "301", tag: "SAMPLE01", name: "anna-pc" }, { id: "302", tag: "SAMPLE02", name: "bob-pc", o }]);

export const C: Contract = {
  source: endpoint_central, clientKey: "endpoint_central", base: BASE, prefix: "endpoint_central", strong,
  opts: { "endpoint-central-min-os": ["windows=10.0.26100"] },
  env: { ENDPOINT_CENTRAL_URL: BASE, ENDPOINT_CENTRAL_CLIENT_ID: "1000.CLIENT", ENDPOINT_CENTRAL_CLIENT_SECRET: "x", ENDPOINT_CENTRAL_REFRESH_TOKEN: "y" },
  rateLimited: { path: SCAN, check: "agent_installed" },
  fails: {
    disk_encryption: weak({ drives: [["C:", "Encrypted"], ["D:", "Not Encrypted"]] }),
    firewall: weak({ profiles: ["Enabled", "Enabled", "Disabled"] }),
    os_minimum: weak({ version: "10.0.19045" }),
    os_patches: weak({ missing: "4" }),
    last_contact: weak({ contact: msAgo(30) }),
    agent_installed: weak({ install: "29" }),
  },
};
