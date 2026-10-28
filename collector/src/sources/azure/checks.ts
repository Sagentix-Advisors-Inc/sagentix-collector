// Per-subscription checks over Azure Resource Manager (GET only). One result per resource; a refused
// call gives "skipped"; a check with nothing to judge (no storage account, no SQL database) gives
// "skipped". Microsoft Entra ID is not read here.
//
// Endpoints (all under https://management.azure.com/subscriptions/{s}) and the role that reads them:
//   GET /providers/Microsoft.Security/pricings                     Security Reader (or Reader)
//   GET /providers/Microsoft.Security/secureScores                 Security Reader (or Reader)
//   GET /providers/Microsoft.Insights/diagnosticSettings           Reader
//   GET /providers/Microsoft.KeyVault/vaults                       Reader
//   GET /providers/Microsoft.Storage/storageAccounts               Reader
//   GET /providers/Microsoft.Sql/servers, {server}/databases,
//       {database}/transparentDataEncryption/current               Reader
//   GET /providers/Microsoft.Network/networkSecurityGroups         Reader
//   GET /providers/Microsoft.Authorization/policyAssignments       Reader
//   GET /providers/Microsoft.Compute/disks                         Reader
//   GET /providers/Microsoft.RecoveryServices/vaults, {vault}/backupProtectedItems   Reader
//   GET /resources?$filter=resourceType eq '<type>'                Reader (which Defender plans the subscription needs)
//   GET {sql server}/firewallRules                                 Reader
//   GET /providers/Microsoft.Compute/virtualMachines, {vm}/instanceView   Reader

import { ADMIN_PORTS, Results, ageDays, arr, isObj, j, rangeHits, str, httpWhy, type Obj } from "../shared-cloud.ts";
import { API, ARM, armGet, armMessage, listAll, okStatus, rgName, type ArmReply, type AzureTransport } from "./api.ts";

export const AZURE_CHECKS = [
  "defender_plans", "secure_score", "activity_log_export", "keyvault_recoverable",
  "storage_secure_transfer", "storage_no_public_blob", "storage_min_tls", "sql_tde",
  "nsg_no_open_admin_ports", "policy_assignments", "disk_encryption", "backup_protected_items",
  "sql_firewall_not_open", "vm_patches_current",
] as const;
/** Oldest a VM's patch assessment may be (Azure Update Manager's periodic assessment runs every 24 hours). */
export const MAX_ASSESSMENT_DAYS = 7;
export type AzureCheck = (typeof AZURE_CHECKS)[number];

const why = (r: ArmReply) => httpWhy(r.reply, armMessage(r));

/** Source prefixes NSG treats as "anyone on the Internet". */
const OPEN_SOURCES = new Set(["*", "internet", "any", "0.0.0.0/0", "0.0.0.0", "::/0"]);
const TLS_OK = new Set(["TLS1_2", "TLS1_3"]);
const DISK_ENCRYPTION_TYPES = new Set(["EncryptionAtRestWithPlatformKey", "EncryptionAtRestWithCustomerKey", "EncryptionAtRestWithPlatformAndCustomerKeys"]);

export interface AzureOptions { minSecureScore: number; now: Date }

// Which resource types each Defender for Cloud plan protects, so a plan is demanded only where the subscription has
// something for it to protect (Stéphane, 2026-10-26). Plan names are the pricings API's (Pricings - List,
// learn.microsoft.com/rest/api/defenderforcloud/pricings/list, read 2026-10-26); what each plan covers is from its
// Defender for Cloud page, read 2026-10-26: Servers (defender-for-servers-overview: machines in Azure, other clouds and
// on-premises through Azure Arc), Azure SQL (defender-for-sql-introduction: Azure SQL databases, managed instances,
// Synapse dedicated SQL pools), SQL servers on machines, App Service, Storage (storage accounts), Key Vault, Containers
// (Kubernetes clusters and registries), open-source relational databases (defender-for-databases-introduction:
// PostgreSQL and MySQL Flexible Server), Cosmos DB and APIs (API Management). Each type name was confirmed on the
// service's REST reference on 2026-10-26; Microsoft.ContainerRegistry/registries and Microsoft.DBforMySQL/flexibleServers,
// whose reference pages did not load, on 2026-10-27 in Microsoft's REST specifications (github.com/Azure/azure-rest-api-specs
// at 2455f14a8f: ContainerRegistry Registry stable 2025-11-01 and DBforMySQL FlexibleServers stable 2024-12-30 both list
// /subscriptions/{subscriptionId}/providers/<that type>). Arm (Defender for Resource Manager)
// watches the subscription's own management operations, so every subscription needs it. Any other plan (CloudPosture,
// whose foundational tier is free, and plans added after this list) is reported and not judged.
export const PLAN_TYPES: Record<string, string[]> = {
  VirtualMachines: ["Microsoft.Compute/virtualMachines", "Microsoft.Compute/virtualMachineScaleSets", "Microsoft.HybridCompute/machines"],
  SqlServers: ["Microsoft.Sql/servers", "Microsoft.Sql/managedInstances", "Microsoft.Synapse/workspaces/sqlPools"],
  SqlServerVirtualMachines: ["Microsoft.SqlVirtualMachine/sqlVirtualMachines"],
  AppServices: ["Microsoft.Web/sites"],
  StorageAccounts: ["Microsoft.Storage/storageAccounts"],
  KeyVaults: ["Microsoft.KeyVault/vaults"],
  Containers: ["Microsoft.ContainerService/managedClusters", "Microsoft.Kubernetes/connectedClusters", "Microsoft.ContainerRegistry/registries"],
  OpenSourceRelationalDatabases: ["Microsoft.DBforPostgreSQL/flexibleServers", "Microsoft.DBforMySQL/flexibleServers"],
  CosmosDbs: ["Microsoft.DocumentDB/databaseAccounts"],
  Api: ["Microsoft.ApiManagement/service"],
};
export const SUBSCRIPTION_WIDE_PLANS = new Set(["Arm"]);

async function defenderPlans(t: AzureTransport, S: string, subRes: string, out: Results<AzureCheck>): Promise<void> {
  const pr = await listAll(t, `${S}/providers/Microsoft.Security/pricings?api-version=${API.pricings}`);
  if ("error" in pr) return out.skip("defender_plans", subRes, `Defender for Cloud plans not readable: ${why(pr.error)}`);
  const plans = pr.items.filter((p) => !(isObj(p.properties) && p.properties.deprecated === true));
  if (!plans.length) return out.skip("defender_plans", subRes, "the API listed no current Defender for Cloud plan");
  // Resources - List with $filter=resourceType eq '<type>' (learn.microsoft.com/rest/api/resources/resources/list, read
  // 2026-10-26; Reader). One filtered call per type, so a large subscription is not paged through.
  const seen = new Map<string, number | string>();
  const count = async (type: string) => {
    if (!seen.has(type)) {
      const r = await listAll(t, `${S}/resources?$filter=${encodeURIComponent(`resourceType eq '${type}'`)}&api-version=${API.resources}`, 5);
      seen.set(type, "error" in r ? why(r.error) : r.items.length);
    }
    return seen.get(type)!;
  };
  for (const p of plans) {
    const name = String(p.name);
    const tier = isObj(p.properties) ? p.properties.pricingTier : undefined;
    const res = `defender plan ${name} (${subRes})`;
    const on = tier === "Standard";
    if (SUBSCRIPTION_WIDE_PLANS.has(name)) { out.add("defender_plans", res, on ? "pass" : "fail", `pricingTier is ${j(tier)}; "Standard" required (the plan protects the subscription itself)`); continue; }
    const types = PLAN_TYPES[name];
    if (!types) { out.add("defender_plans", res, "skipped", `pricingTier is ${j(tier)}; the plan has no resource-type mapping in the collector, so whether the subscription needs it is not judged`); continue; }
    const found: string[] = [], unread: string[] = [];
    for (const ty of types) {
      const n = await count(ty);
      if (typeof n === "string") unread.push(`${ty} (${n})`);
      else if (n > 0) found.push(`${n} ${ty}`);
    }
    if (found.length) out.add("defender_plans", res, on ? "pass" : "fail", `pricingTier is ${j(tier)}; the subscription has ${found.join(", ")}; "Standard" required`);
    else if (unread.length) out.add("defender_plans", res, on ? "pass" : "skipped", `pricingTier is ${j(tier)}; resources not listable to see whether the plan is needed: ${unread.join("; ")}`);
    else out.add("defender_plans", res, on ? "pass" : "skipped", `pricingTier is ${j(tier)}; the subscription has no ${types.join(", ")}, so the plan is not required`);
  }
}

/** Ports a destination port spec covers among 22 and 3389 ("*", "22", "20-30"). */
export function adminPortsIn(spec: string): number[] {
  const s = spec.trim();
  if (s === "*") return [...ADMIN_PORTS];
  const m = /^(\d+)(?:\s*-\s*(\d+))?$/.exec(s);
  if (!m) return [];
  return rangeHits(Number(m[1]), Number(m[2] ?? m[1]), ADMIN_PORTS);
}

/** Inbound Allow rules of an NSG that open 22 or 3389 to the Internet, as "rule:port" strings. */
export function openAdminRules(nsg: Obj): string[] {
  const props = isObj(nsg.properties) ? nsg.properties : {};
  const hits: string[] = [];
  for (const rule of arr(props.securityRules).filter(isObj)) {
    const p = isObj(rule.properties) ? rule.properties : {};
    if (String(p.direction) !== "Inbound" || String(p.access) !== "Allow") continue;
    if (!["tcp", "*"].includes(String(p.protocol).toLowerCase())) continue;
    const sources = [str(p.sourceAddressPrefix), ...arr(p.sourceAddressPrefixes).map(str)].filter((x): x is string => !!x);
    if (!sources.some((s) => OPEN_SOURCES.has(s.trim().toLowerCase()))) continue;
    const ports = [str(p.destinationPortRange), ...arr(p.destinationPortRanges).map(str)].filter((x): x is string => !!x);
    const open = [...new Set(ports.flatMap(adminPortsIn))];
    for (const port of open) hits.push(`${String(rule.name ?? "?")}:${port}`);
  }
  return hits;
}

export async function subscriptionChecks(t: AzureTransport, sub: string, o: AzureOptions): Promise<Results<AzureCheck>["results"]> {
  const out = new Results<AzureCheck>("azure");
  const S = `${ARM}/subscriptions/${encodeURIComponent(sub)}`;
  const subRes = `subscription ${sub}`;

  await defenderPlans(t, S, subRes, out);

  // Secure score: the ascScore item.
  const sc = await listAll(t, `${S}/providers/Microsoft.Security/secureScores?api-version=${API.secureScores}`);
  if ("error" in sc) out.skip("secure_score", subRes, `secure score not readable: ${why(sc.error)}`);
  else {
    const asc = sc.items.find((x) => x.name === "ascScore");
    const score = asc && isObj(asc.properties) && isObj(asc.properties.score) ? asc.properties.score : undefined;
    const ratio = score ? Number(score.percentage) : NaN;
    if (!Number.isFinite(ratio)) out.skip("secure_score", subRes, "the API returned no ascScore percentage (Defender for Cloud may not be on for this subscription)");
    else {
      const pct = Math.round(ratio * 10000) / 100;
      out.add("secure_score", subRes, pct >= o.minSecureScore ? "pass" : "fail",
        `secure score ${pct}% (current ${String(score!.current)} of max ${String(score!.max)}); at least ${o.minSecureScore}% required (--azure-min-secure-score)`);
    }
  }

  // Activity log export: a subscription diagnostic setting with a destination and administrative events.
  const ds = await armGet(t, `${S}/providers/Microsoft.Insights/diagnosticSettings?api-version=${API.diagnosticSettings}`);
  if (!okStatus(ds.status) || !isObj(ds.json) || !Array.isArray(ds.json.value)) out.skip("activity_log_export", subRes, `diagnostic settings not readable: ${why(ds)}`);
  else {
    const settings = (ds.json.value as unknown[]).filter(isObj);
    const good = settings.filter((s) => {
      const p = isObj(s.properties) ? s.properties : {};
      const dest = ["workspaceId", "storageAccountId", "eventHubAuthorizationRuleId", "serviceBusRuleId", "marketplacePartnerId"].filter((k) => str(p[k]));
      const admin = arr(p.logs).filter(isObj).some((l) => l.enabled === true && (l.category === "Administrative" || l.categoryGroup === "allLogs"));
      return dest.length > 0 && admin;
    });
    out.add("activity_log_export", subRes, good.length ? "pass" : "fail",
      `${settings.length} subscription diagnostic setting(s), ${good.length} export Administrative events to a workspace, storage account, event hub or partner${good.length ? ` (${good.slice(0, 5).map((s) => j(s.name)).join(", ")})` : ""}; at least one required`);
  }

  // Key Vault: soft delete and purge protection, per vault.
  const kv = await listAll(t, `${S}/providers/Microsoft.KeyVault/vaults?api-version=${API.keyVaults}`);
  if ("error" in kv) out.skip("keyvault_recoverable", subRes, `key vaults not readable: ${why(kv.error)}`);
  else if (!kv.items.length) out.skip("keyvault_recoverable", subRes, "the subscription has no key vault");
  else for (const v of kv.items) {
    const p = isObj(v.properties) ? v.properties : {};
    const soft = p.enableSoftDelete === undefined ? "not returned (Azure's documented default is true)" : j(p.enableSoftDelete);
    const softOn = p.enableSoftDelete !== false;
    const purge = p.enablePurgeProtection === true;
    out.add("keyvault_recoverable", `key vault ${rgName(v.id, v.name)}`, softOn && purge ? "pass" : "fail",
      `enableSoftDelete ${soft}, enablePurgeProtection ${j(p.enablePurgeProtection ?? null)}; both true required`);
  }

  // Storage accounts: three settings per account.
  const st = await listAll(t, `${S}/providers/Microsoft.Storage/storageAccounts?api-version=${API.storage}`);
  const stChecks: AzureCheck[] = ["storage_secure_transfer", "storage_no_public_blob", "storage_min_tls"];
  if ("error" in st) out.skipAll(stChecks, subRes, `storage accounts not readable: ${why(st.error)}`);
  else if (!st.items.length) out.skipAll(stChecks, subRes, "the subscription has no storage account");
  else for (const a of st.items) {
    const p = isObj(a.properties) ? a.properties : {};
    const res = `storage account ${rgName(a.id, a.name)}`;
    const https = p.supportsHttpsTrafficOnly;
    out.add("storage_secure_transfer", res, https === false ? "fail" : https === true ? "pass" : "fail",
      `supportsHttpsTrafficOnly is ${j(https ?? null)}; true required`);
    const pub = p.allowBlobPublicAccess;
    out.add("storage_no_public_blob", res, pub === true ? "fail" : "pass",
      `allowBlobPublicAccess is ${pub === undefined ? "not set (Azure reads that as false)" : j(pub)}; false required`);
    const tls = p.minimumTlsVersion;
    out.add("storage_min_tls", res, TLS_OK.has(String(tls)) ? "pass" : "fail",
      `minimumTlsVersion is ${tls === undefined ? "not set (Azure reads that as TLS 1.0)" : j(tls)}; TLS1_2 or higher required`);
  }

  await sqlTde(t, S, subRes, out);
  await sqlFirewall(t, S, subRes, out);
  await vmPatches(t, S, subRes, out, o.now);

  // NSGs: inbound Allow from the Internet to 22 or 3389, per NSG.
  const ns = await listAll(t, `${S}/providers/Microsoft.Network/networkSecurityGroups?api-version=${API.network}`);
  if ("error" in ns) out.skip("nsg_no_open_admin_ports", subRes, `network security groups not readable: ${why(ns.error)}`);
  else if (!ns.items.length) out.skip("nsg_no_open_admin_ports", subRes, "the subscription has no network security group");
  else for (const g of ns.items) {
    const hits = openAdminRules(g);
    const n = isObj(g.properties) ? arr(g.properties.securityRules).length : 0;
    out.add("nsg_no_open_admin_ports", `nsg ${rgName(g.id, g.name)}`, hits.length ? "fail" : "pass",
      `${n} custom rule(s); ${hits.length ? `inbound Allow from the Internet on ${hits.slice(0, 10).join(", ")}` : "none allows 22 or 3389 from the Internet"}; none required`);
  }

  // Azure Policy: assignments that apply to the subscription.
  const pa = await listAll(t, `${S}/providers/Microsoft.Authorization/policyAssignments?api-version=${API.policy}`);
  if ("error" in pa) out.skip("policy_assignments", subRes, `policy assignments not readable: ${why(pa.error)}`);
  else {
    const modes = pa.items.map((x) => (isObj(x.properties) ? String(x.properties.enforcementMode ?? "Default") : "Default"));
    const enforced = modes.filter((m) => m === "Default").length;
    out.add("policy_assignments", subRes, pa.items.length ? "pass" : "fail",
      `${pa.items.length} policy assignment(s) apply to the subscription (${enforced} with enforcementMode Default); at least one required`);
  }

  // Managed disks: encrypted at rest (platform or customer key) or Azure Disk Encryption on.
  const dk = await listAll(t, `${S}/providers/Microsoft.Compute/disks?api-version=${API.disks}`);
  if ("error" in dk) out.skip("disk_encryption", subRes, `managed disks not readable: ${why(dk.error)}`);
  else if (!dk.items.length) out.skip("disk_encryption", subRes, "the subscription has no managed disk");
  else for (const d of dk.items) {
    const p = isObj(d.properties) ? d.properties : {};
    const type = isObj(p.encryption) ? str(p.encryption.type) : undefined;
    const ade = isObj(p.encryptionSettingsCollection) && p.encryptionSettingsCollection.enabled === true;
    const ok = (type !== undefined && DISK_ENCRYPTION_TYPES.has(type)) || ade;
    out.add("disk_encryption", `disk ${rgName(d.id, d.name)}`, ok ? "pass" : "fail",
      `encryption.type ${j(type ?? null)}, Azure Disk Encryption ${ade ? "on" : "off"}; encryption at rest required`);
  }

  // Recovery Services vaults: at least one protected item each; no vault at all fails.
  const rv = await listAll(t, `${S}/providers/Microsoft.RecoveryServices/vaults?api-version=${API.recoveryServices}`);
  if ("error" in rv) out.skip("backup_protected_items", subRes, `Recovery Services vaults not readable: ${why(rv.error)}`);
  else if (!rv.items.length) out.add("backup_protected_items", subRes, "fail", "the subscription has no Recovery Services vault, so nothing is backed up by Azure Backup; a vault with protected items required");
  else for (const v of rv.items) {
    const res = `recovery vault ${rgName(v.id, v.name)}`;
    if (typeof v.id !== "string") { out.skip("backup_protected_items", res, "the vault has no id"); continue; }
    const items = await listAll(t, `${ARM}${v.id}/backupProtectedItems?api-version=${API.backup}`);
    if ("error" in items) { out.skip("backup_protected_items", res, `protected items not readable: ${why(items.error)}`); continue; }
    out.add("backup_protected_items", res, items.items.length ? "pass" : "fail", `${items.items.length} protected item(s); at least one required`);
  }

  return out.results;
}

async function sqlTde(t: AzureTransport, S: string, subRes: string, out: Results<AzureCheck>): Promise<void> {
  const servers = await listAll(t, `${S}/providers/Microsoft.Sql/servers?api-version=${API.sql}`);
  if ("error" in servers) return out.skip("sql_tde", subRes, `SQL servers not readable: ${why(servers.error)}`);
  let judged = 0;
  for (const s of servers.items) {
    if (typeof s.id !== "string") continue;
    const dbs = await listAll(t, `${ARM}${s.id}/databases?api-version=${API.sql}`);
    if ("error" in dbs) { out.skip("sql_tde", `sql server ${rgName(s.id, s.name)}`, `databases not readable: ${why(dbs.error)}`); judged++; continue; }
    for (const d of dbs.items.filter((x) => x.name !== "master" && typeof x.id === "string")) {
      judged++;
      const res = `sql database ${rgName(s.id, s.name)}/${String(d.name)}`;
      const r = await armGet(t, `${ARM}${String(d.id)}/transparentDataEncryption/current?api-version=${API.sql}`);
      const state = isObj(r.json) && isObj(r.json.properties) ? r.json.properties.state : undefined;
      if (!okStatus(r.status) || state === undefined) { out.skip("sql_tde", res, `TDE state not readable: ${why(r)}`); continue; }
      out.add("sql_tde", res, state === "Enabled" ? "pass" : "fail", `transparent data encryption state is ${j(state)}; "Enabled" required`);
    }
  }
  if (!judged) out.skip("sql_tde", subRes, "the subscription has no Azure SQL database (master excluded)");
}

/** True for a dotted IPv4 address (no range check beyond 0 to 255 per part). */
const ipv4 = (s: unknown): number | undefined => {
  const m = typeof s === "string" ? /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s.trim()) : null;
  if (!m || m.slice(1).some((x) => Number(x) > 255)) return undefined;
  return m.slice(1).reduce((n, x) => n * 256 + Number(x), 0);
};
/** Rules wider than this many addresses are "open to the internet" (a /8 holds 16,777,216). */
export const MAX_SQL_RULE_ADDRESSES = 16_777_216;

// Azure SQL server-level IP firewall rules. "Azure SQL Database and Azure Synapse IP firewall rules"
// (learn.microsoft.com/azure/azure-sql/database/firewall-configure, read 2026-10-26): a rule from 0.0.0.0 to 0.0.0.0 is
// "Allow Azure Services and resources to access this server" (AllowAllWindowsAzureIps), reported and not failed. "Azure
// SQL connectivity settings" (learn.microsoft.com/azure/azure-sql/database/connectivity-settings, read 2026-10-26):
// "When Public network access is set to Disable, only connections from private endpoints are allowed", so the rules do
// not apply then. Firewall Rules - List By Server (learn.microsoft.com/rest/api/sql/firewall-rules/list-by-server,
// read 2026-10-26): properties.startIpAddress and endIpAddress.
async function sqlFirewall(t: AzureTransport, S: string, subRes: string, out: Results<AzureCheck>): Promise<void> {
  const servers = await listAll(t, `${S}/providers/Microsoft.Sql/servers?api-version=${API.sql}`);
  if ("error" in servers) return out.skip("sql_firewall_not_open", subRes, `SQL servers not readable: ${why(servers.error)}`);
  const list = servers.items.filter((s) => typeof s.id === "string");
  if (!list.length) return out.skip("sql_firewall_not_open", subRes, "the subscription has no Azure SQL logical server");
  for (const s of list) {
    const res = `sql server ${rgName(s.id, s.name)}`;
    const pna = isObj(s.properties) ? str(s.properties.publicNetworkAccess) : undefined;
    if (pna === "Disabled") { out.add("sql_firewall_not_open", res, "pass", `publicNetworkAccess is "Disabled": only private endpoints connect, so IP firewall rules do not apply`); continue; }
    const fw = await listAll(t, `${ARM}${String(s.id)}/firewallRules?api-version=${API.sql}`);
    if ("error" in fw) { out.skip("sql_firewall_not_open", res, `firewall rules not readable: ${why(fw.error)}`); continue; }
    const wide: string[] = [];
    let azure = false;
    for (const r of fw.items) {
      const p = isObj(r.properties) ? r.properties : {};
      const a = ipv4(p.startIpAddress), b = ipv4(p.endIpAddress);
      if (a === undefined || b === undefined) continue;
      if (a === 0 && b === 0) { azure = true; continue; }
      if (b - a + 1 > MAX_SQL_RULE_ADDRESSES) wide.push(`${String(r.name ?? "?")} ${String(p.startIpAddress)}-${String(p.endIpAddress)}`);
    }
    out.add("sql_firewall_not_open", res, wide.length ? "fail" : "pass",
      `publicNetworkAccess ${j(pna ?? null)}; ${fw.items.length} firewall rule(s)${azure ? ", including Allow Azure services (0.0.0.0, which also admits services in other customers' subscriptions)" : ""}; ${wide.length ? `wider than a /8: ${wide.slice(0, 10).join(", ")}` : "none wider than a /8"}; no rule wider than ${MAX_SQL_RULE_ADDRESSES.toLocaleString("en-US")} addresses allowed`);
  }
}

// Each running VM's last patch assessment. Virtual Machines - Instance View (learn.microsoft.com/rest/api/compute/
// virtual-machines/instance-view, api-version 2026-04-01, read 2026-10-26): statuses[] carries "PowerState/running";
// patchStatus.availablePatchSummary has status (InProgress, Unknown, Failed, Succeeded, CompletedWithWarnings),
// criticalAndSecurityPatchCount ("critical or security patches that have been detected as available and not yet
// installed"), otherPatchCount and lastModifiedTime. Azure Update Manager's periodic assessment "fetch[es] latest updates
// for your machines every 24 hours" (learn.microsoft.com/azure/update-manager/assessment-options, read 2026-10-26), so
// an assessment older than MAX_ASSESSMENT_DAYS, or none, shows nothing about the VM today. The patch mode
// (osProfile.windowsConfiguration / linuxConfiguration .patchSettings.patchMode, Virtual Machines - List All) is reported.
async function vmPatches(t: AzureTransport, S: string, subRes: string, out: Results<AzureCheck>, now: Date): Promise<void> {
  const vms = await listAll(t, `${S}/providers/Microsoft.Compute/virtualMachines?api-version=${API.compute}`);
  if ("error" in vms) return out.skip("vm_patches_current", subRes, `virtual machines not readable: ${why(vms.error)}`);
  const list = vms.items.filter((v) => typeof v.id === "string");
  if (!list.length) return out.skip("vm_patches_current", subRes, "the subscription has no virtual machine");
  for (const v of list) {
    const res = `vm ${rgName(v.id, v.name)}`;
    const os = isObj(v.properties) && isObj(v.properties.osProfile) ? v.properties.osProfile : {};
    const cfg = isObj(os.windowsConfiguration) ? os.windowsConfiguration : isObj(os.linuxConfiguration) ? os.linuxConfiguration : {};
    const mode = isObj(cfg.patchSettings) ? str(cfg.patchSettings.patchMode) : undefined;
    const iv = await armGet(t, `${ARM}${String(v.id)}/instanceView?api-version=${API.compute}`);
    if (!okStatus(iv.status) || !isObj(iv.json)) { out.skip("vm_patches_current", res, `instance view not readable: ${why(iv)}`); continue; }
    const power = arr(iv.json.statuses).filter(isObj).map((s) => String(s.code ?? "")).find((c) => c.startsWith("PowerState/"));
    if (power !== "PowerState/running") { out.add("vm_patches_current", res, "skipped", `${power ?? "power state not reported"}: only running VMs are assessed`); continue; }
    const sum = isObj(iv.json.patchStatus) && isObj(iv.json.patchStatus.availablePatchSummary) ? iv.json.patchStatus.availablePatchSummary : undefined;
    const head = `patchMode ${j(mode ?? null)}`;
    if (!sum) { out.add("vm_patches_current", res, "fail", `${head}; no patch assessment reported for the VM; a recent assessment with 0 critical or security patches pending required`); continue; }
    const st = str(sum.status), crit = Number(sum.criticalAndSecurityPatchCount ?? NaN), age = ageDays(str(sum.lastModifiedTime), now);
    const seen = `${head}; last assessment ${st ?? "status unknown"}${age === undefined ? "" : ` ${Math.floor(age)} day(s) ago`}, ${Number.isFinite(crit) ? crit : "?"} critical or security patch(es) pending, ${String(sum.otherPatchCount ?? "?")} other`;
    if (st === "InProgress") { out.add("vm_patches_current", res, "skipped", `${seen}; the assessment is still running`); continue; }
    const fresh = age !== undefined && age <= MAX_ASSESSMENT_DAYS && (st === "Succeeded" || st === "CompletedWithWarnings");
    out.add("vm_patches_current", res, fresh && crit === 0 ? "pass" : "fail",
      `${seen}; an assessment that succeeded within ${MAX_ASSESSMENT_DAYS} days with 0 critical or security patches pending required`);
  }
}
