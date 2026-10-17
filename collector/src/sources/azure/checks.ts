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

import { ADMIN_PORTS, Results, arr, isObj, j, rangeHits, str, httpWhy, type Obj } from "../shared-cloud.ts";
import { API, ARM, armGet, armMessage, listAll, okStatus, rgName, type ArmReply, type AzureTransport } from "./api.ts";

export const AZURE_CHECKS = [
  "defender_plans", "secure_score", "activity_log_export", "keyvault_recoverable",
  "storage_secure_transfer", "storage_no_public_blob", "storage_min_tls", "sql_tde",
  "nsg_no_open_admin_ports", "policy_assignments", "disk_encryption", "backup_protected_items",
] as const;
export type AzureCheck = (typeof AZURE_CHECKS)[number];

const why = (r: ArmReply) => httpWhy(r.reply, armMessage(r));

/** Source prefixes NSG treats as "anyone on the Internet". */
const OPEN_SOURCES = new Set(["*", "internet", "any", "0.0.0.0/0", "0.0.0.0", "::/0"]);
const TLS_OK = new Set(["TLS1_2", "TLS1_3"]);
const DISK_ENCRYPTION_TYPES = new Set(["EncryptionAtRestWithPlatformKey", "EncryptionAtRestWithCustomerKey", "EncryptionAtRestWithPlatformAndCustomerKeys"]);

export interface AzureOptions { minSecureScore: number }

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

  // Defender for Cloud plans: one result per plan that is not deprecated.
  const pr = await listAll(t, `${S}/providers/Microsoft.Security/pricings?api-version=${API.pricings}`);
  if ("error" in pr) out.skip("defender_plans", subRes, `Defender for Cloud plans not readable: ${why(pr.error)}`);
  else {
    const plans = pr.items.filter((p) => !(isObj(p.properties) && p.properties.deprecated === true));
    if (!plans.length) out.skip("defender_plans", subRes, "the API listed no current Defender for Cloud plan");
    for (const p of plans) {
      const tier = isObj(p.properties) ? p.properties.pricingTier : undefined;
      out.add("defender_plans", `defender plan ${String(p.name)} (${subRes})`, tier === "Standard" ? "pass" : "fail", `pricingTier is ${j(tier)}; "Standard" required`);
    }
  }

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
