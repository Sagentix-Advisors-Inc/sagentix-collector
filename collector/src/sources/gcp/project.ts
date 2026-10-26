// Per-project checks over Google Cloud REST APIs (GET, plus POST :getIamPolicy and :getAncestry). One result per
// resource; a refused call gives "skipped", never "pass"; nothing to judge gives "skipped".
//
// Calls and the role that grants each (Google's predefined roles):
//   POST cloudresourcemanager v1 projects/{p}:getIamPolicy             roles/iam.securityReviewer (resourcemanager.projects.getIamPolicy)
//   POST cloudresourcemanager v1 projects/{p}:getAncestry              roles/viewer (resourcemanager.projects.get),
//        then POST v3 folders/{f}|organizations/{o}:getIamPolicy       roles/iam.securityReviewer granted on the ORGANIZATION
//        (inherited by its folders; resourcemanager.folders.getIamPolicy, .organizations.getIamPolicy); only when the
//        project's own auditConfigs fall short of data_access_audit_logs
//   GET  compute v1 projects/{p}/aggregated/instances                  roles/viewer (compute.instances.list)
//   GET  osconfig v1 projects/{p}/locations/{zone}/instances/-/vulnerabilityReports
//                                                                      roles/osconfig.vulnerabilityReportViewer (osconfig.vulnerabilityReports.list)
//   GET  orgpolicy v2 projects/{p}/policies/{c}:getEffectivePolicy      roles/viewer (orgpolicy.policy.get)
//   GET  iam v1 projects/{p}/serviceAccounts, …/keys?keyTypes=USER_MANAGED   roles/viewer (iam.serviceAccounts.list, iam.serviceAccountKeys.list)
//   GET  storage v1 b?project={p}                                      roles/viewer (storage.buckets.list)
//   GET  storage v1 b/{bucket}/iam                                     roles/iam.securityReviewer (storage.buckets.getIamPolicy)
//   GET  sqladmin v1 projects/{p}/instances                            roles/viewer (cloudsql.instances.list)
//   GET  compute v1 projects/{p}/global/firewalls                      roles/viewer (compute.firewalls.list)
//   GET  compute v1 projects/{p}/aggregated/subnetworks                roles/viewer (compute.subnetworks.list)
//   GET  serviceusage v1 projects/{p}/services/securitycenter.googleapis.com   roles/viewer (serviceusage.services.get)
//   GET  cloudkms v1 projects/{p}/locations, …/keyRings, …/cryptoKeys  roles/viewer (cloudkms.keyRings.list, cloudkms.cryptoKeys.list)

import { ADMIN_PORTS, Results, ageDays, arr, isObj, j, rangeHits, str, type Obj } from "../shared-cloud.ts";
import { Gcp, gWhy, okStatus, type GcpReply } from "./api.ts";

export const GCP_CHECKS = [
  "data_access_audit_logs", "org_policy_enforced", "sa_keys_rotated", "bucket_not_public",
  "cloudsql_no_public_ip", "cloudsql_ssl_required", "firewall_no_open_admin_ports", "scc_api_enabled",
  "kms_rotation", "vpc_flow_logs", "vm_os_vulnerabilities",
] as const;
export type GcpCheck = (typeof GCP_CHECKS)[number];
/** Oldest a VM's OS Config vulnerability report may be. */
export const MAX_VULN_REPORT_DAYS = 7;
/** Upgradable-CVE severities that fail a VM: a fix is published and not installed. */
export const FAIL_SEVERITIES = new Set(["HIGH", "CRITICAL"]);

export const DEFAULT_ORG_CONSTRAINTS = ["iam.disableServiceAccountKeyCreation", "storage.publicAccessPrevention"];
export const DEFAULT_KEY_MAX_AGE_DAYS = 90;
export const MAX_KMS_ROTATION_SECONDS = 365 * 86_400;

const CRM = "https://cloudresourcemanager.googleapis.com/v1";
const CRM3 = "https://cloudresourcemanager.googleapis.com/v3";
const NETMGMT = "https://networkmanagement.googleapis.com/v1";
const ORGPOLICY = "https://orgpolicy.googleapis.com/v2";
const IAM = "https://iam.googleapis.com/v1";
const STORAGE = "https://storage.googleapis.com/storage/v1";
const SQL = "https://sqladmin.googleapis.com/v1";
const COMPUTE = "https://compute.googleapis.com/compute/v1";
const SERVICEUSAGE = "https://serviceusage.googleapis.com/v1";
const KMS = "https://cloudkms.googleapis.com/v1";
const OSCONFIG = "https://osconfig.googleapis.com/v1";

const enc = encodeURIComponent;
const OPEN = new Set(["0.0.0.0/0", "::/0"]);
const PUBLIC_MEMBERS = new Set(["allUsers", "allAuthenticatedUsers"]);

export interface ProjectOptions { orgConstraints: string[]; keyMaxAgeDays: number; now: Date }

type Out = Results<GcpCheck>;
const skipFor = (out: Out, check: GcpCheck, resource: string, what: string, r: GcpReply) =>
  out.skip(check, resource, `${what} not readable: ${gWhy(r)}`);

/** The log types of an IAM policy's allServices auditConfig. */
const allServicesTypes = (policy: unknown): string[] => {
  const all = arr(isObj(policy) ? policy.auditConfigs : undefined).filter(isObj).find((c) => c.service === "allServices");
  return all ? arr(all.auditLogConfigs).filter(isObj).map((c) => String(c.logType)) : [];
};

/**
 * The folders and organization above a project, nearest first ("folders/1", "organizations/2"). Resource Manager v1
 * projects.getAncestry (POST, a read; discovery revision 20261018, read 2026-10-26): "Ancestors are ordered from bottom
 * to top of the resource hierarchy. The first ancestor is the project itself", each a resourceId { type ("organization",
 * "folder", "project"), id }. It needs only resourcemanager.projects.get on the project (roles/viewer there), where
 * walking up with folders.get would need a role on every folder: roles/iam.securityReviewer has no folders.get
 * (IAM roles reference, roles-permissions/iam, last updated 2026-10-22, read 2026-10-26).
 */
async function ancestors(api: Gcp, project: string): Promise<{ names: string[]; error?: string }> {
  const r = await api.call("POST", `${CRM}/projects/${enc(project)}:getAncestry`, {});
  if (!okStatus(r)) return { names: [], error: `the project's ancestry not readable: ${gWhy(r)}` };
  const names = arr((r.json as Obj).ancestor).filter(isObj).map((a) => (isObj(a.resourceId) ? a.resourceId : {}))
    .map((id) => (id.type === "folder" ? `folders/${String(id.id)}` : id.type === "organization" ? `organizations/${String(id.id)}` : ""))
    .filter((n) => /^(folders|organizations)\/\d+$/.test(n));
  return { names };
}

export async function projectChecks(api: Gcp, project: string, o: ProjectOptions, out: Out): Promise<void> {
  const pr = `project ${project}`;
  const p = `projects/${enc(project)}`;

  // Data Access audit logs: auditConfigs for allServices. Bindings and members are read, never reported.
  const pol = await api.call("POST", `${CRM}/${p}:getIamPolicy`, { options: { requestedPolicyVersion: 3 } });
  if (!okStatus(pol)) skipFor(out, "data_access_audit_logs", pr, "the project IAM policy", pol);
  else {
    const cfgs = arr((pol.json as Obj).auditConfigs).filter(isObj);
    const types = new Set(allServicesTypes(pol.json));
    const has = () => types.has("DATA_READ") && types.has("DATA_WRITE");
    // Google's "Enable Data Access audit logs" (cloud.google.com/logging/docs/audit/configure-data-access, last
    // updated 2026-10-22, read 2026-10-26): "You can configure Data Access audit logs for Google Cloud projects,
    // billing accounts, folders, and organizations. If there is a configuration for a Google Cloud service across the
    // hierarchy, then the resulting configuration is the union of the configurations." So when the project alone
    // falls short, its folders and organization are read too (GET v3 projects/folders for the parent, POST
    // :getIamPolicy on each; roles/iam.securityReviewer there). An ancestor that cannot be read leaves "skipped".
    const from: string[] = [];
    let unread: string | undefined;
    if (!has()) {
      const anc = await ancestors(api, project);
      for (const a of anc.names) {
        const r = await api.call("POST", `${CRM3}/${a}:getIamPolicy`, { options: { requestedPolicyVersion: 3 } });
        if (!okStatus(r)) { unread = `${a} IAM policy not readable: ${gWhy(r)}`; break; }
        const t = allServicesTypes(r.json);
        if (t.some((x) => !types.has(x))) from.push(a);
        for (const x of t) types.add(x);
        if (has()) break;
      }
      if (!unread && anc.error) unread = anc.error;
    }
    const shown = [...types];
    const detail = `allServices audit log types${from.length ? ` (project with ${from.join(", ")})` : ""}: ${shown.length ? shown.join(", ") : "none configured"}; ${cfgs.length} auditConfig(s) on the project; DATA_READ and DATA_WRITE for allServices, on the project or an ancestor, required`;
    if (has()) out.add("data_access_audit_logs", pr, "pass", detail);
    else if (unread) out.add("data_access_audit_logs", pr, "skipped", `${detail}; ${unread}, so a folder or organization setting cannot be ruled out`);
    else out.add("data_access_audit_logs", pr, "fail", detail);
  }

  for (const c of o.orgConstraints) {
    const res = `${pr} constraint ${c}`;
    const r = await api.get(`${ORGPOLICY}/${p}/policies/${enc(c)}:getEffectivePolicy`);
    if (!okStatus(r)) { skipFor(out, "org_policy_enforced", res, "the effective policy", r); continue; }
    const rules = isObj((r.json as Obj).spec) ? arr(((r.json as Obj).spec as Obj).rules).filter(isObj) : [];
    const enforced = rules.some((x) => x.enforce === true);
    out.add("org_policy_enforced", res, enforced ? "pass" : "fail",
      `effective policy has ${rules.length} rule(s), enforce ${enforced ? "true" : "not true"}; enforce true required`);
  }

  await serviceAccountKeys(api, project, o, out);
  await buckets(api, project, out);
  await cloudSql(api, project, out);
  await firewalls(api, project, out);

  const su = await api.get(`${SERVICEUSAGE}/${p}/services/securitycenter.googleapis.com`);
  if (!okStatus(su)) skipFor(out, "scc_api_enabled", pr, "the securitycenter.googleapis.com service", su);
  else {
    const state = (su.json as Obj).state;
    out.add("scc_api_enabled", pr, state === "ENABLED" ? "pass" : "fail",
      `securitycenter.googleapis.com state is ${j(state)}; ENABLED required (the API being on does not show which Security Command Center tier is active)`);
  }

  await kms(api, project, out);
  await subnets(api, project, out);
  await vmVulnerabilities(api, project, o.now, out);
}

// Each running Compute Engine VM against its OS Config vulnerability report. OS Config API v1 (discovery revision
// 20261015, read 2026-10-26): projects.locations.instances.vulnerabilityReports.list, parent
// "projects/{project}/locations/{location}/instances/-"; a VulnerabilityReport has name ".../instances/{instance_id}/
// vulnerabilityReport", highestUpgradableCveSeverity ("Highest level of severity among all the upgradable
// vulnerabilities with CVEs attached": NONE, MINIMAL, LOW, MEDIUM, HIGH, CRITICAL), vulnerabilities[] and updateTime
// ("when the last vulnerability report was generated for the VM"). Permission osconfig.vulnerabilityReports.list, in
// roles/osconfig.vulnerabilityReportViewer, whose only other permissions are resourcemanager.projects.get and .list (IAM
// roles reference, roles-permissions/osconfig, last updated 2026-10-22, read 2026-10-26). Running VMs come from compute
// v1 aggregated/instances (status RUNNING; discovery revision 20261016). A VM with no report has no OS Config agent
// reporting (or VM Manager is off), so nothing shows its patches; an API switched off for the project gives the same.
async function vmVulnerabilities(api: Gcp, project: string, now: Date, out: Out): Promise<void> {
  const pr = `project ${project}`;
  const ag = await api.getAll(`${COMPUTE}/projects/${enc(project)}/aggregated/instances?maxResults=500`, "items");
  if ("error" in ag) return skipFor(out, "vm_os_vulnerabilities", pr, "Compute Engine instances", ag.error);
  const vms: { id: string; name: string; zone: string }[] = [];
  for (const page of ag.items.filter(isObj)) for (const scoped of Object.values(page).filter(isObj)) {
    for (const i of arr(scoped.instances).filter(isObj)) {
      if (i.status !== "RUNNING") continue;
      vms.push({ id: String(i.id ?? ""), name: String(i.name ?? "?"), zone: String(i.zone ?? "").split("/").pop() ?? "" });
    }
  }
  if (!vms.length) return out.skip("vm_os_vulnerabilities", pr, "the project has no running Compute Engine instance");
  const reports = new Map<string, Obj>();
  const zoneErr = new Map<string, string>();
  let disabled: string | undefined;
  for (const zone of [...new Set(vms.map((v) => v.zone))]) {
    const r = await api.getAll(`${OSCONFIG}/projects/${enc(project)}/locations/${enc(zone)}/instances/-/vulnerabilityReports?pageSize=100`, "vulnerabilityReports");
    if ("error" in r) {
      const w = gWhy(r.error);
      if (/SERVICE_DISABLED|has not been used|is disabled/i.test(w)) { disabled = w; continue; }
      zoneErr.set(zone, w);
      continue;
    }
    for (const rep of r.items.filter(isObj)) {
      const m = /\/instances\/([^/]+)\/vulnerabilityReport$/.exec(String(rep.name ?? ""));
      if (m) reports.set(m[1], rep);
    }
  }
  for (const v of vms) {
    const res = `instance ${project}/${v.zone}/${v.name}`;
    if (zoneErr.has(v.zone)) { out.skip("vm_os_vulnerabilities", res, `vulnerability reports not readable: ${zoneErr.get(v.zone)}`); continue; }
    const rep = reports.get(v.id);
    if (!rep) {
      out.add("vm_os_vulnerabilities", res, "fail", disabled
        ? "the OS Config API is off for the project, so no vulnerability report exists for the VM; VM Manager with a recent report and no HIGH or CRITICAL upgradable CVE required"
        : "running, but OS Config has no vulnerability report for it (no OS Config agent reporting, or VM Manager off); a recent report with no HIGH or CRITICAL upgradable CVE required");
      continue;
    }
    const sev = str(rep.highestUpgradableCveSeverity) ?? "VULNERABILITY_SEVERITY_LEVEL_UNSPECIFIED";
    const age = ageDays(str(rep.updateTime), now);
    const fresh = age !== undefined && age <= MAX_VULN_REPORT_DAYS;
    out.add("vm_os_vulnerabilities", res, fresh && !FAIL_SEVERITIES.has(sev) ? "pass" : "fail",
      `highestUpgradableCveSeverity ${sev}, ${arr(rep.vulnerabilities).length} vulnerabilit(ies) listed, report ${age === undefined ? "undated" : `${Math.floor(age)} day(s) old`}; a report within ${MAX_VULN_REPORT_DAYS} days with no HIGH or CRITICAL upgradable CVE required`);
  }
}

async function serviceAccountKeys(api: Gcp, project: string, o: ProjectOptions, out: Out): Promise<void> {
  const pr = `project ${project}`;
  const sas = await api.getAll(`${IAM}/projects/${enc(project)}/serviceAccounts?pageSize=100`, "accounts");
  if ("error" in sas) return skipFor(out, "sa_keys_rotated", pr, "service accounts", sas.error);
  const list = sas.items.filter(isObj);
  if (!list.length) return out.skip("sa_keys_rotated", pr, "the project has no service account");
  for (const sa of list) {
    const email = str(sa.email) ?? String(sa.uniqueId ?? "?");
    const res = `service account ${email}`;
    const k = await api.get(`${IAM}/projects/${enc(project)}/serviceAccounts/${enc(email)}/keys?keyTypes=USER_MANAGED`);
    if (!okStatus(k)) { skipFor(out, "sa_keys_rotated", res, "the account's keys", k); continue; }
    const keys = arr((k.json as Obj).keys).filter(isObj).filter((x) => x.disabled !== true);
    const ages = keys.map((x) => ageDays(str(x.validAfterTime), o.now));
    const old = ages.filter((a) => a === undefined || a > o.keyMaxAgeDays);
    const oldest = Math.max(0, ...ages.filter((a): a is number => a !== undefined));
    out.add("sa_keys_rotated", res, old.length ? "fail" : "pass",
      keys.length
        ? `${keys.length} enabled user-managed key(s), oldest ${Math.floor(oldest)} day(s), ${old.length} older than ${o.keyMaxAgeDays} days or undated; none older allowed`
        : "no enabled user-managed key");
  }
}

async function buckets(api: Gcp, project: string, out: Out): Promise<void> {
  const pr = `project ${project}`;
  const b = await api.getAll(`${STORAGE}/b?project=${enc(project)}&maxResults=500`, "items");
  if ("error" in b) return skipFor(out, "bucket_not_public", pr, "buckets", b.error);
  const list = b.items.filter(isObj);
  if (!list.length) return out.skip("bucket_not_public", pr, "the project has no Cloud Storage bucket");
  for (const x of list) {
    const name = String(x.name ?? "?");
    const res = `bucket ${name}`;
    const pap = isObj(x.iamConfiguration) ? str(x.iamConfiguration.publicAccessPrevention) : undefined;
    if (pap === "enforced") { out.add("bucket_not_public", res, "pass", `publicAccessPrevention is "enforced"`); continue; }
    const iam = await api.get(`${STORAGE}/b/${enc(name)}/iam`);
    if (!okStatus(iam)) { skipFor(out, "bucket_not_public", res, "the bucket IAM policy", iam); continue; }
    const roles = arr((iam.json as Obj).bindings).filter(isObj)
      .filter((bd) => arr(bd.members).some((m) => PUBLIC_MEMBERS.has(String(m)))).map((bd) => String(bd.role));
    out.add("bucket_not_public", res, roles.length ? "fail" : "pass",
      `publicAccessPrevention is ${j(pap ?? "unset")}; ${roles.length} role binding(s) grant allUsers or allAuthenticatedUsers${roles.length ? ` (${roles.slice(0, 10).join(", ")})` : ""}; none allowed`);
  }
}

async function cloudSql(api: Gcp, project: string, out: Out): Promise<void> {
  const pr = `project ${project}`;
  const s = await api.getAll(`${SQL}/projects/${enc(project)}/instances`, "items");
  if ("error" in s) {
    skipFor(out, "cloudsql_no_public_ip", pr, "Cloud SQL instances", s.error);
    return skipFor(out, "cloudsql_ssl_required", pr, "Cloud SQL instances", s.error);
  }
  const list = s.items.filter(isObj);
  if (!list.length) {
    out.skip("cloudsql_no_public_ip", pr, "the project has no Cloud SQL instance");
    return out.skip("cloudsql_ssl_required", pr, "the project has no Cloud SQL instance");
  }
  for (const i of list) {
    const res = `cloudsql instance ${project}/${String(i.name ?? "?")}`;
    const ip = isObj(i.settings) && isObj(i.settings.ipConfiguration) ? i.settings.ipConfiguration : {};
    const nets = arr(ip.authorizedNetworks).length;
    out.add("cloudsql_no_public_ip", res, ip.ipv4Enabled === false ? "pass" : "fail",
      `ipv4Enabled is ${j(ip.ipv4Enabled)}, ${nets} authorized network(s); false required`);
    // sslMode takes priority over the older requireSsl flag (Cloud SQL Admin API v1, IpConfiguration).
    const mode = str(ip.sslMode);
    const enforced = mode ? ["ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"].includes(mode) : ip.requireSsl === true;
    out.add("cloudsql_ssl_required", res, enforced ? "pass" : "fail",
      `sslMode is ${j(mode ?? "unset")}, requireSsl is ${j(ip.requireSsl)}; ENCRYPTED_ONLY or TRUSTED_CLIENT_CERTIFICATE_REQUIRED (or requireSsl true when sslMode is unset) required`);
  }
}

/** Admin ports (22, 3389) a firewall `allowed` entry opens. */
function openAdminPorts(allowed: unknown): number[] {
  const hits = new Set<number>();
  for (const a of arr(allowed).filter(isObj)) {
    const proto = String(a.IPProtocol ?? "").toLowerCase();
    if (proto !== "tcp" && proto !== "all") continue;
    const ports = arr(a.ports).map(String);
    if (proto === "all" || !ports.length) { ADMIN_PORTS.forEach((p) => hits.add(p)); continue; }
    for (const p of ports) {
      const m = /^(\d+)(?:-(\d+))?$/.exec(p.trim());
      if (m) rangeHits(Number(m[1]), Number(m[2] ?? m[1]), ADMIN_PORTS).forEach((x) => hits.add(x));
    }
  }
  return [...hits].sort((a, b) => a - b);
}

async function firewalls(api: Gcp, project: string, out: Out): Promise<void> {
  const pr = `project ${project}`;
  const f = await api.getAll(`${COMPUTE}/projects/${enc(project)}/global/firewalls?maxResults=500`, "items");
  if ("error" in f) return skipFor(out, "firewall_no_open_admin_ports", pr, "firewall rules", f.error);
  const ingress = f.items.filter(isObj).filter((r) => (r.direction ?? "INGRESS") === "INGRESS");
  if (!ingress.length) return out.skip("firewall_no_open_admin_ports", pr, "the project has no ingress firewall rule");
  for (const r of ingress) {
    const res = `firewall ${project}/${String(r.name ?? "?")}`;
    const open = arr(r.sourceRanges).map(String).filter((x) => OPEN.has(x));
    const ports = openAdminPorts(r.allowed);
    const bad = r.disabled !== true && open.length > 0 && ports.length > 0;
    out.add("firewall_no_open_admin_ports", res, bad ? "fail" : "pass",
      `disabled ${j(r.disabled ?? false)}; sources open to the internet: ${open.length ? open.join(", ") : "none"}; admin ports allowed: ${ports.length ? ports.join(", ") : "none"}; an enabled rule may not allow 22 or 3389 from 0.0.0.0/0 or ::/0`);
  }
}

/** Duration string such as "7776000s" in seconds; undefined when absent or unreadable. */
export function durationSecs(v: unknown): number | undefined {
  const m = typeof v === "string" ? /^(\d+(?:\.\d+)?)s$/.exec(v) : null;
  return m ? Number(m[1]) : undefined;
}

async function kms(api: Gcp, project: string, out: Out): Promise<void> {
  const pr = `project ${project}`;
  const locs = await api.getAll(`${KMS}/projects/${enc(project)}/locations?pageSize=100`, "locations");
  if ("error" in locs) return skipFor(out, "kms_rotation", pr, "KMS locations", locs.error);
  let keys = 0;
  for (const l of locs.items.filter(isObj)) {
    const loc = str(l.locationId);
    if (!loc) continue;
    const rings = await api.getAll(`${KMS}/projects/${enc(project)}/locations/${enc(loc)}/keyRings?pageSize=100`, "keyRings");
    if ("error" in rings) {
      if (rings.error.status === 403 || rings.error.status === 401) return skipFor(out, "kms_rotation", pr, "key rings", rings.error);
      continue;
    }
    for (const ring of rings.items.filter(isObj)) {
      const ringName = str(ring.name);
      if (!ringName) continue;
      const ck = await api.getAll(`${KMS}/${ringName}/cryptoKeys?pageSize=100`, "cryptoKeys");
      if ("error" in ck) { skipFor(out, "kms_rotation", `key ring ${ringName}`, "crypto keys", ck.error); continue; }
      for (const k of ck.items.filter(isObj).filter((x) => x.purpose === "ENCRYPT_DECRYPT")) {
        keys++;
        const secs = durationSecs(k.rotationPeriod);
        const good = secs !== undefined && secs <= MAX_KMS_ROTATION_SECONDS;
        out.add("kms_rotation", `kms key ${String(k.name)}`, good ? "pass" : "fail",
          `rotationPeriod is ${j(k.rotationPeriod ?? "unset")}${secs !== undefined ? ` (${Math.round(secs / 86_400)} days)` : ""}; 365 days or less required`);
      }
    }
  }
  if (!keys) out.skip("kms_rotation", pr, "the project has no symmetric (ENCRYPT_DECRYPT) KMS key");
}

interface FlowConfigs { configs: { name: string; subnet?: string; network?: string; org: boolean }[]; error?: string }

/**
 * Enabled VPC Flow Logs configurations of the Network Management API that apply to a project: its own (list) and the
 * organization's (queryOrgVpcFlowLogsConfigs, "all organization-level VPC Flow Logs configurations applicable to the
 * specified project"; discovery document revision 20261014, read 2026-10-26). An organization configuration with a
 * filterExpr covers only part of the traffic and is not counted. The API switched off for the project (Google's
 * SERVICE_DISABLED) means no project configuration can exist; any other refusal is reported.
 */
async function flowConfigs(api: Gcp, project: string): Promise<FlowConfigs> {
  const parent = `${NETMGMT}/projects/${enc(project)}/locations/global/vpcFlowLogsConfigs`;
  const out: FlowConfigs = { configs: [] };
  for (const [url, org] of [[parent, false], [`${parent}:queryOrgVpcFlowLogsConfigs`, true]] as const) {
    const r = await api.getAll(`${url}?pageSize=100`, "vpcFlowLogsConfigs");
    if ("error" in r) {
      if (/SERVICE_DISABLED|has not been used|is disabled/i.test(gWhy(r.error))) continue;
      out.error ??= gWhy(r.error);
      continue;
    }
    for (const c of r.items.filter(isObj)) {
      if (c.state === "DISABLED") continue;
      if (org && str(c.filterExpr)) continue;
      out.configs.push({ name: String(c.name ?? "?"), subnet: str(c.subnet), network: str(c.network), org });
    }
  }
  return out;
}

async function subnets(api: Gcp, project: string, out: Out): Promise<void> {
  const pr = `project ${project}`;
  const s = await api.getAll(`${COMPUTE}/projects/${enc(project)}/aggregated/subnetworks?maxResults=500`, "items");
  if ("error" in s) return skipFor(out, "vpc_flow_logs", pr, "subnetworks", s.error);
  let n = 0;
  let nm: FlowConfigs | undefined;
  for (const page of s.items.filter(isObj)) {
    for (const scoped of Object.values(page).filter(isObj)) {
      for (const sn of arr(scoped.subnetworks).filter(isObj)) {
        const purpose = str(sn.purpose);
        if (purpose && purpose !== "PRIVATE" && purpose !== "PRIVATE_RFC_1918") continue;
        n++;
        const region = String(sn.region ?? "").split("/").pop();
        const res = `subnet ${project}/${region}/${String(sn.name ?? "?")}`;
        const own = `logConfig.enable is ${j(isObj(sn.logConfig) ? sn.logConfig.enable : undefined)}, enableFlowLogs is ${j(sn.enableFlowLogs)}`;
        const on = (isObj(sn.logConfig) && sn.logConfig.enable === true) || sn.enableFlowLogs === true;
        if (on) { out.add("vpc_flow_logs", res, "pass", `${own}; flow logs on required`); continue; }
        // Off on the subnet itself: Google now recommends Network Management API configurations, which can cover the
        // subnet, its VPC network, or the whole organization (cloud.google.com/vpc/docs/flow-logs, last updated
        // 2026-10-22, read 2026-10-26: "Recommended: Enable VPC Flow Logs for a subnet (Network Management API)").
        nm ??= await flowConfigs(api, project);
        const self = `projects/${project}/regions/${region}/subnetworks/${String(sn.name ?? "")}`;
        const net = String(sn.network ?? "").replace(/^.*?(projects\/)/, "$1");
        const by = nm.configs.find((c) => c.subnet === self || (net && c.network === net) || c.org);
        if (by) out.add("vpc_flow_logs", res, "pass", `${own}; flow logs on through Network Management API configuration ${by.name} (${by.org ? "organization" : by.subnet ? "subnet" : "VPC network"} scope)`);
        else if (nm.error) out.add("vpc_flow_logs", res, "skipped", `${own}; Network Management API flow log configurations not readable (${nm.error}), so one covering this subnet cannot be ruled out`);
        else out.add("vpc_flow_logs", res, "fail", `${own}; no enabled Network Management API configuration covers the subnet, its network or the organization; flow logs on required`);
      }
    }
  }
  if (!n) out.skip("vpc_flow_logs", pr, "the project has no private-purpose subnetwork");
}
