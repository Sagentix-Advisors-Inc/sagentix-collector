// Vulnerability scanner results, reconciled with the organization's asset inventory: files the customer's scanner
// already wrote, read locally. The collector never runs a scan and never calls the scanner's API.
//
// Formats read, each page read 2026-11-07:
//   nessus   .nessus (NessusClientData_v2 XML), Tenable's "Nessus File Format" (docs.tenable.com/quick-reference/
//            nessus-file-format/Nessus-File-Format.pdf, last revised 2023-05-24): <ReportHost name="192.168.0.10">,
//            HostProperties tags HOST_START / HOST_END / netbios-name, ReportItem severity "0 — informational … 4 —
//            critical" and pluginID. Also read when present, though that document does not show them [Unverified]:
//            host-ip, host-fqdn, hostname, HOST_END_TIMESTAMP. Authentication: plugin 19506 "Nessus Scan Information"
//            (tenable.com/plugins/nessus/19506, modified 2026-07-10) reports "Whether credentialed or third-party patch
//            management checks are possible"; its output line "Credentialed checks : yes|no" is read [Unverified: the
//            public page does not show the line]. One scan, so no first-found date: findings_within_sla is skipped.
//   tenable  Tenable Vulnerability Management exports (developer.tenable.com/reference/exports-vulns-request-export):
//            vulnerability records with asset.hostname / asset.fqdn / asset.ipv4, severity, state OPEN|REOPENED|FIXED,
//            first_found, last_found, plugin.id; asset records with last_authenticated_scan_date ("The date and time of
//            the most recent credentialed scan performed on the asset"), compared with last_scan_time [Unverified name].
//            Exports need "at least the Basic [16] user permission" and "Can View" on the assets.
//   qualys   Qualys VMDR Host List Detection (/api/2.0/fo/asset/host/vm/detection/?action=list, HOST_LIST_VM_DETECTION_
//            OUTPUT XML; Qualys API (VM and PA) User Guide v10.41, 2026-10-12, cdn2.qualys.com/docs/qualys-api-vmpc-user-
//            guide.pdf): HOST → IP, DNS, LAST_VM_SCANNED_DATE, LAST_VM_AUTH_SCANNED_DATE; DETECTION → QID, TYPE,
//            SEVERITY 1-5, STATUS "New, Active, Re-Opened, Fixed", FIRST_FOUND_DATETIME. "Scanners and Readers view VM
//            scanned hosts": the Reader role can export it.
//   Wiz is not read: its documentation and API reference sit behind a sign-in (docs.wiz.io, 2026-11-07).
//
// Remediation windows: FedRAMP's POA&M guidance, "Critical and High risks to be remediated within 30 days of discovery,
// Moderate … 90 days … Low … 180 days" (fedramp.gov/legacy/playbook/csp/authorization/poam/). FedRAMP's 2026
// Vulnerability Detection and Response rules (fedramp.gov/2026/reference/vulnerability-detection-and-response/, changelog
// 2026-10-13) replace them with timeframes by potential agency impact; set --vulnscan-sla to the windows that apply.
// Scan age: "CSPs must scan operating systems, Web applications, and databases monthly. [RA-5]"; authenticated scans
// "wherever possible. [RA-5(5)]" (FedRAMP Continuous Monitoring Playbook v1.0, 2025-11-17).
//
// The inventory (--vulnscan-inventory) is the list the scans are held to: a CSV with a hostname, fqdn, name, ip,
// ipv4 or address column, a JSON array of names or of objects with such a field, or one name or address per line.
//
// Checks (one fact each):
//   authenticated_coverage  every inventory asset appears in a scan whose credentials worked (100% expected)
//   scan_recent             every asset (the inventory's, else every scanned host) was scanned within N days
//   findings_within_sla     no open finding older than its severity's remediation window
// Results carry counts, severities, ages and plugin or QID numbers; never a finding's output text. Host names appear
// only as counts and, for the assets that fail, up to 50 of the inventory's own names.

import { basename } from "node:path";
import { closeSync, fstatSync, openSync, readFileSync } from "node:fs";
import type { Result, Source, SourceContext } from "../types.ts";
import { arr, isObj, str, Results } from "./shared-cloud.ts";
import { MAX_REPORT_BYTES, bySeverity, idList, paths, posNum, readJsonFile } from "./report_files.ts";

export const VULNSCAN_CHECKS = ["authenticated_coverage", "scan_recent", "findings_within_sla"] as const;
type C = (typeof VULNSCAN_CHECKS)[number];
export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
type Sev = (typeof SEVERITIES)[number];
/** FedRAMP's remediation windows (High 30, Moderate 90, Low 180 days); critical is held to high's. */
export const DEFAULT_SLA: Record<Sev, number> = { critical: 30, high: 30, medium: 90, low: 180 };
export const DEFAULTS = { maxScanAgeDays: 30 };
const DAY = 86_400_000;
/** Tenable's "Nessus Scan Information" plugin: its output says whether credentialed checks ran. */
const SCAN_INFO_PLUGIN = "19506";

export interface Host { names: string[]; scannedAt?: number; authenticated: boolean | null }
export interface Finding { host: string; severity: Sev; firstFound: number; id: string }
export interface Scan { format: "nessus" | "tenable" | "qualys"; file: string; hosts: Host[]; findings: Finding[] | null }

// ── A small XML reader: linear scans for the flat tags these formats use (no nesting of a tag in itself). ─────

const ENT: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };
export const xmlText = (s: string) => s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").replace(/&(amp|lt|gt|quot|apos);/g, (_, e: string) => ENT[e]).trim();

/** Each `<tag …>…</tag>` in s, as its attribute text and inner text. */
export function elements(s: string, tag: string): { attrs: string; inner: string }[] {
  const out: { attrs: string; inner: string }[] = [];
  const open = `<${tag}`, close = `</${tag}>`;
  let i = 0;
  while ((i = s.indexOf(open, i)) >= 0) {
    const next = s[i + open.length];
    if (next !== ">" && next !== " " && next !== "\n" && next !== "\t" && next !== "\r" && next !== "/") { i += open.length; continue; }
    const gt = s.indexOf(">", i);
    if (gt < 0) break;
    if (s[gt - 1] === "/") { out.push({ attrs: s.slice(i + open.length, gt - 1), inner: "" }); i = gt + 1; continue; }
    const end = s.indexOf(close, gt);
    if (end < 0) break;
    out.push({ attrs: s.slice(i + open.length, gt), inner: s.slice(gt + 1, end) });
    i = end + close.length;
  }
  return out;
}
export const attr = (attrs: string, name: string): string | undefined => {
  const k = attrs.indexOf(`${name}="`);
  if (k < 0 || (k > 0 && !/\s/.test(attrs[k - 1]))) return undefined;
  const v = attrs.slice(k + name.length + 2), e = v.indexOf('"');
  return e < 0 ? undefined : xmlText(v.slice(0, e));
};
const child = (s: string, tag: string) => { const e = elements(s, tag)[0]; return e ? xmlText(e.inner) : undefined; };

function readText(path: string): { text: string } | { error: string } {
  let fd: number;
  try { fd = openSync(path, "r"); } catch (e) { return { error: `${basename(path)} not readable (${(e as NodeJS.ErrnoException).code ?? "error"})` }; }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return { error: `${basename(path)} is not a file` };
    if (st.size > MAX_REPORT_BYTES) return { error: `${basename(path)} is larger than ${MAX_REPORT_BYTES / 1024 / 1024} MB` };
    let t = readFileSync(fd, "utf8");
    if (t.charCodeAt(0) === 0xfeff) t = t.slice(1);
    return { text: t };
  } catch (e) { return { error: `${basename(path)} not readable (${(e as NodeJS.ErrnoException).code ?? "error"})` }; } finally { closeSync(fd); }
}

const when = (v: string | undefined): number | undefined => { if (!v) return undefined; const t = Date.parse(v); return Number.isFinite(t) ? t : undefined; };
const credentialed = (output: string | undefined): boolean | null => {
  const m = output?.match(/Credentialed checks\s*:\s*(yes|no)/i);
  return m ? m[1].toLowerCase() === "yes" : null;
};
const names = (...xs: (string | undefined)[]) => [...new Set(xs.filter((x): x is string => !!x).map((x) => x.toLowerCase()))];

// ── The three formats ───────────────────────────────────────────────────────────────────────────

const NESSUS_SEV: Record<string, Sev | undefined> = { "4": "critical", "3": "high", "2": "medium", "1": "low" };

export function parseNessus(text: string, file: string): Scan {
  const hosts: Host[] = [];
  for (const rh of elements(text, "ReportHost")) {
    const tags = new Map(elements(rh.inner, "tag").map((t) => [attr(t.attrs, "name") ?? "", xmlText(t.inner)]));
    const end = Number(tags.get("HOST_END_TIMESTAMP"));
    const info = elements(rh.inner, "ReportItem").find((x) => attr(x.attrs, "pluginID") === SCAN_INFO_PLUGIN);
    const flag = tags.get("Credentialed_Scan");
    hosts.push({
      names: names(attr(rh.attrs, "name"), tags.get("host-ip"), tags.get("host-fqdn"), tags.get("hostname"), tags.get("netbios-name")),
      scannedAt: Number.isFinite(end) && end > 0 ? end * 1000 : when(tags.get("HOST_END")),
      authenticated: info ? credentialed(child(info.inner, "plugin_output")) : flag ? flag.toLowerCase() === "true" : null,
    });
  }
  return { format: "nessus", file, hosts, findings: null };
}

export function parseTenable(records: unknown[], file: string): Scan {
  const by = new Map<string, Host>();
  const findings: Finding[] = [];
  for (const r of records.filter(isObj)) {
    // An asset export record (POST /assets/export): "last_authenticated_scan_date: The date and time of the most recent
    // credentialed scan performed on the asset." Authenticated when that is the asset's last scan, as for Qualys.
    if ("last_authenticated_scan_date" in r || "last_scan_time" in r) {
      const many = (k: string) => [...arr(r[`${k}s`]), r[k]].map((x) => str(x));
      const ns = names(...many("fqdn"), ...many("hostname"), ...many("ipv4"));
      const key = str(r.id) ?? ns[0];
      if (!key) continue;
      const last = when(str(r.last_scan_time)), auth = when(str(r.last_authenticated_scan_date));
      const h = by.get(key) ?? { names: [], authenticated: null };
      h.names = names(...h.names, ...ns);
      if (last && (!h.scannedAt || last > h.scannedAt)) h.scannedAt = last;
      h.authenticated = last === undefined ? (auth !== undefined ? true : h.authenticated) : auth !== undefined && auth >= last - DAY;
      by.set(key, h);
      continue;
    }
    const a = isObj(r.asset) ? r.asset : {};
    const ns = names(str(a.fqdn), str(a.hostname), str(a.ipv4), ...arr(a.ipv4s).map((x) => str(x)));
    const key = str(a.uuid) ?? ns[0];
    if (!key) continue;
    const h = by.get(key) ?? { names: [], authenticated: null };
    h.names = names(...h.names, ...ns);
    const plugin = isObj(r.plugin) ? String(r.plugin.id ?? "") : "";
    const last = when(str(r.last_found));
    if (plugin === SCAN_INFO_PLUGIN) {
      const cred = credentialed(str(r.output));
      if (cred !== null && (h.authenticated === null || !h.authenticated)) h.authenticated = cred;
      if (last && (!h.scannedAt || last > h.scannedAt)) h.scannedAt = last;
    }
    by.set(key, h);
    const sev = String(r.severity ?? "").toLowerCase() as Sev;
    const state = String(r.state ?? "").toUpperCase();
    const first = when(str(r.first_found));
    if ((SEVERITIES as readonly string[]).includes(sev) && (state === "OPEN" || state === "REOPENED") && first) findings.push({ host: key, severity: sev, firstFound: first, id: `plugin ${plugin || "?"}` });
  }
  return { format: "tenable", file, hosts: [...by.values()], findings };
}

const QUALYS_SEV: Record<string, Sev | undefined> = { "5": "critical", "4": "high", "3": "medium", "2": "low", "1": "low" };

export function parseQualys(text: string, file: string): Scan {
  const hosts: Host[] = [], findings: Finding[] = [];
  for (const h of elements(text, "HOST")) {
    const ip = child(h.inner, "IP"), dns = child(h.inner, "DNS"), netbios = child(h.inner, "NETBIOS");
    const vm = when(child(h.inner, "LAST_VM_SCANNED_DATE")), auth = when(child(h.inner, "LAST_VM_AUTH_SCANNED_DATE"));
    const host = { names: names(ip, dns, dns?.split(".")[0], netbios), scannedAt: vm ?? when(child(h.inner, "LAST_SCAN_DATETIME")),
                   // Authenticated when the last authenticated VM scan is the last VM scan (Qualys records both dates).
                   authenticated: vm === undefined ? null : auth !== undefined && auth >= vm - DAY };
    hosts.push(host);
    for (const d of elements(h.inner, "DETECTION")) {
      if ((child(d.inner, "TYPE") ?? "").toLowerCase() !== "confirmed") continue;
      const status = (child(d.inner, "STATUS") ?? "").toLowerCase();
      const sev = QUALYS_SEV[child(d.inner, "SEVERITY") ?? ""], first = when(child(d.inner, "FIRST_FOUND_DATETIME"));
      if (sev && first && status !== "fixed") findings.push({ host: host.names[0] ?? "?", severity: sev, firstFound: first, id: `QID ${child(d.inner, "QID") ?? "?"}` });
    }
  }
  return { format: "qualys", file, hosts, findings };
}

/** The scan in a file, by its content. */
export function readScan(path: string): Scan | { error: string } {
  const file = basename(path);
  if (/\.json$/i.test(path)) {
    const r = readJsonFile(path);
    if ("error" in r) return { error: r.error };
    const recs = Array.isArray(r.data) ? r.data : isObj(r.data) && Array.isArray(r.data.vulnerabilities) ? r.data.vulnerabilities : null;
    if (!recs || !recs.some((x) => isObj(x) && ((isObj(x.asset) && ("plugin" in x || "severity" in x)) || "last_authenticated_scan_date" in x || "last_scan_time" in x))) return { error: `${file} is not a Tenable vulnerability or asset export (a JSON array of records with asset and plugin, or with last_scan_time)` };
    return parseTenable(recs, file);
  }
  const t = readText(path);
  if ("error" in t) return t;
  const head = t.text.slice(0, 4096);
  if (head.includes("<NessusClientData_v2")) return parseNessus(t.text, file);
  if (head.includes("HOST_LIST_VM_DETECTION_OUTPUT")) return parseQualys(t.text, file);
  return { error: `${file} is neither a .nessus file (NessusClientData_v2), a Qualys host list detection (HOST_LIST_VM_DETECTION_OUTPUT) nor a Tenable JSON export` };
}

/** The inventory's asset names, lowercased, from CSV, JSON or one name per line. */
export function readInventory(path: string): string[] | { error: string } {
  const t = readText(path);
  if ("error" in t) return t;
  const s = t.text.trim();
  const COLS = ["fqdn", "hostname", "host", "name", "dns", "ip", "ipv4", "ip address", "address", "asset"];
  if (s.startsWith("[")) {
    let j: unknown;
    try { j = JSON.parse(s); } catch { return { error: `${basename(path)} is not valid JSON` }; }
    return [...new Set(arr(j).map((x) => (typeof x === "string" ? x : isObj(x) ? COLS.map((c) => str(x[c])).find(Boolean) : undefined)).filter((x): x is string => !!x).map((x) => x.trim().toLowerCase()))];
  }
  const lines = s.split(/\r?\n/).filter((l) => l.trim() && !l.startsWith("#"));
  const head = lines[0]?.split(",").map((h) => h.trim().replace(/^"|"$/g, "").toLowerCase()) ?? [];
  const col = COLS.map((c) => head.indexOf(c)).find((i) => i >= 0);
  const rows = col === undefined ? lines.map((l) => l.trim()) : lines.slice(1).map((l) => (l.split(",")[col] ?? "").trim().replace(/^"|"$/g, ""));
  return [...new Set(rows.filter(Boolean).map((x) => x.toLowerCase()))];
}

/** The scanned host an inventory name stands for: the same name, IP or short host name. */
const matcher = (hosts: Host[]) => {
  // A host seen in several files (an asset export beside a vulnerability export) is one host: the latest scan wins, and
  // a credential record from any file counts (yes over no over unknown).
  const merge = (a: Host | undefined, b: Host): Host => !a ? b : {
    names: names(...a.names, ...b.names), scannedAt: Math.max(a.scannedAt ?? 0, b.scannedAt ?? 0) || undefined,
    authenticated: a.authenticated === true || b.authenticated === true ? true : a.authenticated === false || b.authenticated === false ? false : null };
  const idx = new Map<string, Host>();
  for (const h of hosts) for (const n of h.names) { idx.set(n, merge(idx.get(n), h)); const s = n.split(".")[0]; if (s !== n) idx.set(s, merge(idx.get(s), h)); }
  return (name: string) => idx.get(name) ?? idx.get(name.split(".")[0]);
};

export function parseSla(v: unknown): Record<Sev, number> | string {
  const out = { ...DEFAULT_SLA };
  if (typeof v !== "string" || !v.trim()) return out;
  for (const part of v.split(",")) {
    const [k, n] = part.split("=").map((x) => x.trim().toLowerCase());
    if (!(SEVERITIES as readonly string[]).includes(k) || !/^\d+$/.test(n ?? "") || Number(n) < 1) return `--vulnscan-sla takes severity=days pairs, e.g. critical=15,high=30,medium=90,low=180 (got ${JSON.stringify(part.slice(0, 40))})`;
    out[k as Sev] = Number(n);
  }
  return out;
}

export function judgeScans(scans: Scan[], inventory: string[] | null, o: { now: Date; maxScanAgeDays: number; sla: Record<Sev, number> }, out: Results<C>, resource: string) {
  const hosts = scans.flatMap((s) => s.hosts);
  const find = matcher(hosts);
  const from = `${scans.length} report(s) (${[...new Set(scans.map((s) => s.format))].join(", ")}), ${hosts.length} scanned host(s)`;

  // authenticated_coverage
  if (!inventory) out.skip("authenticated_coverage", resource, `${from}; give --vulnscan-inventory <file> so coverage is measured against the asset inventory, not against what the scanner happened to reach`);
  else if (!inventory.length) out.skip("authenticated_coverage", resource, "the inventory file lists no asset");
  else {
    const missing: string[] = [], unauth: string[] = [], unknown: string[] = [];
    for (const a of inventory) {
      const h = find(a);
      if (!h) missing.push(a); else if (h.authenticated === false) unauth.push(a); else if (h.authenticated === null) unknown.push(a);
    }
    const ok = inventory.length - missing.length - unauth.length - unknown.length;
    const pct = Math.floor((ok / inventory.length) * 1000) / 10;
    const bad = [...missing, ...unauth, ...unknown];
    out.add("authenticated_coverage", resource, bad.length ? "fail" : "pass",
      `${from}; ${ok} of ${inventory.length} inventory asset(s) (${pct}%) scanned with working credentials; ${missing.length} not in any scan, ${unauth.length} scanned without credentials, ${unknown.length} with no credential record (plugin 19506 or LAST_VM_AUTH_SCANNED_DATE)${idList(bad.sort())}; 100% required`);
  }

  // scan_recent
  const subjects = inventory?.length ? inventory.map((a) => ({ name: a, h: find(a) })) : hosts.map((h) => ({ name: h.names[0] ?? "?", h }));
  if (!subjects.length) out.skip("scan_recent", resource, `${from}; nothing to judge`);
  else {
    const limit = o.now.getTime() - o.maxScanAgeDays * DAY;
    const stale = subjects.filter((x) => !x.h || !x.h.scannedAt || x.h.scannedAt < limit);
    const oldest = subjects.map((x) => x.h?.scannedAt).filter((t): t is number => !!t).sort((a, b) => a - b)[0];
    out.add("scan_recent", resource, stale.length ? "fail" : "pass",
      `${subjects.length} ${inventory?.length ? "inventory asset(s)" : "scanned host(s) (no inventory given)"}; ${stale.length} not scanned in the last ${o.maxScanAgeDays} day(s)${idList(stale.map((x) => x.name).sort())}${oldest ? `; oldest scan ${new Date(oldest).toISOString().slice(0, 10)}` : ""}`);
  }

  // findings_within_sla
  const dated = scans.filter((s) => s.findings !== null);
  if (!dated.length) out.skip("findings_within_sla", resource, `${from}; a .nessus file is one scan and carries no first-found date: import a Tenable Vulnerability Management export or a Qualys host list detection to judge remediation time`);
  else {
    const open = dated.flatMap((s) => s.findings!);
    const counts = new Map<string, number>(), late = new Map<string, number>();
    const lateIds = new Set<string>();
    for (const f of open) {
      counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
      if ((o.now.getTime() - f.firstFound) / DAY > o.sla[f.severity]) { late.set(f.severity, (late.get(f.severity) ?? 0) + 1); lateIds.add(f.id); }
    }
    const nLate = [...late.values()].reduce((a, b) => a + b, 0);
    out.add("findings_within_sla", resource, nLate ? "fail" : "pass",
      `${open.length} open finding(s) by severity: ${bySeverity(counts, SEVERITIES)}; past the window (${SEVERITIES.map((s) => `${s} ${o.sla[s]} d`).join(", ")}): ${bySeverity(late, SEVERITIES)}${idList([...lateIds].sort(), "")}; none past the window required`);
  }
}

export const vulnscan: Source = {
  name: "vulnscan",
  options: {
    "vulnscan-report": { type: "string", multiple: true, help: "a scanner result file: .nessus, a Tenable Vulnerability Management export chunk (.json) or a Qualys host list detection (.xml); repeatable" },
    "vulnscan-inventory": { type: "string", help: "the asset inventory the scans are held to: CSV (hostname/fqdn/ip column), JSON array, or one name or address per line" },
    "vulnscan-max-age-days": { type: "string", help: `days since an asset's last scan before it fails (default ${DEFAULTS.maxScanAgeDays}: monthly)` },
    "vulnscan-sla": { type: "string", help: `remediation windows in days, e.g. critical=30,high=30,medium=90,low=180 (the default)` },
  },
  emits: VULNSCAN_CHECKS.map((c) => `vulnscan.${c}`),
  describe(opts) {
    const ps = paths(opts["vulnscan-report"]);
    return `scanner results ${ps.length ? ps.map((p) => basename(p)).join(", ") : "(none given)"}${typeof opts["vulnscan-inventory"] === "string" ? ` against ${basename(opts["vulnscan-inventory"])}` : ""}`;
  },
  validate(opts) {
    const s = parseSla(opts["vulnscan-sla"]);
    return typeof s === "string" ? s : undefined;
  },
  async run(ctx: SourceContext): Promise<Result[]> {
    const out = new Results<C>("vulnscan");
    const files = paths(ctx.opts["vulnscan-report"]);
    if (!files.length) { out.skipAll(VULNSCAN_CHECKS, "vulnscan", "give --vulnscan-report <file>: a .nessus export, a Tenable vulnerability export chunk or a Qualys host list detection"); return out.results; }
    const scans: Scan[] = [];
    for (const f of files) {
      const s = readScan(f);
      if ("error" in s) out.skipAll(VULNSCAN_CHECKS, `vulnscan ${basename(f)}`, s.error);
      else scans.push(s);
    }
    if (!scans.length) return out.results;
    const invPath = typeof ctx.opts["vulnscan-inventory"] === "string" ? ctx.opts["vulnscan-inventory"] : undefined;
    let inventory: string[] | null = null;
    if (invPath) {
      const inv = readInventory(invPath);
      if ("error" in inv) { out.skipAll(VULNSCAN_CHECKS, `vulnscan inventory ${basename(invPath)}`, inv.error); return out.results; }
      inventory = inv;
    }
    const sla = parseSla(ctx.opts["vulnscan-sla"]);
    const resource = `vulnscan ${invPath ? `inventory ${basename(invPath)}` : scans.map((s) => s.file).join(", ").slice(0, 200)}`;
    judgeScans(scans, inventory, { now: ctx.now, maxScanAgeDays: posNum(ctx.opts["vulnscan-max-age-days"], DEFAULTS.maxScanAgeDays), sla: typeof sla === "string" ? DEFAULT_SLA : sla }, out, resource);
    return out.results;
  },
};
