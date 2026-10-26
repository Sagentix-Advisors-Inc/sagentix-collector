// Fleet (fleetdm.com), the open-source device management server in front of fleetd/osquery, read
// through its REST API with GET only. The token is an API-only user's with the global Observer role
// (read-only; available in Fleet Free). Only Fleet's MIT-licensed core endpoints are used; nothing
// here comes from, or needs, Fleet Premium or the ee/ directory.
//
// Endpoint and fields (Fleet REST API docs, github.com/fleetdm/fleet docs/REST API/rest-api.md at
// commit afe89e6e, 2026-10-14):
//   GET /api/v1/fleet/hosts?page&per_page&order_key=id&populate_policies=true
//       -> { hosts: [ { id, hardware_serial, platform, os_version, seen_time, disk_encryption_enabled,
//                       mdm: { enrollment_status, name }, policies: [ { id, name, query, platform, response } ] } ] }
//   `page` is zero-based; the list has no "next" marker, so a short page is the last one.
//   `disk_encryption_enabled` is omitted when Fleet does not know (and for Linux hosts reporting an
//   unencrypted root volume, which Fleet cannot confirm), so absence is "skipped", never "pass".
//   `mdm.enrollment_status` is "On (manual)", "On (automatic)", "On (personal)", "Pending", "Off" or null.
// Auth header `Authorization: Bearer <token>`. Fleet Premium only (and so not used): fleet_id filters,
// fleet-level policies, low_disk_space, and the vulnerability details of `populate_software`.
//
// Screen lock, OS currency, firewall and EDR come from the customer's own Fleet policies (osquery
// SQL that answers pass or fail per host). A policy counts for a check when its id is given with
// --fleet-policy <check>=<id>, or else when its name matches the check's default pattern below.
// --fleet-min-os adds a version floor per platform for os_up_to_date.
//
// Personal data: a host is named by its Fleet id and hardware serial. Its hostname, computer_name
// and display_name (which often hold the owner's name), its users and end users are never read
// into a result. Policy names are quoted with any email address cut out.

import type { Result, Source, SourceContext } from "../types.ts";
import { Emitter, arr, fetchRest, isObj, ok, realSleep, redact, str, withRetry, type HttpResponse, type Obj, type RestApi, type Sleep, listRead, stampRead } from "./readonly_http.ts";
import { ageDays, cmpVersion, deviceResource, label, minOsOption, posInt, showVersion, versionIn } from "./device_common.ts";

export const FLEET_ENV = { url: "FLEET_URL", token: "FLEET_API_TOKEN" } as const;
export const FLEET_CHECKS = ["disk_encryption", "screen_lock", "os_up_to_date", "firewall", "edr_present", "mdm_enrolled", "last_seen"] as const;
type C = (typeof FLEET_CHECKS)[number];
const POLICY_CHECKS = ["screen_lock", "os_up_to_date", "firewall", "edr_present"] as const;
type P = (typeof POLICY_CHECKS)[number];

export const DEFAULTS = { seenDays: 14, maxHosts: 5000 } as const;
export const PAGE = 100;

/** Policy names that count for a check unless --fleet-policy names the policy ids. */
export const POLICY_PATTERNS: Record<P, RegExp> = {
  screen_lock: /screen ?lock|screen ?saver|lock ?screen|idle lock|auto(matic)?[- ]?lock|password (required )?after (sleep|screen ?saver)|inactivity/i,
  os_up_to_date: /up[- ]?to[- ]?date|(os|operating system|macos|windows|software) updates?|(minimum|latest|supported) (os|operating system|macos|windows|version)|os version/i,
  firewall: /firewall/i,
  edr_present: /\bedr\b|\bxdr\b|anti-?virus|anti-?malware|malware protection|endpoint (detection|protection|security)|defender|crowdstrike|falcon|sentinel ?one|xprotect/i,
};

const WHAT: Record<P, string> = {
  screen_lock: "screen lock", os_up_to_date: "OS currency", firewall: "firewall", edr_present: "EDR or antivirus",
};

export function fleetFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const url = env[FLEET_ENV.url], token = env[FLEET_ENV.token];
  if (!url || !token) return `${FLEET_ENV.url} and ${FLEET_ENV.token} are not both set`;
  let u: URL;
  try { u = new URL(url); } catch { return `${FLEET_ENV.url} is not a URL`; }
  if (u.protocol !== "https:") return `${FLEET_ENV.url} must be https`;
  return fetchRest({ base: `${u.origin}/api/v1/fleet`, fetchFn, headers: async () => ({ authorization: `Bearer ${token}` }) });
}

/** --fleet-policy values "screen_lock=12" or "firewall=3,4" → check → policy ids. */
export function policyIds(v: unknown): Map<P, Set<string>> {
  const out = new Map<P, Set<string>>();
  for (const it of Array.isArray(v) ? v.map(String) : typeof v === "string" ? [v] : []) {
    const [k, ids] = it.split("=", 2);
    if (!ids || !(POLICY_CHECKS as readonly string[]).includes(k.trim())) continue;
    const set = out.get(k.trim() as P) ?? new Set<string>();
    for (const id of ids.split(",").map((s) => s.trim()).filter(Boolean)) set.add(id);
    out.set(k.trim() as P, set);
  }
  return out;
}

async function listHosts(api: RestApi, maxHosts: number): Promise<{ hosts: Obj[]; truncated: boolean } | { error: HttpResponse }> {
  const hosts: Obj[] = [];
  for (let page = 0; ; page++) {
    const r = await api.get(`/hosts?page=${page}&per_page=${PAGE}&order_key=id&order_direction=asc&populate_policies=true`);
    const got = ok(r) && isObj(r.body) && Array.isArray(r.body.hosts) ? r.body.hosts : undefined;
    if (!got) return { error: r };
    hosts.push(...got.filter(isObj));
    if (hosts.length >= maxHosts) return { hosts: hosts.slice(0, maxHosts), truncated: got.length === PAGE || hosts.length > maxHosts };
    if (got.length < PAGE) return { hosts, truncated: false };
  }
}

interface Verdict { result: "pass" | "fail" | "skipped"; detail: string }

/** Idle seconds a screen lock may wait: the default of the macos and windows sources (--macos-max-lock-seconds, --windows-max-lock-seconds). */
export const LOCK_SECONDS = 900;
/** The floor Fleet's library policy "Operating system up to date" (macOS) ships with. */
export const FLEET_LIBRARY_MACOS_FLOOR = "14.1.1";

// Each host policy carries its osquery SQL in `query` (Fleet REST API, "Get host", policies[].query). Two of Fleet's
// library policies pass more than their name says, so a pass from one of them proves nothing on its own:
//   "Screen lock enabled" for Windows (fleetdm.com/policies/screen-lock-enabled-windows, read 2026-10-26):
//     "... InactivityTimeoutSecs' AND CAST(data as INTEGER) <= 1800;" -- 30 minutes, twice the 900 s the macos and
//     windows sources allow, so a pass does not show the 900 s limit is met.
//   "Operating system up to date" for macOS (fleetdm.com/policies/operating-system-up-to-date-mac-os, read
//     2026-10-26): "SELECT 1 FROM os_version WHERE version >= '14.1.1';" -- a fixed floor from 2023. A floor below the
//     platform's --fleet-min-os, or Fleet's shipped one when no --fleet-min-os is given, does not show currency.
// A fail from either still fails: the host misses even the weaker bar.
export function weakPass(check: P, p: Obj, minOs: Map<string, number[]>): string | undefined {
  const q = String(p.query ?? "");
  if (check === "screen_lock") {
    const m = q.match(/InactivityTimeoutSecs[\s\S]*?(<=|<)\s*(\d+)/i);
    const limit = m ? Number(m[2]) - (m[1] === "<" ? 1 : 0) : undefined;
    if (limit !== undefined && limit > LOCK_SECONDS) return `its query passes at an InactivityTimeoutSecs up to ${limit} s, above the ${LOCK_SECONDS} s required`;
  }
  if (check === "os_up_to_date") {
    const m = q.match(/os_version\s+WHERE\s+version\s*>=?\s*'(\d+(?:\.\d+)*)'/i);
    if (m) {
      const floor = m[1].split(".").map(Number);
      const plat = String(p.platform ?? "").split(",")[0].trim().toLowerCase();
      const min = minOs.get(plat) ?? minOs.get("*");
      if (min && cmpVersion(floor, min) < 0) return `its query only asks for version ${m[1]}, below the --fleet-min-os floor ${showVersion(min)}`;
      if (!min && m[1] === FLEET_LIBRARY_MACOS_FLOOR) return `its query is Fleet's library floor version >= '${FLEET_LIBRARY_MACOS_FLOOR}', never raised; raise it or give --fleet-min-os`;
    }
  }
  return undefined;
}

/** The host's policies that count for a check, judged together: any fail fails; none answered is skipped. */
function byPolicies(h: Obj, check: P, ids: Map<P, Set<string>>, minOs: Map<string, number[]> = new Map()): Verdict | undefined {
  const want = ids.get(check);
  const mine = arr(h.policies).filter(isObj).filter((p) => (want ? want.has(String(p.id)) : POLICY_PATTERNS[check].test(String(p.name ?? ""))));
  if (!mine.length) return undefined;
  const weak = new Map(mine.map((p) => [p, p.response === "pass" ? weakPass(check, p, minOs) : undefined] as const));
  const parts = mine.slice(0, 5).map((p) => `policy ${String(p.id)} ${label(p.name)}: ${p.response === "pass" || p.response === "fail" ? p.response : "no response yet"}${weak.get(p) ? ` (not counted: ${weak.get(p)})` : ""}`);
  const more = mine.length > 5 ? ` (+${mine.length - 5} more)` : "";
  const strong = mine.filter((p) => p.response === "pass" && !weak.get(p));
  if (mine.some((p) => p.response === "fail")) return { result: "fail", detail: `${parts.join("; ")}${more}` };
  if (strong.length === mine.length) return { result: "pass", detail: `${parts.join("; ")}${more}` };
  if (strong.length) return { result: "pass", detail: `${parts.join("; ")}${more}; the rest have not run on this host or do not count` };
  if (mine.some((p) => weak.get(p))) return { result: "skipped", detail: `${parts.join("; ")}${more}; no policy that counts has passed` };
  return { result: "skipped", detail: `${parts.join("; ")}${more}; no answer from the host yet` };
}

export async function fleetChecks(api: RestApi, server: string, o: { seenDays: number; maxHosts: number; ids: Map<P, Set<string>>; minOs: Map<string, number[]> }, now: Date): Promise<Result[]> {
  const out = new Emitter<C>("fleet", `fleet ${server}`);
  const got = await listHosts(api, o.maxHosts);
  if ("error" in got) { for (const c of FLEET_CHECKS) out.skip(c, got.error, "Fleet hosts"); return out.results; }
  const { hosts, truncated } = got;
  if (!hosts.length) { out.skipAll(FLEET_CHECKS, "Fleet lists no enrolled host; nothing to judge"); return out.results; }
  const cap = truncated ? `; only the first ${o.maxHosts} hosts read (--fleet-max-hosts)` : "";
  const from = out.results.length;

  // A policy check with no matching policy on any host is one fleet-level "skipped", not one per host.
  const anyPolicy = new Set<P>(POLICY_CHECKS.filter((c) => hosts.some((h) => byPolicies(h, c, o.ids) !== undefined)));
  for (const c of POLICY_CHECKS) {
    if (anyPolicy.has(c) || (c === "os_up_to_date" && o.minOs.size)) continue;
    const how = o.ids.has(c) ? `policy id(s) ${[...o.ids.get(c)!].join(", ")} given with --fleet-policy` : `a policy whose name matches ${POLICY_PATTERNS[c].source}`;
    out.add(c, "skipped", `no Fleet policy for ${WHAT[c]} on any of ${hosts.length} host(s): looked for ${how}; add one or name it with --fleet-policy ${c}=<id>${c === "os_up_to_date" ? " (or give --fleet-min-os)" : ""}${cap}`);
  }

  for (const h of hosts) {
    const res = deviceResource("fleet host", h.id, h.hardware_serial);
    const platform = String(h.platform ?? "?");
    const os = str(h.os_version) ?? "OS not reported";
    const where = ` (${platform}, ${os})`;

    // Disk encryption, from Fleet's own host field.
    const enc = h.disk_encryption_enabled;
    if (typeof enc === "boolean") out.add("disk_encryption", enc ? "pass" : "fail", `disk_encryption_enabled is ${enc}${where}${cap}`, res);
    else out.add("disk_encryption", "skipped", `Fleet does not know this host's disk encryption (disk_encryption_enabled not reported)${where}`, res);

    for (const c of ["screen_lock", "firewall", "edr_present"] as const) {
      if (!anyPolicy.has(c)) continue;
      const v = byPolicies(h, c, o.ids);
      if (v) out.add(c, v.result, `${v.detail}${where}`, res);
      else out.add(c, "skipped", `no ${WHAT[c]} policy applies to this host${where}`, res);
    }

    // OS currency: the matching policies and, when given, the platform's version floor.
    if (anyPolicy.has("os_up_to_date") || o.minOs.size) {
      const v = anyPolicy.has("os_up_to_date") ? byPolicies(h, "os_up_to_date", o.ids, o.minOs) : undefined;
      const floor = o.minOs.get(platform.toLowerCase()) ?? o.minOs.get("*");
      const have = versionIn(h.os_version);
      const verdicts: Verdict[] = v ? [v] : [];
      if (floor && have) {
        const okv = cmpVersion(have, floor) >= 0;
        verdicts.push({ result: okv ? "pass" : "fail", detail: `version ${showVersion(have)} ${okv ? "meets" : "is below"} the --fleet-min-os floor ${showVersion(floor)} for ${platform}` });
      } else if (floor) verdicts.push({ result: "skipped", detail: "os_version not reported, so the --fleet-min-os floor cannot be judged" });
      const judged = verdicts.filter((x) => x.result !== "skipped");
      const detail = verdicts.length ? verdicts.map((x) => x.detail).join("; ") : `no OS currency policy applies to this host and no --fleet-min-os floor for ${platform}`;
      const result = judged.some((x) => x.result === "fail") ? "fail" : judged.length ? "pass" : "skipped";
      out.add("os_up_to_date", result, `${detail}${where}`, res);
    }

    // MDM enrollment (any MDM Fleet detects: Fleet's own, Jamf, Intune...).
    const mdm = isObj(h.mdm) ? h.mdm : {};
    const st = str(mdm.enrollment_status);
    const vendor = str(mdm.name) ? ` with ${label(mdm.name, 40)}` : "";
    if (!st) out.add("mdm_enrolled", "skipped", `Fleet reports no MDM enrollment status for this host (Linux and ChromeOS hosts have none)${where}`, res);
    else out.add("mdm_enrolled", /^On\b/i.test(st) ? "pass" : "fail", `mdm.enrollment_status is ${label(st, 40)}${vendor}${where}`, res);

    // Last seen.
    const age = ageDays(h.seen_time, now);
    if (age === undefined) out.add("last_seen", "skipped", `seen_time not reported${where}`, res);
    else out.add("last_seen", age <= o.seenDays ? "pass" : "fail", `last seen ${age} day(s) ago (${String(h.seen_time)}); at most ${o.seenDays} allowed (--fleet-seen-days)${where}`, res);
  }
  stampRead(out.results, from, listRead(got));   // a capped list leaves devices unseen: format 3 says so
  return out.results;
}

export const fleet: Source = {
  name: "fleet",
  options: {
    "fleet-seen-days": { type: "string", help: `days since a host last checked in before last_seen fails (default ${DEFAULTS.seenDays})` },
    "fleet-max-hosts": { type: "string", help: `hosts read, at most (default ${DEFAULTS.maxHosts})` },
    "fleet-policy": { type: "string", multiple: true, help: "<check>=<policy id>[,<id>] for screen_lock, os_up_to_date, firewall or edr_present (repeatable; default: match by policy name)" },
    "fleet-min-os": { type: "string", multiple: true, help: "<platform>=<version> floor for os_up_to_date, e.g. darwin=15.0 or windows=10.0.22631 (repeatable)" },
  },
  emits: FLEET_CHECKS.map((c) => `fleet.${c}`),
  describe: () => "Fleet server in FLEET_URL (REST API, observer API-only user)",
  async run(ctx: SourceContext) {
    const server = (() => { try { return new URL(ctx.env[FLEET_ENV.url] ?? "").host || "(unknown)"; } catch { return "(unknown)"; } })();
    const given = ctx.clients.fleet as RestApi | null | undefined;
    const built = given !== undefined ? given : fleetFromEnv(ctx.env);
    if (!built || typeof built === "string") {
      const out = new Emitter<C>("fleet", `fleet ${server}`);
      out.skipAll(FLEET_CHECKS, typeof built === "string" ? built : `${FLEET_ENV.token} is not set`);
      return out.results;
    }
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);
    const o = {
      seenDays: posInt(ctx.opts["fleet-seen-days"], DEFAULTS.seenDays),
      maxHosts: posInt(ctx.opts["fleet-max-hosts"], DEFAULTS.maxHosts),
      ids: policyIds(ctx.opts["fleet-policy"]),
      minOs: minOsOption(ctx.opts["fleet-min-os"]),
    };
    const token = ctx.env[FLEET_ENV.token];
    return redact(await fleetChecks(api, server, o, ctx.now), [token, token ? `Bearer ${token}` : undefined]);
  },
};
