// Structured diagnostics (apps/sos-app/docs/COLLECTOR_CHANNEL.md, section 11): every fault a source meets becomes one
// record with a code from a closed list, who can fix it, where it happened and what to do, so sos-app can show a
// customer the fix and send Sagentix the bugs without anyone reading a log.
//
//   code    AUTH_REFUSED, PERMISSION_MISSING, CONFIG_INVALID       owner "customer"  (the doctor's fix is the hint)
//           API_CHANGED, PARSE_ERROR, INTERNAL                      owner "sagentix"  (the fix loop's input)
//           RATE_LIMITED, PROVIDER_5XX, TIMEOUT, NETWORK            owner "provider"  (transient: retried next run)
//
// A diagnostic never carries the provider's own words: no response body, no error message text, no query string, no
// header value. `endpoint` is the call's method, host and templated path (src/report.ts templatePath); `frames` are the
// stack frames inside this package only, as file:line:function; `hint` is our own text.

import { dirname, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { templatePath } from "./report.ts";

export const CODES = ["AUTH_REFUSED", "PERMISSION_MISSING", "CONFIG_INVALID", "RATE_LIMITED", "TIMEOUT", "NETWORK", "PROVIDER_5XX",
  "API_CHANGED", "PARSE_ERROR", "INTERNAL"] as const;
export type Code = (typeof CODES)[number];
export type Owner = "customer" | "sagentix" | "provider";

export const OWNER: Record<Code, Owner> = {
  AUTH_REFUSED: "customer", PERMISSION_MISSING: "customer", CONFIG_INVALID: "customer",
  API_CHANGED: "sagentix", PARSE_ERROR: "sagentix", INTERNAL: "sagentix",
  RATE_LIMITED: "provider", PROVIDER_5XX: "provider", TIMEOUT: "provider", NETWORK: "provider",
};

/** The order in which a source's diagnostics are shown: the one a person can act on first. */
export const SEVERITY: readonly Code[] = ["AUTH_REFUSED", "PERMISSION_MISSING", "CONFIG_INVALID", "API_CHANGED", "PARSE_ERROR", "INTERNAL",
  "PROVIDER_5XX", "RATE_LIMITED", "TIMEOUT", "NETWORK"];

export interface Diagnostic {
  code: Code;
  owner: Owner;
  source: string;
  check?: string;
  httpStatus?: number;
  /** "GET api.github.com/orgs/:id/members": method, host, templated path. Never a query. */
  endpoint?: string;
  /** The provider's page for the permission or the API, when the source names one. */
  providerDoc?: string;
  /** What to do, in our words. */
  hint: string;
  /** Collector frames only, innermost first: "src/sources/okta.ts:214:run". */
  frames: string[];
}

/** What is known of the call that failed. */
export interface CallInfo {
  source?: string;
  check?: string;
  status?: number;
  method?: string;
  url?: string;
  /** The response's headers: only Deprecation and Sunset are looked at, and only whether they are there. */
  headers?: Headers | Record<string, string>;
  providerDoc?: string;
  /** A call with no answer (status 0) that was abandoned for --http-timeout, rather than refused by the network. */
  timedOut?: boolean;
}

/** Thrown by a source for a fault in what the customer gave it (an option, a file, a credential that is not there). */
export class ConfigError extends Error { override name = "ConfigError"; }
/** Thrown by a source when a provider's answer does not have the shape the source reads (the API changed). */
export class SchemaError extends Error { override name = "SchemaError"; }

export const MAX_FRAMES = 8;
const PACKAGE_DIR = dirname(dirname(fileURLToPath(import.meta.url)));

/** The stack's frames that are this package's own code, as file:line:function, innermost first. Never the message. */
export function collectorFrames(stack: string | undefined, root: string = PACKAGE_DIR): string[] {
  const out: string[] = [];
  for (const line of (stack ?? "").split("\n")) {
    // "    at fn (file:///…/src/x.ts:12:3)", "    at async fn (/…/src/x.ts:12:3)" or "    at /…/src/x.ts:12:3"
    const m = /^\s*at (?:async )?(?:(.+?) \()?((?:file:\/\/)?[^()\s]+?):(\d+):\d+\)?\s*$/.exec(line);
    if (!m) continue;
    let file = m[2];
    try { if (file.startsWith("file://")) file = fileURLToPath(file); } catch { continue; }
    const rel = relative(root, file).split(sep).join("/");
    if (!rel.startsWith("src/") || rel.includes("node_modules")) continue;
    const fn = (m[1] ?? "").replace(/^(?:new |Object\.|Array\.)/, "").replace(/[^A-Za-z0-9_$.<>-]/g, "").slice(0, 60) || "<anonymous>";
    out.push(`${rel}:${m[3]}:${fn}`);
    if (out.length >= MAX_FRAMES) break;
  }
  return out;
}

/** "GET host/templated/path", or undefined when the URL does not parse. */
export function endpointOf(method: string | undefined, url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const u = new URL(url);
    return `${(method ?? "GET").toUpperCase()} ${u.host}${templatePath(u.pathname)}`;
  } catch { return undefined; }
}

const header = (h: CallInfo["headers"], name: string): boolean => {
  if (!h) return false;
  if (typeof (h as Headers).get === "function") return !!(h as Headers).get(name);
  return Object.entries(h as Record<string, string>).some(([k, v]) => k.toLowerCase() === name && !!v);
};

/** The code for an HTTP status alone (0: no answer). */
export function codeForStatus(status: number, timedOut = false): Code {
  if (status === 0) return timedOut ? "TIMEOUT" : "NETWORK";
  if (status === 401) return "AUTH_REFUSED";
  if (status === 403) return "PERMISSION_MISSING";
  if (status === 429) return "RATE_LIMITED";
  if (status === 408) return "TIMEOUT";
  if (status === 407) return "NETWORK";
  if (status >= 500) return "PROVIDER_5XX";
  // 404 and 410: the endpoint moved or went; 400, 405, 415 and 422: the request no longer has the shape it needs.
  return "API_CHANGED";
}

const NETWORK_CODES = /^(ECONNREFUSED|ECONNRESET|ENOTFOUND|EAI_AGAIN|EHOSTUNREACH|ENETUNREACH|EPIPE|ECONNABORTED|UND_ERR_SOCKET|UND_ERR_CONNECT_TIMEOUT|CERT_|UNABLE_TO_|DEPTH_ZERO_|SELF_SIGNED_|ERR_TLS_)/;
const TIMEOUT_CODES = /^(ETIMEDOUT|ESOCKETTIMEDOUT|UND_ERR_HEADERS_TIMEOUT|UND_ERR_BODY_TIMEOUT|ABORT_ERR)$/;

/** The error's own code (Node's `code`, or its cause's), never its message. */
function errCode(e: unknown): string {
  for (let x: unknown = e, depth = 0; x && typeof x === "object" && depth < 4; x = (x as { cause?: unknown }).cause, depth++) {
    const c = (x as { code?: unknown }).code;
    if (typeof c === "string") return c;
  }
  return "";
}

/** The code for a thrown error with no HTTP status. Decided from its class, its Node code and the collector's own
 *  message shapes; the text itself never leaves. */
export function codeForError(e: unknown): Code {
  if (!(e instanceof Error)) return "INTERNAL";
  const code = errCode(e), msg = e.message ?? "";
  if (e instanceof ConfigError) return "CONFIG_INVALID";
  if (e instanceof SchemaError) return "API_CHANGED";
  if (e.name === "TimeoutError" || TIMEOUT_CODES.test(code) || /^no answer from \S* within \d+ s/.test(msg)) return "TIMEOUT";
  if (NETWORK_CODES.test(code) || (e.name === "TypeError" && /^fetch failed$/.test(msg))) return "NETWORK";
  if (/invalid_grant|sign-in was revoked|has expired; run `collector google-login`/.test(msg)) return "AUTH_REFUSED";
  const http = /\bHTTP (\d{3})\b/.exec(msg);
  if (http && /^token request to /.test(msg)) return Number(http[1]) >= 500 ? "PROVIDER_5XX" : "AUTH_REFUSED";
  // A file or binary the customer names that is not there, or an option they must give: theirs to fix.
  if (code === "ENOENT" || code === "EACCES" || code === "EISDIR" || code === "EPERM") return "CONFIG_INVALID";
  if (/^(give --|--[a-z0-9-]+ (is required|must|may not|reads one)|cannot (read|run) |the STIG profile .* is not there|[A-Z][A-Z0-9_]+ must be an https URL|the certificate file holds no PEM)/.test(msg)
      || /\((ENOENT|EACCES)\)/.test(msg)) return "CONFIG_INVALID";
  if (e instanceof SyntaxError || /is not (a|an) [A-Za-z ]+(JSON )?report|not an InSpec JSON report|wrote no (report|\.ocsf\.json)/.test(msg)) return "PARSE_ERROR";
  if (e instanceof TypeError && /Cannot read propert|is not iterable|is not a function|Cannot convert undefined or null/.test(msg)) return "PARSE_ERROR";
  return "INTERNAL";
}

/** Our words for what to do. `permission` is the doctor's exact grant for the endpoint, when it knows it. */
export function hintFor(code: Code, source: string, o: { permission?: string; status?: number } = {}): string {
  const doctor = `then run \`collector doctor --config <file> --source ${source}\` to confirm`;
  switch (code) {
    case "AUTH_REFUSED": return `The ${source} credential was refused (expired, revoked, or for another tenant): renew it in the vault or the environment, ${doctor}.`;
    case "PERMISSION_MISSING": return o.permission ? `Grant ${o.permission}, ${doctor}.` : `A permission is missing for ${source}: run \`collector doctor --config <file> --source ${source}\` to see which one.`;
    case "CONFIG_INVALID": return `The ${source} connector is not set up completely (a credential, option or file is missing or wrong): fix it in Connect your environment, ${doctor}.`;
    case "RATE_LIMITED": return `${source} limited the collector's calls even after retries; the next run tries again. Nothing to do unless it repeats.`;
    case "PROVIDER_5XX": return `${source} answered with a server error${o.status ? ` (HTTP ${o.status})` : ""}; the next run tries again. Check the provider's status page if it repeats.`;
    case "TIMEOUT": return `${source} did not answer in time; the next run tries again. Raise --http-timeout if it repeats.`;
    case "NETWORK": return `The collector could not reach ${source}: check the network path from this runner (proxy, firewall, DNS, TLS inspection).`;
    case "API_CHANGED": return `The ${source} API answered in a way this collector does not expect; Sagentix has been told and will ship a fixed collector.`;
    case "PARSE_ERROR": return `The collector could not read what ${source} returned; Sagentix has been told and will ship a fixed collector.`;
    default: return `The collector failed inside the ${source} connector; Sagentix has been told and will ship a fixed collector.`;
  }
}

/** Looks up the doctor's permission for an endpoint; set by doctor.ts so this file does not import every source. */
let permissionLookup: (source: string, path: string) => string | undefined = () => undefined;
export function setPermissionLookup(f: (source: string, path: string) => string | undefined): void { permissionLookup = f; }

/**
 * The diagnostic for one fault: a thrown error, an HTTP answer, or both. The status decides when there is one;
 * otherwise the error's class and Node code do. A 2xx or 404 with a Deprecation or Sunset header is API_CHANGED.
 */
export function classify(error: unknown, call: CallInfo = {}): Diagnostic {
  const source = call.source ?? "collector";
  const status = call.status ?? (error && typeof error === "object" && typeof (error as { status?: unknown }).status === "number" ? (error as { status: number }).status : undefined);
  const timedOut = call.timedOut ?? (error instanceof Error && codeForError(error) === "TIMEOUT");
  let code: Code;
  if (header(call.headers, "deprecation") || header(call.headers, "sunset")) code = "API_CHANGED";
  // A status of 0 is a call that got no answer: abandoned for the timeout, or refused on the way.
  else if (status !== undefined && (status === 0 || status >= 400)) code = codeForStatus(status, timedOut);
  else code = error === undefined || error === null ? "INTERNAL" : codeForError(error);
  const endpoint = endpointOf(call.method, call.url);
  let permission: string | undefined;
  if (code === "PERMISSION_MISSING" && call.url) {
    try { permission = permissionLookup(source, new URL(call.url).pathname); } catch { /* no URL */ }
  }
  return {
    code, owner: OWNER[code], source,
    ...(call.check ? { check: call.check } : {}),
    ...(status !== undefined && status > 0 ? { httpStatus: status } : {}),
    ...(endpoint ? { endpoint } : {}),
    ...(call.providerDoc && /^https:\/\/[^\s]{1,300}$/.test(call.providerDoc) ? { providerDoc: call.providerDoc } : {}),
    hint: hintFor(code, source, { permission, status }),
    frames: error instanceof Error ? collectorFrames(error.stack) : [],
  };
}

/** The most pressing diagnostic of a list (SEVERITY order), or undefined. */
export function primary(ds: readonly Diagnostic[]): Diagnostic | undefined {
  return [...ds].sort((a, b) => SEVERITY.indexOf(a.code) - SEVERITY.indexOf(b.code))[0];
}

/** One diagnostic per code, check and endpoint, at most `max`. */
export function dedupe(ds: readonly Diagnostic[], max = 20): Diagnostic[] {
  const seen = new Set<string>(), out: Diagnostic[] = [];
  for (const d of ds) {
    const k = `${d.code}|${d.check ?? ""}|${d.endpoint ?? ""}|${d.frames[0] ?? ""}`;
    if (seen.has(k)) continue;
    seen.add(k);
    if (out.length < max) out.push(d);
  }
  return out;
}

/** One line for the end-of-run output: code, who fixes it, where, and the hint. */
export function diagnosticLine(d: Diagnostic): string {
  const who = d.owner === "customer" ? "yours to fix" : d.owner === "sagentix" ? "Sagentix fixes it" : "transient";
  return `  ${d.source}${d.check ? ` [${d.check}]` : ""}: ${d.code} (${who})${d.httpStatus ? `, HTTP ${d.httpStatus}` : ""}${d.endpoint ? `, ${d.endpoint}` : ""}; ${d.hint}`;
}
