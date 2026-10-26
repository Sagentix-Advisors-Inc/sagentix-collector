// Websites and APIs by URL: a passive look at what any browser sees, for URLs the organization declared and
// proved it controls. No crawling (only the exact URLs given, no link is followed and no redirect either), no
// form, no POST, no vulnerability probe. Requests are GET, plus TLS handshakes to port 443 of the declared host
// and DNS lookups; at most one request a second to a host by default (--web-delay-ms), each with a timeout,
// and a User-Agent naming the collector.
//
// Proof of control, checked by the collector itself before anything else is sent to a host: --web-proof
// <host>=<token> gives the token sos-app issued for that host, and the host is proven when either
//   the TXT record at _sagentix-collector.<host> holds  sagentix-collector-verification=<token>, or
//   GET https://<host>/.well-known/sagentix-collector.txt (redirect not followed, first 4 KB) holds that line.
// The well-known GET is the only request a host gets before it is proven, as with ACME's HTTP-01 challenge.
// A host without a token gets no request at all, and every check on it is skipped. --web-skip-proof runs the
// checks without proof, and the CLI accepts it only with --dry-run, which never sends anything to sos-app.
//
// What each check reads, and the text it was written against (each page read 2026-10-18):
//   tls_min_version       a handshake offering only TLS 1.0 and 1.1 (ciphers DEFAULT@SECLEVEL=0) must fail, and a
//                         default handshake must land on TLS 1.2 or 1.3. CCCS ITSP.40.062 v3 (January 2025), §3:
//                         "You should phase out versions of TLS older than 1.2 or any versions of Secure Sockets
//                         Layer (SSL)" (cyber.gc.ca/en/guidance/guidance-securely-configuring-network-protocols-itsp40062).
//                         Government of Canada, "Web Sites and Services Management Configuration Requirements"
//                         (canada.ca, page details 2024-10-25): "Implement TLS 1.2, or subsequent versions" and
//                         "Disable known weak protocols such as Secure Sockets Layer (SSL) v2 and v3 and TLS 1.0 and 1.1."
//   certificate_valid     the chain verifies for the host name (Node's own check), with more than --web-cert-min-days
//                         days left (default 14).
//   https_redirect        GET http://<host><path>: a 301, 302, 307 or 308 to https://<same host>. The same canada.ca
//                         page, 1.1: service "only through a secure connection that is configured for HTTPS (and
//                         redirected from HTTP)". Port 80 not answering at all also passes: nothing is served in clear.
//   hsts                  Strict-Transport-Security on the HTTPS answer with max-age ≥ 31536000 (one year). RFC 6797
//                         §6.1.1: max-age is required; §8.1: a header received over plain HTTP is ignored, so only
//                         the HTTPS answer counts. canada.ca 1.2: "Enable HTTP Strict Transport Security (HSTS)."
//   csp                   an enforced Content-Security-Policy (Report-Only alone fails) with script-src or default-src,
//                         whose script sources do not allow 'unsafe-inline' unless a nonce or hash is also given
//                         (CSP Level 3 then ignores 'unsafe-inline'), nor *, https:, http: or data: unless
//                         'strict-dynamic' and a nonce or hash are given (CSP3 §6 and §8.2). OWASP HTTP Headers Cheat Sheet
//                         (cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).
//   content_type_options  X-Content-Type-Options: nosniff (OWASP, same page).
//   frame_protection      CSP frame-ancestors, or X-Frame-Options DENY or SAMEORIGIN (OWASP: "Use Content Security
//                         Policy (CSP) frame-ancestors directive if possible").
//   referrer_policy       a Referrer-Policy whose effective (last) value is not unsafe-url or no-referrer-when-downgrade
//                         (OWASP: "Set the header explicitly rather than relying on browser defaults").
//   no_version_banner     no digit in Server, and no X-Powered-By, X-AspNet-Version or X-AspNetMvc-Version (OWASP:
//                         Server "Remove this header or set non-informative values"; "Remove all X-Powered-By headers").
//   spf                   exactly one TXT record starting v=spf1 at the mail domain (RFC 7208 §4.5: more than one is a
//                         permerror), ending in -all or ~all (§5.1 "all"; qualifiers - and ~ give fail and softfail).
//   dmarc                 _dmarc.<domain> with p, sp and np each quarantine or reject (RFC 9989 §4.7, which obsoletes
//                         RFC 7489; sp and np default to p) after t=y lowers each a level, and pct 100 when given. With no
//                         record there, the parent domains are asked in turn up to two labels, and the parent's sp then
//                         governs the domain: RFC 9989 §4.10 walks to the Organizational Domain; this walk approximates it.
//   dnssec                a DS record for the domain, read by DNS over HTTPS (GET https://cloudflare-dns.com/dns-query,
//                         accept application/dns-json; developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/
//                         make-api-requests/dns-json/). Recommended, not required by the pages above.
//   caa                   a CAA record set at the domain or the nearest parent that has one (RFC 8659 §3 climbs the
//                         tree toward the root). Recommended.
//
// The mail domain is --web-mail-domain, or else the last two labels of each URL's host. That default is wrong for
// a host under a two-label public suffix (example.gc.ca gives gc.ca), so give --web-mail-domain there.
// Results carry host names, header values, protocol versions and dates: never page content, cookies or a person.

import { isIP } from "node:net";
import { resolveCaa, resolveTxt } from "node:dns/promises";
import tls from "node:tls";
import type { Result, Source, SourceContext } from "../types.ts";
import { COLLECTOR_VERSION } from "../payload.ts";
import { Emitter } from "./readonly_http.ts";

export const WEB_URL_CHECKS = ["tls_min_version", "certificate_valid", "https_redirect", "hsts", "csp", "content_type_options",
  "frame_protection", "referrer_policy", "no_version_banner"] as const;
export const WEB_DOMAIN_CHECKS = ["spf", "dmarc", "dnssec", "caa"] as const;
export const WEB_CHECKS = [...WEB_URL_CHECKS, ...WEB_DOMAIN_CHECKS] as const;
type C = (typeof WEB_CHECKS)[number];

export const USER_AGENT = `sagentix-evidence-collector/${COLLECTOR_VERSION} (+https://github.com/Sagentix-Advisors-Inc/sagentix-collector)`;
export const PROOF_PREFIX = "_sagentix-collector";
export const PROOF_TXT = "sagentix-collector-verification";
export const PROOF_PATH = "/.well-known/sagentix-collector.txt";
export const DEFAULTS = { delayMs: 1000, timeoutMs: 15_000, certMinDays: 14, hstsMinAge: 31_536_000 } as const;
const TOKEN = /^[A-Za-z0-9_-]{32,128}$/;
const DAY = 86_400_000;

export interface TlsInfo {
  /** The handshake completed. */
  ok: boolean;
  protocol?: string;
  /** The chain verified for the host name. */
  authorized?: boolean;
  authError?: string;
  validTo?: string;
  issuerOrg?: string;
  /** Why the handshake failed (an error code or "timeout"). */
  error?: string;
}
export interface WebDns {
  /** TXT records as joined strings; [] when the name has none; null when DNS could not answer. */
  txt(name: string): Promise<string[] | null>;
  /** CAA records as text ("0 issue \"letsencrypt.org\""); [] when none; null when unknown. */
  caa(name: string): Promise<string[] | null>;
}
export interface WebClient {
  fetch: typeof fetch;
  tls(host: string, o: { legacyOnly: boolean; timeoutMs: number }): Promise<TlsInfo>;
  dns: WebDns;
  sleep(ms: number): Promise<void>;
  /** Milliseconds, for the per-host delay. */
  clock(): number;
}

const dnsMissing = (e: unknown) => ["ENODATA", "ENOTFOUND"].includes(String((e as NodeJS.ErrnoException).code));

export function realWebClient(): WebClient {
  return {
    fetch: globalThis.fetch,
    tls: (host, o) => new Promise((resolve) => {
      let done = false;
      const finish = (r: TlsInfo) => { if (!done) { done = true; resolve(r); } };
      const s = tls.connect({
        host, port: 443, servername: host, rejectUnauthorized: false,   // read the certificate, judge `authorized` ourselves
        ...(o.legacyOnly ? { minVersion: "TLSv1" as const, maxVersion: "TLSv1.1" as const, ciphers: "DEFAULT@SECLEVEL=0" } : {}),
      });
      s.setTimeout(o.timeoutMs, () => { s.destroy(); finish({ ok: false, error: "timeout" }); });
      s.once("secureConnect", () => {
        const c = s.getPeerCertificate();
        finish({ ok: true, protocol: s.getProtocol() ?? undefined, authorized: s.authorized,
                 authError: s.authorizationError ? String(s.authorizationError) : undefined,
                 validTo: c?.valid_to, issuerOrg: typeof c?.issuer?.O === "string" ? c.issuer.O : undefined });
        s.end();
      });
      s.once("error", (e: NodeJS.ErrnoException) => finish({ ok: false, error: e.code ?? e.message }));
    }),
    dns: {
      async txt(name) { try { return (await resolveTxt(name)).map((r) => r.join("")); } catch (e) { return dnsMissing(e) ? [] : null; } },
      async caa(name) {
        // Node gives {critical, type: "CAA", issue: "…"} (or issuewild, iodef, …): the tag is the one other key.
        try { return (await resolveCaa(name)).map((r) => { const [tag, value] = Object.entries(r).find(([k]) => k !== "critical" && k !== "type") ?? ["?", ""]; return `${r.critical} ${tag} "${String(value)}"`; }); }
        catch (e) { return dnsMissing(e) ? [] : null; }
      },
    },
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    clock: () => Date.now(),
  };
}

const list = (v: unknown): string[] =>
  (Array.isArray(v) ? v : typeof v === "string" ? [v] : []).flatMap((s) => String(s).split(",")).map((s) => s.trim()).filter(Boolean);

/** A declared URL, or why it is refused. */
export function parseWebUrl(raw: string): URL | string {
  let u: URL;
  try { u = new URL(raw); } catch { return `${raw} is not a URL`; }
  if (u.protocol !== "https:") return `${raw}: only https URLs are checked (the HTTP redirect is tested from the https one)`;
  if (u.username || u.password) return `${raw}: a URL with a user name or password is refused`;
  if (u.port) return `${raw}: only the default port (443) is checked`;
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (isIP(host)) return `${raw}: an IP address cannot be proven by DNS; give the host name`;
  if (!host.includes(".")) return `${raw}: give a fully qualified host name`;
  u.hash = "";
  return u;
}

/** host → token from --web-proof host=token. */
export function parseProofs(v: unknown): Map<string, string> | string {
  const out = new Map<string, string>();
  for (const p of list(v)) {
    const i = p.indexOf("=");
    const host = p.slice(0, i).trim().toLowerCase(), token = p.slice(i + 1).trim();
    if (i < 1 || !TOKEN.test(token)) return `--web-proof takes <host>=<token>, the token being the 32 to 128 letters, digits, - or _ sos-app issued (got ${JSON.stringify(p.slice(0, 80))})`;
    out.set(host, token);
  }
  return out;
}

/** The default mail domain of a host: its last two labels. */
export const twoLabels = (host: string) => host.split(".").slice(-2).join(".");

const headerValue = (h: Headers, n: string) => h.get(n) ?? undefined;

/** The CSP directives of a header value (several policies joined by commas count together; the first of a name wins in each). */
export function cspDirectives(v: string): Map<string, string[]>[] {
  return v.split(",").map((policy) => {
    const m = new Map<string, string[]>();
    for (const d of policy.split(";")) {
      const [name, ...vals] = d.trim().split(/\s+/);
      if (name && !m.has(name.toLowerCase())) m.set(name.toLowerCase(), vals);
    }
    return m;
  });
}

export function judgeCsp(enforced: string | undefined, reportOnly: string | undefined): { pass: boolean; detail: string } {
  if (!enforced) return { pass: false, detail: reportOnly ? "only Content-Security-Policy-Report-Only is sent, which blocks nothing" : "no Content-Security-Policy header" };
  const policies = cspDirectives(enforced);
  const scripted = policies.filter((p) => p.has("script-src") || p.has("default-src"));
  if (!scripted.length) return { pass: false, detail: "Content-Security-Policy has neither script-src nor default-src, so scripts are not restricted" };
  // A script loads only when every policy allows it, so one strict policy is enough.
  // CSP Level 3 (www.w3.org/TR/CSP3/, read 2026-10-26), §6: developers "SHOULD NOT include either 'unsafe-inline', or
  // data: as valid sources in their policies. Both enable XSS attacks"; and "Schemes such as https: (which matches any
  // resource having the specified scheme)", so https: or http: lets in a script from any host, as * does. §8.2: with
  // 'strict-dynamic' beside a
  // nonce or hash, "host-source and scheme-source expressions, as well as the "'unsafe-inline'" and "'self'
  // keyword-sources will be ignored when loading script", which is how a strict policy stays backward compatible.
  const weak = (p: Map<string, string[]>) => {
    const src = (p.get("script-src") ?? p.get("default-src") ?? []).map((s) => s.toLowerCase());
    const keyed = src.some((s) => /^'(nonce-|sha256-|sha384-|sha512-)/i.test(s));
    const dynamic = keyed && src.includes("'strict-dynamic'");
    const anyHost = src.some((s) => s === "*" || /^(https?|data):$/.test(s));
    return (src.includes("'unsafe-inline'") && !keyed) || (anyHost && !dynamic);
  };
  const strict = scripted.find((p) => !weak(p));
  const extras = [...new Set(scripted.flatMap((p) => (p.get("script-src") ?? p.get("default-src") ?? []).filter((s) => s === "'unsafe-eval'")))];
  if (!strict) return { pass: false, detail: "script sources allow 'unsafe-inline' without a nonce or hash, or any origin (*, or a bare scheme such as https: or data:) without 'strict-dynamic' and a nonce or hash" };
  // A nonce changes on every answer, so its value is left out of the detail.
  const shown = (strict.get("script-src") ?? strict.get("default-src"))!.map((s) => s.replace(/^'nonce-[^']*'$/i, "'nonce-…'")).join(" ");
  return { pass: true, detail: `enforced; scripts from ${shown.slice(0, 300)}${extras.length ? "; note 'unsafe-eval' is allowed" : ""}` };
}

export function judgeReferrer(v: string | undefined): { pass: boolean; detail: string } {
  if (!v) return { pass: false, detail: "no Referrer-Policy header (browsers fall back to their default)" };
  const known = ["no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"];
  const effective = v.split(",").map((s) => s.trim().toLowerCase()).filter((s) => known.includes(s)).at(-1);
  if (!effective) return { pass: false, detail: `Referrer-Policy ${JSON.stringify(v.slice(0, 100))} names no policy browsers know` };
  const bad = effective === "unsafe-url" || effective === "no-referrer-when-downgrade";
  return { pass: !bad, detail: `Referrer-Policy ${effective}${bad ? " sends full URLs to other sites" : ""}` };
}

export function judgeHsts(v: string | undefined, min: number = DEFAULTS.hstsMinAge): { pass: boolean; detail: string } {
  if (!v) return { pass: false, detail: "no Strict-Transport-Security header on the HTTPS answer" };
  const age = Number(v.match(/(?:^|;)\s*max-age\s*=\s*"?(\d+)"?/i)?.[1] ?? NaN);
  if (!Number.isFinite(age)) return { pass: false, detail: "Strict-Transport-Security has no max-age (RFC 6797 §6.1.1 requires one)" };
  const flags = [/includesubdomains/i.test(v) && "includeSubDomains", /preload/i.test(v) && "preload"].filter(Boolean).join(", ");
  return { pass: age >= min, detail: `max-age ${age} s (at least ${min})${flags ? `; ${flags}` : ""}` };
}

export function judgeBanner(h: Headers): { pass: boolean; detail: string } {
  const server = headerValue(h, "server");
  const leaks = [server && /\d/.test(server) && `Server: ${server.slice(0, 80)}`,
    ...["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"].map((n) => h.get(n) !== null && `${n}: ${String(h.get(n)).slice(0, 80)}`)].filter(Boolean) as string[];
  return { pass: !leaks.length, detail: leaks.length ? `software versions shown: ${leaks.join("; ")}` : `no version in Server${server ? ` (${server.slice(0, 40)})` : " (absent)"}; no X-Powered-By or X-AspNet-Version` };
}

export function judgeSpf(records: string[]): { result: "pass" | "fail" | "skipped"; detail: string } {
  const spf = records.filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
  if (!spf.length) return { result: "fail", detail: "no TXT record starting v=spf1: anyone may send mail as this domain" };
  if (spf.length > 1) return { result: "fail", detail: `${spf.length} SPF records; RFC 7208 §4.5 makes that a permerror` };
  const terms = spf[0].trim().split(/\s+/).slice(1);
  const all = terms.find((t) => /^[+\-~?]?all$/i.test(t));
  if (!all) {
    const redirect = terms.find((t) => /^redirect=/i.test(t));
    return redirect ? { result: "skipped", detail: `the record ends in ${redirect.slice(0, 100)}; the target is not followed` }
      : { result: "fail", detail: `${spf[0].slice(0, 200)} has no "all" term, so unlisted senders get a neutral result` };
  }
  const q = /^[+\-~?]/.test(all) ? all[0] : "+";
  return { result: q === "-" || q === "~" ? "pass" : "fail", detail: `${spf[0].slice(0, 200)} (ends ${all}: ${q === "-" ? "fail" : q === "~" ? "softfail" : q === "?" ? "neutral" : "pass"} for unlisted senders)` };
}

// RFC 9989 (DMARC, May 2026, obsoletes RFC 7489; www.rfc-editor.org/rfc/rfc9989, read 2026-10-26), §4.7:
//   p  "The policy applies to the domain queried and to subdomains, unless the subdomain policy is explicitly
//      described using the "sp" or "np" tags."
//   sp "applies only to existing subdomains of the message's Organizational Domain"; "Note that "sp" will be ignored
//      for DMARC Policy Records published on subdomains of Organizational Domains and PSDs".
//   np for non-existent subdomains; absent, sp applies, else p.
//   t=y asks receivers to apply "one level below the specified policy" (reject acts as quarantine, quarantine as none).
//   pct is historic (Appendix A.6) but RFC 7489 receivers still sample by it, so anything under 100 still fails.
// So p=reject with sp=none leaves every subdomain open to spoofing, and a domain whose record was found at a parent
// is itself a subdomain, governed by the parent's sp. The Organizational Domain is approximated as two labels, as in
// the walk below.
const ENFORCE = ["quarantine", "reject"];
export function judgeDmarc(record: string | undefined, at: string, domain: string = at): { pass: boolean; detail: string } {
  if (!record) return { pass: false, detail: "no DMARC record at _dmarc of the domain or its parents" };
  const tags = new Map(record.split(";").map((t) => t.trim().split("=").map((s) => s.trim())).filter((kv) => kv.length === 2).map(([k, v]) => [k.toLowerCase(), v.toLowerCase()]));
  const p = tags.get("p"), pct = tags.has("pct") ? Number(tags.get("pct")) : 100, testing = tags.get("t") === "y";
  const orgLevel = at.split(".").length <= 2;
  const sp = orgLevel ? tags.get("sp") ?? p : p;
  const np = orgLevel ? tags.get("np") ?? sp : p;
  const applied = (v: string | undefined) => !testing ? v : v === "reject" ? "quarantine" : v === "quarantine" ? "none" : v;
  // A record found at a parent governs this domain as a subdomain; one at the domain must also cover its subdomains.
  const judged: [string, string | undefined][] = domain !== at ? [["sp", applied(sp)], ["np", applied(np)]] : [["p", applied(p)], ["sp", applied(sp)], ["np", applied(np)]];
  const weak = judged.filter(([, v]) => !ENFORCE.includes(v ?? ""));
  const ok = !weak.length && pct === 100;
  const shown = ["p", "sp", "np", "pct", "t"].filter((k) => tags.has(k)).map((k) => `${k}=${tags.get(k)}`).join(", ") || "p=(none)";
  const why = pct !== 100 ? "the policy covers only part of the mail"
    : `${weak.map(([k, v]) => `${k === "p" ? "the domain" : k === "sp" ? "existing subdomains" : "non-existent subdomains"} get ${v ?? "none"}`).join(", ")}${testing ? " (t=y: test mode applies one level lower)" : ""}; quarantine or reject required`;
  return { pass: ok, detail: `_dmarc.${at}: ${shown}${p === undefined ? " (no p: treated as none)" : ""}${domain !== at ? `; governs ${domain} as a subdomain` : ""}${ok ? "" : `; ${why}`}` };
}

/** Is a TLS error a local limit (this Node cannot offer the old protocol) or a network failure, rather than the server refusing? */
const LOCAL_TLS = /NO_PROTOCOLS_AVAILABLE|NO_CIPHERS_AVAILABLE|NO_SUITABLE/i;
const NETWORK = /^(timeout|ENOTFOUND|EAI_AGAIN|EHOSTUNREACH|ENETUNREACH|ECONNREFUSED|ETIMEDOUT)$/;

interface Ctx { client: WebClient; delayMs: number; timeoutMs: number; last: Map<string, number> }

/** Waits so that requests to one host are at least delayMs apart. */
async function pace(c: Ctx, host: string) {
  const prev = c.last.get(host);
  if (prev !== undefined) {
    const wait = prev + c.delayMs - c.client.clock();
    if (wait > 0) await c.client.sleep(wait);
  }
  c.last.set(host, c.client.clock());
}

async function get(c: Ctx, url: string, maxBody = 0): Promise<{ status: number; headers: Headers; body: string } | { error: string }> {
  await pace(c, new URL(url).hostname);
  try {
    const res = await c.client.fetch(url, { method: "GET", redirect: "manual", headers: { "user-agent": USER_AGENT, accept: "*/*" }, signal: AbortSignal.timeout(c.timeoutMs) });
    let body = "";
    if (maxBody > 0 && res.body) {
      const reader = res.body.getReader(), chunks: Uint8Array[] = [];
      let n = 0;
      while (n < maxBody) { const { done, value } = await reader.read(); if (done) break; chunks.push(value); n += value.length; }
      await reader.cancel().catch(() => undefined);
      body = new TextDecoder().decode(Buffer.concat(chunks).subarray(0, maxBody));
    } else await res.body?.cancel().catch(() => undefined);
    return { status: res.status, headers: res.headers, body };
  } catch (e) {
    const err = e as Error & { cause?: { code?: string } };
    return { error: err.cause?.code ?? (err.name === "TimeoutError" ? "timeout" : err.message.slice(0, 120)) };
  }
}

/** How the host was proven, or why not. Makes no request when no token is given. */
async function prove(c: Ctx, host: string, token: string | undefined): Promise<{ ok: true; how: string } | { ok: false; why: string }> {
  const howTo = `publish the TXT record ${PROOF_PREFIX}.${host} = "${PROOF_TXT}=<token>" or serve https://${host}${PROOF_PATH} holding that line, with the token sos-app issued, then give --web-proof ${host}=<token>`;
  if (!token) return { ok: false, why: `no --web-proof for ${host}, so nothing was sent to it; ${howTo}` };
  const line = `${PROOF_TXT}=${token}`;
  const txt = await c.client.dns.txt(`${PROOF_PREFIX}.${host}`);
  if (txt?.some((r) => r.trim() === line)) return { ok: true, how: `DNS TXT ${PROOF_PREFIX}.${host}` };
  const r = await get(c, `https://${host}${PROOF_PATH}`, 4096);
  if (!("error" in r) && r.status === 200 && r.body.split(/\r?\n/).some((l) => l.trim() === line)) return { ok: true, how: `https://${host}${PROOF_PATH}` };
  return { ok: false, why: `control of ${host} is not proven (TXT ${txt === null ? "lookup failed" : "has no matching record"}; ${PROOF_PATH} ${"error" in r ? r.error : `answered ${r.status}${r.status === 200 ? " without the token" : ""}`}); ${howTo}` };
}

async function urlChecks(c: Ctx, out: Emitter<C>, u: URL, prefix: string, certMinDays: number, now: Date) {
  const host = u.hostname, res = `url ${u.href}`.slice(0, 300);
  const add = (check: C, ok: boolean | "skipped", detail: string) => out.add(check, ok === "skipped" ? "skipped" : ok ? "pass" : "fail", prefix + detail, res);

  await pace(c, host);
  const modern = await c.client.tls(host, { legacyOnly: false, timeoutMs: c.timeoutMs });
  await pace(c, host);
  const legacy = await c.client.tls(host, { legacyOnly: true, timeoutMs: c.timeoutMs });
  if (!modern.ok) add("tls_min_version", "skipped", `no TLS handshake with ${host}:443 (${modern.error})`);
  else if (legacy.ok) add("tls_min_version", false, `the server accepted ${legacy.protocol ?? "TLS 1.1 or older"} when offered nothing newer; TLS 1.0 and 1.1 must be off`);
  else if (legacy.error && (LOCAL_TLS.test(legacy.error) || NETWORK.test(legacy.error))) add("tls_min_version", "skipped", `could not tell whether TLS 1.0 and 1.1 are refused (${legacy.error}); negotiated ${modern.protocol}`);
  else {
    const good = modern.protocol === "TLSv1.2" || modern.protocol === "TLSv1.3";
    add("tls_min_version", good, `TLS 1.0 and 1.1 refused (${legacy.error ?? "handshake failed"}); a default handshake negotiated ${modern.protocol ?? "an unknown version"}`);
  }
  if (!modern.ok) add("certificate_valid", "skipped", `no TLS handshake with ${host}:443 (${modern.error})`);
  else {
    const end = modern.validTo ? Date.parse(modern.validTo) : NaN;
    const days = Number.isFinite(end) ? Math.floor((end - now.getTime()) / DAY) : NaN;
    const who = modern.issuerOrg ? `issued by ${modern.issuerOrg.slice(0, 80)}, ` : "";
    if (!modern.authorized) add("certificate_valid", false, `${who}the chain does not verify for ${host}: ${modern.authError ?? "unknown reason"}`);
    else if (!Number.isFinite(days)) add("certificate_valid", "skipped", "the certificate's end date did not parse");
    else add("certificate_valid", days > certMinDays, `${who}verifies for ${host}; ${days} day(s) left, until ${new Date(end).toISOString().slice(0, 10)} (more than ${certMinDays} required)`);
  }

  const plain = new URL(u.href); plain.protocol = "http:";
  const r80 = await get(c, plain.href);
  if ("error" in r80) {
    if (r80.error === "ECONNREFUSED") add("https_redirect", true, `http://${host} refuses connections on port 80 (${r80.error}), so nothing is served without TLS`);
    else add("https_redirect", "skipped", `http://${host} could not be read (${r80.error})`);
  } else {
    const loc = r80.headers.get("location");
    let to: URL | undefined;
    try { to = loc ? new URL(loc, plain) : undefined; } catch { to = undefined; }
    const ok = [301, 302, 307, 308].includes(r80.status) && to?.protocol === "https:" && to.hostname === host;
    add("https_redirect", ok, ok ? `HTTP ${r80.status} to ${to!.origin}` : `http://${host} answered ${r80.status}${loc ? ` to ${loc.slice(0, 120)}` : " without a redirect"}; a redirect to https://${host} is required`);
  }

  const r = await get(c, u.href);
  if ("error" in r) {
    for (const k of ["hsts", "csp", "content_type_options", "frame_protection", "referrer_policy", "no_version_banner"] as const) add(k, "skipped", `${u.href} could not be read (${r.error})`);
    return;
  }
  // A bot challenge answered instead of the site: its headers are Cloudflare's, not the site's, so none is judged.
  // Cloudflare (Detect a Challenge Page response, updated 2026-05-05): "The header is set for all Challenge Page types."
  // and "For the cf-mitigated header, challenge is the only valid value."
  // developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
  if (headerValue(r.headers, "cf-mitigated")?.trim().toLowerCase() === "challenge") {
    for (const k of ["hsts", "csp", "content_type_options", "frame_protection", "referrer_policy", "no_version_banner"] as const)
      add(k, "skipped", `${u.href} answered a Cloudflare challenge page (HTTP ${r.status}, cf-mitigated: challenge), not the site; let the collector's address skip bot checks for this host to judge its headers`);
    return;
  }
  const h = r.headers, note = r.status >= 300 && r.status < 400 ? ` (headers of the ${r.status} answer; the redirect was not followed)` : "";
  const hs = judgeHsts(headerValue(h, "strict-transport-security"));
  add("hsts", hs.pass, hs.detail + note);
  const csp = judgeCsp(headerValue(h, "content-security-policy"), headerValue(h, "content-security-policy-report-only"));
  add("csp", csp.pass, csp.detail + note);
  const xcto = headerValue(h, "x-content-type-options");
  add("content_type_options", xcto?.trim().toLowerCase() === "nosniff", (xcto ? `X-Content-Type-Options: ${xcto.slice(0, 40)}` : "no X-Content-Type-Options header") + note);
  const fa = cspDirectives(headerValue(h, "content-security-policy") ?? "").map((p) => p.get("frame-ancestors")).find((v) => v && v.length && !v.includes("*"));
  const xfo = headerValue(h, "x-frame-options")?.trim().toUpperCase();
  add("frame_protection", !!fa || xfo === "DENY" || xfo === "SAMEORIGIN",
    (fa ? `CSP frame-ancestors ${fa.join(" ").slice(0, 120)}` : xfo ? `X-Frame-Options ${xfo.slice(0, 40)}` : "neither CSP frame-ancestors nor X-Frame-Options") + note);
  const rp = judgeReferrer(headerValue(h, "referrer-policy"));
  add("referrer_policy", rp.pass, rp.detail + note);
  const b = judgeBanner(h);
  add("no_version_banner", b.pass, b.detail + note);
}

async function dsRecord(c: Ctx, domain: string): Promise<{ result: "pass" | "fail" | "skipped"; detail: string }> {
  const doh = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=DS`;
  await pace(c, "cloudflare-dns.com");
  try {
    const res = await c.client.fetch(doh, { method: "GET", redirect: "manual", headers: { accept: "application/dns-json", "user-agent": USER_AGENT }, signal: AbortSignal.timeout(c.timeoutMs) });
    if (res.status !== 200) return { result: "skipped", detail: `DNS over HTTPS answered ${res.status}` };
    const j = await res.json() as { Status?: number; AD?: boolean; Answer?: { type?: number }[] };
    if (j.Status !== 0) return { result: "skipped", detail: `DNS over HTTPS answered status ${j.Status}` };
    const ds = (j.Answer ?? []).filter((a) => a.type === 43).length;
    return ds ? { result: "pass", detail: `${ds} DS record(s) at the parent zone${j.AD ? "; the answer validated (AD)" : ""}` }
      : { result: "fail", detail: "no DS record at the parent zone: the domain is not signed with DNSSEC (recommended)" };
  } catch (e) { return { result: "skipped", detail: `DNS over HTTPS not reachable (${(e as Error).name})` }; }
}

async function domainChecks(c: Ctx, out: Emitter<C>, domain: string, prefix: string) {
  const res = `domain ${domain}`;
  const put = (check: C, result: "pass" | "fail" | "skipped", detail: string) => out.add(check, result, prefix + detail, res);
  const txt = await c.client.dns.txt(domain);
  if (txt === null) put("spf", "skipped", `the TXT lookup for ${domain} failed`);
  else { const s = judgeSpf(txt); put("spf", s.result, s.detail); }

  const labels = domain.split(".");
  let dmarc: string | undefined, at = domain, failed = false;
  for (let i = 0; i <= labels.length - 2; i++) {
    const d = labels.slice(i).join("."), recs = await c.client.dns.txt(`_dmarc.${d}`);
    if (recs === null) { failed = true; break; }
    const found = recs.filter((r) => /^v=DMARC1\s*(;|$)/i.test(r.trim()));
    if (found.length > 1) { dmarc = undefined; at = d; put("dmarc", "fail", `${found.length} DMARC records at _dmarc.${d}; there must be one`); failed = true; break; }
    if (found.length) { dmarc = found[0]; at = d; break; }
  }
  if (!failed) { const m = judgeDmarc(dmarc, at, domain); put("dmarc", m.pass ? "pass" : "fail", m.detail); }
  else if (!out.results.some((r) => r.check === "web.dmarc" && r.resource === res)) put("dmarc", "skipped", "a DMARC lookup failed");

  const ds = await dsRecord(c, domain);
  put("dnssec", ds.result, ds.detail);

  let caa: string[] | null = [], from = domain;
  for (let i = 0; i <= labels.length - 2; i++) {
    from = labels.slice(i).join(".");
    caa = await c.client.dns.caa(from);
    if (caa === null || caa.length) break;
  }
  if (caa === null) put("caa", "skipped", `the CAA lookup for ${from} failed`);
  else if (!caa.length) put("caa", "fail", "no CAA record at the domain or its parents, so any certificate authority may issue for it (recommended)");
  else put("caa", "pass", `${caa.length} CAA record(s) at ${from}: ${caa.filter((x) => /issue/.test(x)).map((x) => x.replace(/^\d+\s+/, "")).join(", ").slice(0, 400)}`);
}

export async function runWeb(o: { urls: URL[]; proofs: Map<string, string>; mailDomains: string[]; skipProof: boolean; delayMs: number; timeoutMs: number; certMinDays: number },
                             client: WebClient, now: Date): Promise<Result[]> {
  const out = new Emitter<C>("web", "web");
  const c: Ctx = { client, delayMs: o.delayMs, timeoutMs: o.timeoutMs, last: new Map() };
  const proven = new Set<string>();
  const prefix = o.skipProof ? "control not proven (dry run only): " : "";
  for (const host of [...new Set(o.urls.map((u) => u.hostname))]) {
    if (o.skipProof) { proven.add(host); continue; }
    const p = await prove(c, host, o.proofs.get(host));
    if (p.ok) proven.add(host);
    else for (const u of o.urls.filter((x) => x.hostname === host)) out.skipAll(WEB_URL_CHECKS, p.why, `url ${u.href}`.slice(0, 300));
  }
  for (const u of o.urls) if (proven.has(u.hostname)) await urlChecks(c, out, u, prefix, o.certMinDays, now);
  const domains = [...new Set(o.mailDomains.length ? o.mailDomains : o.urls.map((u) => twoLabels(u.hostname)))];
  for (const d of domains) {
    // A mail domain is read only beside a proven host: the same domain, a parent, or a sibling under the same two labels.
    const near = [...proven].some((h) => h === d || h.endsWith(`.${d}`) || twoLabels(h) === twoLabels(d));
    if (!near) out.skipAll(WEB_DOMAIN_CHECKS, `no proven URL lies under ${twoLabels(d)}; prove one of its hosts first`, `domain ${d}`);
    else await domainChecks(c, out, d, prefix);
  }
  return out.results;
}

export const web: Source = {
  name: "web",
  options: {
    "web-url": { type: "string", multiple: true, help: "an https URL the organization runs (repeatable); only this URL is read, nothing is crawled" },
    "web-proof": { type: "string", multiple: true, help: "<host>=<token>: the token sos-app issued for the host, published in DNS or at /.well-known/sagentix-collector.txt (repeatable)" },
    "web-mail-domain": { type: "string", multiple: true, help: "domain whose SPF, DMARC, DNSSEC and CAA are read (default: the last two labels of each URL's host)" },
    "web-skip-proof": { type: "boolean", help: "run without proof of control; accepted only with --dry-run" },
    "web-delay-ms": { type: "string", help: `milliseconds between two requests to one host (default ${DEFAULTS.delayMs}, at least 200)` },
    "web-cert-min-days": { type: "string", help: `days a certificate must still be valid (default ${DEFAULTS.certMinDays})` },
  },
  emits: WEB_CHECKS.map((c) => `web.${c}`),
  describe(opts) {
    const urls = list(opts["web-url"]);
    return `URLs ${urls.length ? urls.map((u) => { try { return new URL(u).host; } catch { return "?"; } }).join(", ") : "(none given)"}`;
  },
  validate(opts) {
    if (opts["web-skip-proof"] === true && opts["dry-run"] !== true) return "--web-skip-proof is accepted only with --dry-run: a push to sos-app needs proof that the organization controls each host.";
    for (const raw of list(opts["web-url"])) { const u = parseWebUrl(raw); if (typeof u === "string") return u; }
    const p = parseProofs(opts["web-proof"]);
    if (typeof p === "string") return p;
    for (const d of list(opts["web-mail-domain"])) if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(d)) return `--web-mail-domain ${d} is not a domain name`;
    return undefined;
  },
  async run(ctx: SourceContext) {
    const urls = list(ctx.opts["web-url"]).map(parseWebUrl).filter((u): u is URL => typeof u !== "string");
    if (!urls.length) {
      const out = new Emitter<C>("web", "web");
      out.skipAll(WEB_CHECKS, "give --web-url <https URL> (and --web-proof <host>=<token>)");
      return out.results;
    }
    const proofs = parseProofs(ctx.opts["web-proof"]);
    const skipProof = ctx.opts["web-skip-proof"] === true && ctx.opts["dry-run"] === true;
    const n = (k: string, d: number, min = 0) => { const v = Number(ctx.opts[k]); return Number.isFinite(v) && typeof ctx.opts[k] === "string" ? Math.max(min, v) : d; };
    return runWeb({ urls, proofs: typeof proofs === "string" ? new Map() : proofs, mailDomains: list(ctx.opts["web-mail-domain"]).map((d) => d.toLowerCase()),
                    skipProof, delayMs: n("web-delay-ms", DEFAULTS.delayMs, 200), timeoutMs: DEFAULTS.timeoutMs, certMinDays: n("web-cert-min-days", DEFAULTS.certMinDays) },
                  (ctx.clients.web as WebClient | undefined) ?? realWebClient(), ctx.now);
  },
};
