// Fixtures for the web source, shared by test/web.test.ts and the end-to-end run (test/e2e.test.ts).
import { main, EXIT } from "../../../src/cli.ts";
import { USER_AGENT, judgeCsp, judgeDmarc, judgeReferrer, judgeSpf, parseWebUrl, runWeb, web, type TlsInfo, type WebClient } from "../../../src/sources/web.ts";
import { judgeConsent, judgeRequestChannel, noticeDate, noticeTopics, pageText, robotsAllows } from "../../../src/sources/web_privacy.ts";
import { capture } from "../../helpers.ts";

export const NOW = new Date("2026-10-18T12:00:00Z");
export const HOST = "app.example.ca", URL_ = `https://${HOST}/`, TOKEN = "a".repeat(40), PRIVACY = `https://${HOST}/privacy`;
export const HOME = `<html><head><script src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js"></script><script src="https://www.googletagmanager.com/gtm.js"></script></head><body>Hello</body></html>`;
export const NOTICE = `<html><head><title>Privacy notice | Example</title></head><body><h1>Privacy notice</h1><p>Last updated: March 4, 2026</p>
<h2>Information we collect</h2><p>We collect your name.</p><h2>How we use it</h2><p>For the purposes of support.</p>
<h2>Sharing</h2><p>We share with service providers.</p><h2>Retention</h2><p>We retain it for two years.</p>
<h2>Your rights</h2><p>You may request access to your information or correct it.</p><p>You may withdraw your consent.</p>
<p>Contact our privacy officer at <a href="mailto:privacy@example.ca">privacy@example.ca</a>.</p><script>var t="nothing here counts";</script></body></html>`;
export const GOOD_HEADERS = {
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "content-security-policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  server: "cloudflare",
};
export type Reply = { status: number; headers?: Record<string, string>; body?: string } | Error;

export interface Fake extends WebClient { calls: { url: string; method: string; headers: Record<string, string>; redirect?: string }[]; tlsCalls: { host: string; legacyOnly: boolean }[]; sleeps: number[] }

export function fake(o: { http?: Record<string, Reply>; tls?: Partial<Record<"modern" | "legacy", TlsInfo>>; txt?: Record<string, string[] | null>; caa?: Record<string, string[]> } = {}): Fake {
  const http: Record<string, Reply> = {
    [URL_]: { status: 200, headers: GOOD_HEADERS, body: HOME },
    [`https://${HOST}/robots.txt`]: { status: 200, body: "User-agent: *\nDisallow: /admin/\n" },
    [PRIVACY]: { status: 200, headers: { "content-type": "text/html; charset=utf-8" }, body: NOTICE },
    [`http://${HOST}/`]: { status: 301, headers: { location: URL_ } },
    [`https://${HOST}/.well-known/sagentix-collector.txt`]: { status: 404 },
    "https://cloudflare-dns.com/dns-query?name=example.ca&type=DS": { status: 200, headers: { "content-type": "application/dns-json" }, body: JSON.stringify({ Status: 0, AD: true, Answer: [{ type: 43, data: "1 13 2 ABC" }] }) },
    ...o.http,
  };
  const txt: Record<string, string[] | null> = {
    [`_sagentix-collector.${HOST}`]: [`sagentix-collector-verification=${TOKEN}`],
    "example.ca": ["v=spf1 include:_spf.example.net -all", "google-site-verification=x"],
    "_dmarc.example.ca": ["v=DMARC1; p=reject; rua=mailto:d@example.ca"],
    ...o.txt,
  };
  const caa: Record<string, string[]> = { "example.ca": ['0 issue "letsencrypt.org"'], ...o.caa };
  let t = 0;
  const f: Fake = {
    calls: [], tlsCalls: [], sleeps: [],
    fetch: (async (url: string | URL | Request, init?: RequestInit) => {
      const u = String(url);
      f.calls.push({ url: u, method: String(init?.method ?? "GET"), headers: init?.headers as Record<string, string>, redirect: init?.redirect });
      const r = http[u];
      if (!r) throw Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNREFUSED" } });
      if (r instanceof Error) throw r;
      return new Response(r.body ?? null, { status: r.status, headers: r.headers });
    }) as typeof fetch,
    tls: async (host, opts) => {
      f.tlsCalls.push({ host, legacyOnly: opts.legacyOnly });
      return opts.legacyOnly ? (o.tls?.legacy ?? { ok: false, error: "ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION" })
        : (o.tls?.modern ?? { ok: true, protocol: "TLSv1.3", authorized: true, validTo: "Jan 10 12:00:00 2027 GMT", issuerOrg: "Let's Encrypt" });
    },
    dns: { txt: async (n) => (n in txt ? txt[n] : []), caa: async (n) => caa[n] ?? [] },
    sleep: async (ms) => { f.sleeps.push(ms); t += ms; },
    clock: () => t,
  };
  return f;
}
