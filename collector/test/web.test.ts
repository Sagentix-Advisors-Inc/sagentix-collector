// The web source against a fake network: no request leaves the machine.
import { test } from "node:test";
import assert from "node:assert/strict";
import { main, EXIT } from "../src/cli.ts";
import { USER_AGENT, judgeCsp, judgeDmarc, judgeReferrer, judgeSpf, parseWebUrl, runWeb, web, type TlsInfo, type WebClient } from "../src/sources/web.ts";
import { capture } from "./helpers.ts";

const NOW = new Date("2026-10-18T12:00:00Z");
const HOST = "app.example.ca", URL_ = `https://${HOST}/`, TOKEN = "a".repeat(40);
const GOOD_HEADERS = {
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "content-security-policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  server: "cloudflare",
};
type Reply = { status: number; headers?: Record<string, string>; body?: string } | Error;

interface Fake extends WebClient { calls: { url: string; method: string; headers: Record<string, string>; redirect?: string }[]; tlsCalls: { host: string; legacyOnly: boolean }[]; sleeps: number[] }

function fake(o: { http?: Record<string, Reply>; tls?: Partial<Record<"modern" | "legacy", TlsInfo>>; txt?: Record<string, string[] | null>; caa?: Record<string, string[]> } = {}): Fake {
  const http: Record<string, Reply> = {
    [URL_]: { status: 200, headers: GOOD_HEADERS, body: "<html>" },
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

const opts = (over: Partial<Parameters<typeof runWeb>[0]> = {}) => ({
  urls: [new URL(URL_)], proofs: new Map([[HOST, TOKEN]]), mailDomains: [] as string[], skipProof: false, delayMs: 1000, timeoutMs: 5000, certMinDays: 14, ...over,
});
const by = (rs: Awaited<ReturnType<typeof runWeb>>) => Object.fromEntries(rs.map((r) => [r.check.replace("web.", ""), r]));

test("a well-run site passes every check, after proof by DNS TXT", async () => {
  const f = fake();
  const rs = await runWeb(opts(), f, NOW);
  assert.equal(rs.length, web.emits.length);
  for (const r of rs) assert.equal(r.result, "pass", `${r.check}: ${r.detail}`);
  const b = by(rs);
  assert.equal(b.hsts.resource, `url ${URL_}`);
  assert.equal(b.spf.resource, "domain example.ca");
  assert.match(b.certificate_valid.detail, /84 day\(s\) left, until 2027-01-10/);
  assert.match(b.tls_min_version.detail, /negotiated TLSv1\.3/);
  assert.match(b.dnssec.detail, /AD/);
  // No well-known GET: the TXT record proved the host.
  assert.ok(!f.calls.some((c) => c.url.includes(".well-known")));
});

test("only GET, never a redirect followed, always the collector's User-Agent, and requests to a host are paced", async () => {
  const f = fake();
  await runWeb(opts(), f, NOW);
  assert.ok(f.calls.length > 0);
  for (const c of f.calls) {
    assert.equal(c.method, "GET");
    assert.equal(c.redirect, "manual");
    assert.equal(c.headers["user-agent"], USER_AGENT);
  }
  assert.match(USER_AGENT, /^sagentix-evidence-collector\/\d+\.\d+\.\d+ \(\+https:\/\/github\.com\//);
  // Two TLS handshakes and two GETs to one host: three waits of up to 1000 ms between them.
  assert.equal(f.sleeps.filter((ms) => ms === 1000).length, 3);
  // Only the exact URL and its http:// form are read on the host: nothing is crawled.
  assert.deepEqual(f.calls.filter((c) => c.url.includes(HOST)).map((c) => c.url).sort(), [`http://${HOST}/`, URL_].sort());
});

test("a host without --web-proof gets no request at all, and every check on it is skipped", async () => {
  const f = fake();
  const rs = await runWeb(opts({ proofs: new Map() }), f, NOW);
  assert.equal(f.tlsCalls.length, 0);
  assert.equal(f.calls.filter((c) => c.url.includes(HOST)).length, 0);
  for (const r of rs) assert.equal(r.result, "skipped", r.check);
  assert.match(by(rs).hsts.detail, /no --web-proof for app\.example\.ca, so nothing was sent to it; publish the TXT record _sagentix-collector\.app\.example\.ca/);
  assert.match(by(rs).spf.detail, /no proven URL lies under example\.ca/);
});

test("a wrong token: one DNS lookup and one well-known GET, then nothing else", async () => {
  const f = fake({ txt: { [`_sagentix-collector.${HOST}`]: ["sagentix-collector-verification=someone-elses-token-0000000000000"] } });
  const rs = await runWeb(opts(), f, NOW);
  assert.equal(f.tlsCalls.length, 0);
  assert.deepEqual(f.calls.filter((c) => c.url.includes(HOST)).map((c) => c.url), [`https://${HOST}/.well-known/sagentix-collector.txt`]);
  assert.ok(rs.every((r) => r.result === "skipped"));
  assert.match(by(rs).csp.detail, /control of app\.example\.ca is not proven/);
});

test("the well-known file proves a host when DNS does not", async () => {
  const f = fake({ txt: { [`_sagentix-collector.${HOST}`]: [] }, http: { [`https://${HOST}/.well-known/sagentix-collector.txt`]: { status: 200, body: `# sagentix\nsagentix-collector-verification=${TOKEN}\n` } } });
  const rs = await runWeb(opts(), f, NOW);
  assert.ok(rs.every((r) => r.result === "pass"), JSON.stringify(rs.filter((r) => r.result !== "pass")));
});

test("a well-known file that redirects is not followed and proves nothing", async () => {
  const f = fake({ txt: { [`_sagentix-collector.${HOST}`]: [] }, http: { [`https://${HOST}/.well-known/sagentix-collector.txt`]: { status: 302, headers: { location: "https://elsewhere.example/x" } } } });
  const rs = await runWeb(opts(), f, NOW);
  assert.ok(rs.every((r) => r.result === "skipped"));
  assert.ok(!f.calls.some((c) => c.url.includes("elsewhere")));
});

test("--web-skip-proof runs the checks, marks every detail, and the CLI refuses it without --dry-run", async () => {
  const f = fake();
  const rs = await runWeb(opts({ proofs: new Map(), skipProof: true }), f, NOW);
  assert.ok(rs.every((r) => r.result === "pass" && r.detail.startsWith("control not proven (dry run only): ")));
  const c = capture({ clients: { web: fake() } });
  assert.equal(await main(["run", "--endpoint", "https://sos.example.test", "--key-id", "k", "--source", "web", "--web-url", URL_, "--web-skip-proof"], c.deps), EXIT.usage);
  assert.match(c.stderr.join("\n"), /accepted only with --dry-run/);
  assert.equal(c.posts.length, 0);
  const d = capture({ clients: { web: fake() } });
  assert.equal(await main(["run", "--endpoint", "https://sos.example.test", "--source", "web", "--web-url", URL_, "--web-skip-proof", "--dry-run"], d.deps), EXIT.ok, d.stderr.join("\n"));
  assert.equal(d.posts.length, 0);
});

test("each URL check fails on the setting it reads", async () => {
  const f = fake({
    tls: { legacy: { ok: true, protocol: "TLSv1" }, modern: { ok: true, protocol: "TLSv1.2", authorized: false, authError: "CERT_HAS_EXPIRED", validTo: "Oct 1 00:00:00 2026 GMT" } },
    http: {
      [`http://${HOST}/`]: { status: 200 },
      [URL_]: { status: 200, headers: { "strict-transport-security": "max-age=86400", "content-security-policy-report-only": "default-src 'self'",
        "x-content-type-options": "sniff", "x-frame-options": "ALLOW-FROM https://x", "referrer-policy": "unsafe-url", server: "Apache/2.4.58 (Ubuntu)", "x-powered-by": "PHP/8.3" } },
    },
  });
  const b = by(await runWeb(opts(), f, NOW));
  for (const k of ["tls_min_version", "certificate_valid", "https_redirect", "hsts", "csp", "content_type_options", "frame_protection", "referrer_policy", "no_version_banner"]) assert.equal(b[k].result, "fail", `${k}: ${b[k].detail}`);
  assert.match(b.tls_min_version.detail, /accepted TLSv1/);
  assert.match(b.certificate_valid.detail, /CERT_HAS_EXPIRED/);
  assert.match(b.hsts.detail, /max-age 86400/);
  assert.match(b.csp.detail, /Report-Only/);
  assert.match(b.no_version_banner.detail, /Apache\/2\.4\.58.*x-powered-by: PHP\/8\.3/);
});

test("a certificate close to expiry fails; a redirect to another host fails; port 80 refusing passes", async () => {
  const soon = fake({ tls: { modern: { ok: true, protocol: "TLSv1.3", authorized: true, validTo: "Oct 25 00:00:00 2026 GMT" } }, http: { [`http://${HOST}/`]: { status: 301, headers: { location: "https://other.example.ca/" } } } });
  const b = by(await runWeb(opts(), soon, NOW));
  assert.equal(b.certificate_valid.result, "fail");
  assert.match(b.certificate_valid.detail, /6 day\(s\) left/);
  assert.equal(b.https_redirect.result, "fail");
  const closed = fake({ http: { [`http://${HOST}/`]: Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNREFUSED" } }) } });
  assert.equal(by(await runWeb(opts(), closed, NOW)).https_redirect.result, "pass");
});

test("a TLS 1.1 probe this machine cannot make is skipped, never passed", async () => {
  const f = fake({ tls: { legacy: { ok: false, error: "ERR_SSL_NO_PROTOCOLS_AVAILABLE" } } });
  assert.equal(by(await runWeb(opts(), f, NOW)).tls_min_version.result, "skipped");
});

test("each domain check fails on the record it reads", async () => {
  const f = fake({ txt: { "example.ca": ["v=spf1 +all"], "_dmarc.example.ca": ["v=DMARC1; p=none"] }, caa: { "example.ca": [] },
    http: { "https://cloudflare-dns.com/dns-query?name=example.ca&type=DS": { status: 200, body: JSON.stringify({ Status: 0, AD: false }) } } });
  const b = by(await runWeb(opts(), f, NOW));
  for (const k of ["spf", "dmarc", "dnssec", "caa"]) assert.equal(b[k].result, "fail", `${k}: ${b[k].detail}`);
});

test("DMARC and CAA are looked up at the parent when the domain has none; --web-mail-domain chooses the domain", async () => {
  const f = fake({ txt: { "mail.example.ca": ["v=spf1 -all"], "_dmarc.mail.example.ca": [] }, caa: { "mail.example.ca": [] },
    http: { "https://cloudflare-dns.com/dns-query?name=mail.example.ca&type=DS": { status: 200, body: JSON.stringify({ Status: 0, Answer: [{ type: 43 }] }) } } });
  const b = by(await runWeb(opts({ mailDomains: ["mail.example.ca"] }), f, NOW));
  assert.equal(b.dmarc.result, "pass");
  assert.match(b.dmarc.detail, /_dmarc\.example\.ca: p=reject/);
  assert.equal(b.caa.result, "pass");
  assert.match(b.caa.detail, /at example\.ca/);
  assert.equal(b.spf.resource, "domain mail.example.ca");
});

test("judges: SPF, DMARC, CSP and Referrer-Policy edge cases", () => {
  assert.equal(judgeSpf(["v=spf1 -all", "v=spf1 ~all"]).result, "fail");
  assert.equal(judgeSpf(["v=spf1 ip4:192.0.2.1 ~all"]).result, "pass");
  assert.equal(judgeSpf(["v=spf1 redirect=_spf.example.net"]).result, "skipped");
  assert.equal(judgeDmarc("v=DMARC1; p=quarantine; pct=50", "x.ca").pass, false);
  assert.equal(judgeDmarc("v=DMARC1; p=quarantine", "x.ca").pass, true);
  assert.equal(judgeCsp("script-src 'self' 'unsafe-inline'", undefined).pass, false);
  assert.equal(judgeCsp("script-src 'self' 'unsafe-inline' 'nonce-abc'", undefined).pass, true);
  assert.equal(judgeCsp("img-src 'self'", undefined).pass, false);
  assert.equal(judgeReferrer("unsafe-url, strict-origin").pass, true);
  assert.equal(judgeReferrer("no-referrer-when-downgrade").pass, false);
});

test("declared URLs: https only, default port, no user info, no IP address", () => {
  assert.ok(parseWebUrl("https://app.example.ca/path?q=1") instanceof URL);
  for (const bad of ["http://app.example.ca/", "https://u:p@app.example.ca/", "https://app.example.ca:8443/", "https://192.0.2.1/", "https://[2001:db8::1]/", "https://localhost/"]) {
    assert.equal(typeof parseWebUrl(bad), "string", bad);
  }
  assert.match(web.validate!({ "web-proof": ["app.example.ca=short"] })!, /--web-proof takes <host>=<token>/);
  assert.equal(web.validate!({ "web-url": [URL_], "web-proof": [`${HOST}=${TOKEN}`] }), undefined);
});
