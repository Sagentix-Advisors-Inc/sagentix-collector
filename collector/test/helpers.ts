// Fakes shared by the tests. Nothing here touches the network.
import { readFileSync } from "node:fs";
import type { CloudflareApi, CfResponse } from "../src/sources/cloudflare/api.ts";
import type { OpaRunner } from "../src/sources/cloudflare/opa.ts";
import type { Deps } from "../src/cli.ts";
import { SOURCES } from "../src/sources/index.ts";

/** False in the public mirror, whose catalogues carry no control mappings (scripts/public-catalogue.mjs). */
export const MAPPED = JSON.parse(readFileSync(new URL("../../apps/sos-app/src/data/checks/cloudflare.json", import.meta.url), "utf8")).checks[0].hub !== undefined;
export const NO_MAPPINGS = !MAPPED && "the public catalogue carries no control mappings";

export const ZONE = "0123456789abcdef0123456789abcdef";
export const ACCOUNT = "fedcba9876543210fedcba9876543210";
export const NOW = new Date("2026-10-15T12:00:00Z");
export const inDays = (n: number) => new Date(NOW.getTime() + n * 86_400_000).toISOString();

export const okBody = (result: unknown, extra: Record<string, unknown> = {}): CfResponse =>
  ({ status: 200, body: { success: true, errors: [], messages: [], result, ...extra } });
export const errBody = (status: number, message = "Authentication error"): CfResponse =>
  ({ status, body: { success: false, errors: [{ code: 10000, message }], messages: [], result: null } });

const Z = `/zones/${ZONE}`, A = `/accounts/${ACCOUNT}`;
const setting = (id: string, value: unknown) => okBody({ id, value, editable: true });

/** A well-configured zone and account: every API check passes. Keyed by path without the query. */
export function strongRoutes(): Record<string, CfResponse> {
  return {
    "/zones": okBody([{ id: ZONE, name: "example.com", account: { id: ACCOUNT } }], { result_info: { page: 1, per_page: 50, total_pages: 1, count: 1 } }),
    [Z]: okBody({ id: ZONE, name: "example.com", account: { id: ACCOUNT }, plan: { legacy_id: "pro", name: "Pro Website" } }),
    [`${Z}/settings/min_tls_version`]: setting("min_tls_version", "1.2"),
    [`${Z}/settings/tls_1_3`]: setting("tls_1_3", "on"),
    [`${Z}/settings/always_use_https`]: setting("always_use_https", "on"),
    [`${Z}/settings/automatic_https_rewrites`]: setting("automatic_https_rewrites", "on"),
    [`${Z}/settings/ssl`]: setting("ssl", "strict"),
    [`${Z}/settings/security_header`]: setting("security_header", { strict_transport_security: { enabled: true, max_age: 31536000, include_subdomains: true, nosniff: true, preload: false } }),
    [`${Z}/settings/security_level`]: setting("security_level", "medium"),
    [`${Z}/settings/browser_check`]: setting("browser_check", "on"),
    [`${Z}/dnssec`]: okBody({ status: "active" }),
    [`${Z}/rulesets/phases/http_request_firewall_managed/entrypoint`]: okBody({ phase: "http_request_firewall_managed", rules: [{ action: "execute", enabled: true, action_parameters: { id: "efb7b8c949ac4650a09736fc376e9aee" } }] }),
    [`${Z}/rulesets/phases/http_request_firewall_custom/entrypoint`]: okBody({ phase: "http_request_firewall_custom", rules: [{ action: "block", enabled: true, expression: "ip.src.country eq \"T1\"" }] }),
    [`${Z}/rulesets/phases/http_ratelimit/entrypoint`]: okBody({ phase: "http_ratelimit", rules: [{ action: "block", enabled: true, ratelimit: { period: 60, requests_per_period: 100 } }] }),
    [`${Z}/bot_management`]: okBody({ fight_mode: true, enable_js: true }),
    [`${Z}/leaked-credential-checks`]: okBody({ enabled: true }),
    [`${Z}/ssl/certificate_packs`]: okBody([{ id: "pack1", type: "universal", status: "active", certificates: [{ id: "c1", status: "active", expires_on: inDays(60) }] }]),
    [`${Z}/custom_hostnames`]: okBody([{ id: "h1", hostname: "app.customer.test", ssl: { settings: { min_tls_version: "1.2" } } }]),
    [`${Z}/page_shield`]: okBody({ enabled: true, use_cloudflare_reporting_endpoint: true }),
    [`${Z}/security-center/securitytxt`]: okBody({ enabled: true, contact: ["mailto:security@example.com"], expires: inDays(300) }),
    [A]: okBody({ id: ACCOUNT, name: "Vendor", settings: { enforce_twofactor: true } }),
    [`${A}/members`]: okBody([
      { id: "m1", status: "accepted", roles: [{ id: "r1", name: "Super Administrator - All Privileges" }], user: { two_factor_authentication_enabled: true } },
      { id: "m2", status: "accepted", roles: [{ id: "r2", name: "Administrator" }], user: { two_factor_authentication_enabled: true } },
    ]),
    [`${A}/audit_logs`]: okBody([{ id: "a1", when: "2026-10-14T12:00:00Z" }]),
    [`${A}/tokens`]: okBody([{ id: "t1", name: "sagentix-collector-readonly", status: "active", expires_on: inDays(90) }]),
    [`${A}/alerting/v3/policies`]: okBody([{ id: "n1", name: "DDoS", alert_type: "dos_attack_l7", enabled: true }]),
    [`${A}/access/apps`]: okBody([{ id: "app1", name: "Admin", type: "self_hosted", domain: "admin.example.com", session_duration: "8h" }]),
    [`${A}/access/apps/app1/policies`]: okBody([{ id: "p1", decision: "allow", include: [{ email_domain: { domain: "example.com" } }], require: [{ auth_method: { auth_method: "mfa" } }], exclude: [] }]),
    [`${A}/gateway/rules`]: okBody([{ id: "g1", name: "Block malware", enabled: true, action: "block", filters: ["dns"], traffic: "any(dns.security_category[*] in {80})" }]),
    [`${A}/gateway/locations`]: okBody([{ id: "l1", name: "Office", client_default: true }]),
    [`${A}/devices/physical-devices`]: okBody([]),
    [`${A}/devices/posture`]: okBody([{ id: "d1", name: "Disk encrypted", type: "disk_encryption" }]),
    [`${A}/r2/buckets`]: okBody({ buckets: [{ name: "logs", creation_date: "2026-01-01T00:00:00Z" }] }),
    [`${A}/r2/buckets/logs/domains/managed`]: okBody({ bucketId: "b1", domain: "pub-1.r2.dev", enabled: false }),
  };
}

/** A fake read-only Cloudflare API. `over` replaces routes; every path asked is recorded. */
export function fakeCloudflare(over: Record<string, CfResponse | ((path: string) => CfResponse)> = {}, calls: string[] = []): CloudflareApi {
  const routes: Record<string, CfResponse | ((path: string) => CfResponse)> = { ...strongRoutes(), ...over };
  return {
    async get(path: string) {
      calls.push(path);
      const r = routes[path.split("?")[0]];
      if (r === undefined) return errBody(404, `no fake for ${path}`);
      return typeof r === "function" ? r(path) : r;
    },
  };
}

/** An opa runner that fails like a missing binary. */
export const missingOpa: OpaRunner = () => Promise.reject(Object.assign(new Error("spawn opa ENOENT"), { code: "ENOENT" }));

/** An opa runner that returns the given checks as `opa eval --format json` would. */
export function cannedOpa(checks: unknown[], seen: string[][] = []): OpaRunner {
  return async (args: string[]) => {
    seen.push(args);
    return { code: 0, stderr: "", stdout: JSON.stringify({ result: [{ expressions: [{ value: checks, text: "data.sagentix.cloudflare.checks" }] }] }) };
  };
}

export interface Captured { deps: Deps; stdout: string[]; stderr: string[]; posts: { url: string; init: RequestInit }[] }

export function capture(over: Partial<Deps> = {}, reply: { status: number; body: unknown } = { status: 201, body: { runId: "r1", checks: 1 } }): Captured {
  const stdout: string[] = [], stderr: string[] = [], posts: Captured["posts"] = [];
  const deps: Deps = {
    fetch: (async (url: string | URL | Request, init?: RequestInit) => {
      posts.push({ url: String(url), init: init ?? {} });
      return new Response(JSON.stringify(reply.body), { status: reply.status, headers: { "content-type": "application/json" } });
    }) as typeof fetch,
    clients: { cloudflare: fakeCloudflare(), opa: missingOpa },
    sources: SOURCES,
    env: {},
    now: () => NOW,
    out: (s) => stdout.push(s),
    err: (s) => stderr.push(s),
    ...over,
  };
  return { deps, stdout, stderr, posts };
}
