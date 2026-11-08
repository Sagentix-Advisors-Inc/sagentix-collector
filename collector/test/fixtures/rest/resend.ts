// Fixtures for the resend source, shared by test/resend.test.ts and the end-to-end run (test/e2e.test.ts).
import { RESEND_BASE, resend, resendFromEnv, resendTime } from "../../../src/sources/resend.ts";
import { contractSuite, fakeRest, of, res, runWith, type Contract, type Routes } from "../../rest_fakes.ts";

// A fake key built at run time, so no key-shaped literal sits in the source for a secret scanner to flag.
export const RE_KEY = ["re", "abcdefgh12345678"].join("_");
export const ok = (b: unknown) => res(200, b);
export const list = (data: unknown[], has_more = false) => ok({ object: "list", has_more, data });
// Resend's own timestamp shape, relative to NOW (2026-10-15T12:00:00Z).
export const ago = (days: number) => new Date(Date.parse("2026-10-15T12:00:00Z") - days * 86_400_000).toISOString().replace("T", " ").replace("Z", "123+00");
export const rec = (record: string, type: string, status = "verified") => ({ record, name: "send", type, ttl: "Auto", status, value: "v=spf1 include:amazonses.com ~all" });
export const domain = (id: string, name: string, status = "verified", records = [rec("SPF", "MX"), rec("SPF", "TXT"), rec("DKIM", "TXT")]) =>
  ({ object: "domain", id, name, status, created_at: ago(200), region: "us-east-1", open_tracking: false, click_tracking: false, capabilities: { sending: "enabled", receiving: "disabled" }, records });

export function strong(): Routes {
  return {
    "/domains": list([
      { id: "d1", name: "sagentix.example", status: "verified", created_at: ago(200), region: "us-east-1", capabilities: { sending: "enabled", receiving: "disabled" } },
      { id: "d2", name: "inbound.example", status: "not_started", created_at: ago(10), region: "us-east-1", capabilities: { sending: "disabled", receiving: "enabled" } },
    ]),
    "/domains/d1": ok(domain("d1", "sagentix.example")),
    "/api-keys": list([{ id: "k1", name: "Production (Alice)", created_at: ago(100), last_used_at: ago(1) }]),
  };
}

export const C: Contract = {
  source: resend, clientKey: "resend", base: RESEND_BASE, prefix: "resend", strong,
  env: { RESEND_API_KEY: RE_KEY },
  rateLimited: { path: "/api-keys", check: "api_keys_rotated" },
  fails: {
    sending_domains_authenticated: { "/domains/d1": ok(domain("d1", "sagentix.example", "partially_verified", [rec("SPF", "MX"), rec("DKIM", "TXT", "failed")])) },
    api_keys_rotated: { "/api-keys": list([{ id: "k1", created_at: ago(400), last_used_at: ago(1) }]) },
    api_keys_in_use: { "/api-keys": list([{ id: "k1", created_at: ago(10), last_used_at: null }]) },
  },
};
