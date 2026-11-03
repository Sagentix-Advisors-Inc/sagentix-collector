// The Stripe source against a fake API shaped like GET /v1/webhook_endpoints (docs.stripe.com/api/webhook_endpoints/list
// and Stripe's OpenAPI spec3.json, read 2026-11-02).
import { test } from "node:test";
import assert from "node:assert/strict";
import { STRIPE_BASE, stripe, stripeFromEnv, stripeKeyProblem } from "../src/sources/stripe.ts";
import { contractSuite, fakeRest, of, res, runWith, type Contract, type Routes } from "./rest_fakes.ts";

// Fake keys built at run time, so no key-shaped literal sits in the source for a secret scanner to flag.
const fake = (kind: string, mode: string) => [kind, mode, "abcdefgh12345678"].join("_");
const RK_LIVE = fake("rk", "live"), RK_TEST = fake("rk", "test"), SK_LIVE = fake("sk", "live");

const ok = (b: unknown) => res(200, b);
const ep = (id: string, url: string, events: string[], status = "enabled") =>
  ({ id, object: "webhook_endpoint", api_version: null, application: null, created: 1680122196, description: null, enabled_events: events, livemode: true, metadata: {}, status, url });
const page = (data: unknown[], has_more = false) => ok({ object: "list", url: "/v1/webhook_endpoints", has_more, data });

function strong(): Routes {
  return {
    "/v1/webhook_endpoints": page([
      ep("we_1", "https://app.example.com/api/billing/webhook", ["checkout.session.completed", "invoice.paid"]),
      ep("we_2", "http://old.example.com/hook", ["*"], "disabled"),
    ]),
  };
}

const C: Contract = {
  source: stripe, clientKey: "stripe", base: STRIPE_BASE, prefix: "stripe", strong,
  env: { STRIPE_API_KEY: RK_LIVE },
  rateLimited: { path: "/v1/webhook_endpoints", check: "webhooks_https" },
  fails: {
    webhooks_https: { "/v1/webhook_endpoints": page([ep("we_1", "http://app.example.com/hook?secret=x", ["invoice.paid"])]) },
    webhook_events_scoped: { "/v1/webhook_endpoints": page([ep("we_1", "https://app.example.com/hook", ["*"])]) },
  },
};

contractSuite(C);

test("stripe: a secret key is refused before any request, even with a client handed in", async () => {
  const calls: string[] = [];
  const rs = await runWith(C, fakeRest(STRIPE_BASE, strong(), calls), { env: { STRIPE_API_KEY: SK_LIVE } });
  assert.equal(calls.length, 0);
  for (const r of rs) { assert.equal(r.result, "skipped"); assert.match(r.detail, /secret key \(sk_\)/); }
  assert.ok(!JSON.stringify(rs).includes(SK_LIVE));
  assert.match(stripeKeyProblem("pk_live_x") ?? "", /not a restricted/);
  assert.equal(stripeKeyProblem("rk_test_x"), undefined);
  assert.equal(typeof stripeFromEnv({ STRIPE_API_KEY: "sk_test_x" }), "string");
});

test("stripe: follows starting_after pages; disabled endpoints are not judged; results show hosts, never paths", async () => {
  const calls: string[] = [];
  const routes: Routes = {
    "/v1/webhook_endpoints": (url) => new URL(`https://x${url}`).searchParams.get("starting_after") === "we_1"
      ? page([ep("we_2", "http://plain.example.com/p/q?token=abc", ["invoice.paid"])])
      : page([ep("we_1", "https://ok.example.com/a", ["invoice.paid"])], true),
  };
  const rs = await runWith(C, fakeRest(STRIPE_BASE, routes, calls));
  assert.equal(calls.length, 2);
  const r = of(rs, "stripe.webhooks_https")[0];
  assert.equal(r.result, "fail");
  assert.match(r.detail, /we_2:plain\.example\.com/);
  assert.ok(!JSON.stringify(rs).includes("token=abc") && !JSON.stringify(rs).includes("/p/q"));
  const off = await runWith(C, fakeRest(STRIPE_BASE, { "/v1/webhook_endpoints": page([ep("we_9", "http://x.example.com", ["*"], "disabled")]) }));
  for (const x of off) assert.equal(x.result, "skipped");
});

test("stripe: a sandbox key marks the resource; the real client sends GET with a Bearer key to api.stripe.com only", async () => {
  const rs = await runWith(C, fakeRest(STRIPE_BASE, strong()), { env: { STRIPE_API_KEY: RK_TEST } });
  assert.ok(rs.every((r) => r.resource.endsWith("(sandbox)")));
  const seen: { url: string; init: RequestInit }[] = [];
  const api = stripeFromEnv({ STRIPE_API_KEY: RK_LIVE }, (async (url: string, init: RequestInit) => { seen.push({ url, init }); return new Response("{}", { status: 200 }); }) as unknown as typeof fetch);
  assert.ok(typeof api !== "string");
  await api.get("/v1/webhook_endpoints?limit=100");
  assert.equal(seen[0].url, "https://api.stripe.com/v1/webhook_endpoints?limit=100");
  assert.equal(seen[0].init.method, "GET");
  assert.equal((seen[0].init.headers as Record<string, string>).authorization, `Bearer ${RK_LIVE}`);
  assert.equal((await api.get("https://evil.example/v1/x")).status, 0);
});
