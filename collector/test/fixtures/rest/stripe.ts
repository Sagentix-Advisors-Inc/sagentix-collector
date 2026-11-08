// Fixtures for the stripe source, shared by test/stripe.test.ts and the end-to-end run (test/e2e.test.ts).
import { STRIPE_BASE, stripe, stripeFromEnv, stripeKeyProblem } from "../../../src/sources/stripe.ts";
import { contractSuite, fakeRest, of, res, runWith, type Contract, type Routes } from "../../rest_fakes.ts";

// Fake keys built at run time, so no key-shaped literal sits in the source for a secret scanner to flag.
export const fake = (kind: string, mode: string) => [kind, mode, "abcdefgh12345678"].join("_");
export const RK_LIVE = fake("rk", "live"), RK_TEST = fake("rk", "test"), SK_LIVE = fake("sk", "live");

export const ok = (b: unknown) => res(200, b);
export const ep = (id: string, url: string, events: string[], status = "enabled") =>
  ({ id, object: "webhook_endpoint", api_version: null, application: null, created: 1680122196, description: null, enabled_events: events, livemode: true, metadata: {}, status, url });
export const page = (data: unknown[], has_more = false) => ok({ object: "list", url: "/v1/webhook_endpoints", has_more, data });

export function strong(): Routes {
  return {
    "/v1/webhook_endpoints": page([
      ep("we_1", "https://app.example.com/api/billing/webhook", ["checkout.session.completed", "invoice.paid"]),
      ep("we_2", "http://old.example.com/hook", ["*"], "disabled"),
    ]),
  };
}

export const C: Contract = {
  source: stripe, clientKey: "stripe", base: STRIPE_BASE, prefix: "stripe", strong,
  env: { STRIPE_API_KEY: RK_LIVE },
  rateLimited: { path: "/v1/webhook_endpoints", check: "webhooks_https" },
  fails: {
    webhooks_https: { "/v1/webhook_endpoints": page([ep("we_1", "http://app.example.com/hook?secret=x", ["invoice.paid"])]) },
    webhook_events_scoped: { "/v1/webhook_endpoints": page([ep("we_1", "https://app.example.com/hook", ["*"])]) },
  },
};
