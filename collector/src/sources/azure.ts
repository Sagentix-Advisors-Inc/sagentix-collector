// Azure: Azure Resource Manager read with a service principal that holds Reader and Security Reader
// at subscription scope. Every ARM call is a GET. Microsoft Entra ID (users, MFA, roles) belongs to
// the Entra source, not this one.

import type { Result, Source } from "../types.ts";
import { API, ARM, CREDENTIAL_ENVS, fetchAzure, listAll, armMessage, tokenFromEnv, type AzureTransport } from "./azure/api.ts";
import { AZURE_CHECKS, subscriptionChecks } from "./azure/checks.ts";
import { allSkipped, httpWhy, list, scrub, str } from "./shared-cloud.ts";

export const DEFAULT_MIN_SECURE_SCORE = 0;

export const azure: Source = {
  name: "azure",
  options: {
    "azure-subscription": { type: "string", multiple: true, help: "Azure subscription id; default: every subscription the identity can list" },
    "azure-min-secure-score": { type: "string", help: `lowest Defender for Cloud secure score accepted, in percent (default ${DEFAULT_MIN_SECURE_SCORE})` },
  },
  emits: AZURE_CHECKS.map((c) => `azure.${c}`),
  describe(opts) {
    const s = list(opts["azure-subscription"]);
    return s.length ? `subscriptions ${s.join(",")}` : "every subscription the identity lists";
  },
  async run(ctx) {
    const secrets = [...CREDENTIAL_ENVS.map((k) => ctx.env[k])];
    const given = ctx.clients.azure as AzureTransport | null | undefined;
    let t: AzureTransport | null;
    if (given !== undefined) t = given;
    else {
      const token = tokenFromEnv(ctx.env);
      t = token ? fetchAzure(token) : null;
    }
    let subs = list(ctx.opts["azure-subscription"]);
    if (!t) {
      const reason = "no Azure credential: set AZURE_ACCESS_TOKEN, or AZURE_TENANT_ID and AZURE_CLIENT_ID with AZURE_FEDERATED_TOKEN_FILE or AZURE_CLIENT_SECRET";
      return (subs.length ? subs : ["(none listed)"]).flatMap((s) => allSkipped("azure", AZURE_CHECKS, `subscription ${s}`, reason));
    }
    const out: Result[] = [];
    if (!subs.length) {
      const r = await listAll(t, `${ARM}/subscriptions?api-version=${API.subscriptions}`);
      if ("error" in r) {
        const reason = `subscriptions not listable: ${httpWhy(r.error.reply, armMessage(r.error))}; give --azure-subscription`;
        ctx.warn(`azure: ${reason}`);
        return scrub(allSkipped("azure", AZURE_CHECKS, "subscription (list)", reason), secrets);
      }
      subs = r.items.filter((s) => s.state === undefined || s.state === "Enabled").map((s) => str(s.subscriptionId)).filter((x): x is string => !!x);
      if (!subs.length) return allSkipped("azure", AZURE_CHECKS, "subscription (list)", "the identity can list no enabled subscription; give --azure-subscription");
    }
    const min = Number(ctx.opts["azure-min-secure-score"] ?? DEFAULT_MIN_SECURE_SCORE);
    for (const s of [...new Set(subs)]) out.push(...(await subscriptionChecks(t, s, { minSecureScore: Number.isFinite(min) ? min : DEFAULT_MIN_SECURE_SCORE, now: ctx.now })));
    return scrub(out, secrets);
  },
};
