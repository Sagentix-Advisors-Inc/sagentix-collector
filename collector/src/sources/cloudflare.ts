// Cloudflare: the API (read-only token in CLOUDFLARE_API_TOKEN_READONLY) and, when --tofu-state is
// given, the OPA policies over the OpenTofu state. Every call is a GET.

import type { OptionValue, Result, Source, SourceContext } from "../types.ts";
import { ACCOUNT_CHECKS, DEFAULT_MAX_SUPER_ADMINS, accountChecks, accountSkipped } from "./cloudflare/account.ts";
import { TOKEN_ENV, fetchCloudflareApi, getAll, isObj, str, why, type CloudflareApi } from "./cloudflare/api.ts";
import { DEFAULT_POLICY_DIR, OPA_CHECKS, opaChecks, spawnOpa } from "./cloudflare/opa.ts";
import { ZONE_CHECKS, zoneChecks, zoneSkipped } from "./cloudflare/zone.ts";

const list = (v: OptionValue): string[] => (Array.isArray(v) ? v : typeof v === "string" ? [v] : []).flatMap((s) => s.split(",")).map((s) => s.trim()).filter(Boolean);

async function apiChecks(api: CloudflareApi | null, ctx: SourceContext): Promise<Result[]> {
  const accounts = list(ctx.opts.account);
  let zones = list(ctx.opts.zone);
  if (!api) {
    const reason = `${TOKEN_ENV} is not set`;
    return [
      ...(zones.length ? zones : ["(none listed)"]).flatMap((z) => zoneSkipped(`zone ${z}`, reason)),
      ...(accounts.length ? accounts : ["(none listed)"]).flatMap((a) => accountSkipped(`account ${a}`, reason)),
    ];
  }
  const out: Result[] = [];
  if (!zones.length) {
    // Default: every zone the token can list (in the given accounts, when --account is given).
    const filters = accounts.length ? accounts.map((a) => `/zones?account.id=${encodeURIComponent(a)}`) : ["/zones"];
    for (const f of filters) {
      const r = await getAll(api, f, 50, 40);
      if ("error" in r) {
        ctx.warn(`cloudflare: cannot list zones (${why(r.error)}); give --zone`);
        out.push(...zoneSkipped("zone (list)", `zones not listable: ${why(r.error)}`));
        continue;
      }
      zones.push(...r.items.filter(isObj).map((z) => str(z.id)).filter((x): x is string => !!x));
    }
    zones = [...new Set(zones)];
  }
  const seenAccounts = new Set(accounts);
  for (const z of zones) {
    const r = await zoneChecks(api, z, ctx.now);
    out.push(...r.results);
    if (!accounts.length && r.accountId) seenAccounts.add(r.accountId);
  }
  const maxSuper = Number(ctx.opts["max-super-admins"] ?? DEFAULT_MAX_SUPER_ADMINS);
  if (!seenAccounts.size) out.push(...accountSkipped("account (unknown)", "no account id: give --account, or a zone the token can read"));
  for (const a of seenAccounts) out.push(...(await accountChecks(api, a, { maxSuperAdmins: Number.isFinite(maxSuper) ? maxSuper : DEFAULT_MAX_SUPER_ADMINS })));
  return out;
}

export const cloudflare: Source = {
  name: "cloudflare",
  options: {
    account: { type: "string", multiple: true, help: "Cloudflare account id; default: the accounts of the zones read" },
    zone: { type: "string", multiple: true, help: "Cloudflare zone id; default: every zone the token can list" },
    "max-super-admins": { type: "string", help: `members allowed to hold Super Administrator (default ${DEFAULT_MAX_SUPER_ADMINS})` },
    "tofu-state": { type: "string", help: "`tofu show -json` output, evaluated with the OPA policies" },
    policy: { type: "string", help: "Rego policy directory (default ../iac/policy/cloudflare)" },
  },
  emits: [...new Set([...[...ZONE_CHECKS, ...ACCOUNT_CHECKS].map((c) => `cloudflare.${c}`), ...OPA_CHECKS])],
  describe(opts) {
    const a = list(opts.account), z = list(opts.zone);
    const parts = [
      a.length ? `account ${a.join(",")}` : "accounts of the zones read",
      z.length ? `zones ${z.join(",")}` : "every zone the token lists",
    ];
    if (typeof opts["tofu-state"] === "string") parts.push("tofu state with OPA");
    return parts.join(" / ");
  },
  async run(ctx) {
    const token = ctx.env[TOKEN_ENV];
    const api = ctx.clients.cloudflare !== undefined ? ctx.clients.cloudflare : token ? fetchCloudflareApi(token) : null;
    const opa = ctx.clients.opa ?? spawnOpa(ctx.env);
    const state = typeof ctx.opts["tofu-state"] === "string" ? ctx.opts["tofu-state"] : undefined;
    const policy = typeof ctx.opts.policy === "string" ? ctx.opts.policy : DEFAULT_POLICY_DIR;
    return [...(await apiChecks(api, ctx)), ...(await opaChecks(opa, policy, state))];
  },
};
