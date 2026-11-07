// Rippling (GET only), with an API token a Rippling admin makes under Developer > API credentials and grants only the
// workers.read scope, read as joiners, leavers and the org chart (hris_common.ts).
//
// From Rippling's REST API documentation (all read 2026-11-07):
//   Tokens: made at https://app.rippling.com/api-tokens/tokens by a user who may manage API tokens; scopes are chosen at
//   creation and limited by the creator's own permissions; a token is revoked when its owner leaves or after 30 days
//   unused, so a daily or weekly run keeps it alive. Requests go to https://rest.ripplingapis.com with
//   Authorization: Bearer <token>. https://developer.rippling.com/documentation/rest-api/essentials/api-tokens
//   GET /workers/?limit=100                                                                     workers.read
//     -> { __meta, results: [ { id, work_email, status (INIT, HIRED, ACCEPTED, ACTIVE, TERMINATED), start_date,
//          end_date, manager_id, title, custom_fields, termination_details } ], next_link }
//     https://developer.rippling.com/documentation/rest-api/reference/list-workers.md
//   Pages: send the first request without a cursor, then follow next_link unchanged until it is null; limit is at most
//   100. https://developer.rippling.com/documentation/rest-api/essentials/pagination
//   Rate: 600 requests per 10 seconds per token and path; a 429 is retried after Retry-After.
//   https://developer.rippling.com/documentation/rest-api/essentials/api-limits
// The acknowledgement and the background check have no standard worker field: the customer names the custom field that
// records each date (--rippling-ack-field, --rippling-background-field). custom_fields' item shape is open in the
// reference, so both { "<name>": value } and { name|label|api_name, value } items are read; a field never found is
// reported as such rather than failing every hire.
//
// Personal data: names, compensation and every expandable object are never asked for (no expand). A person is named in
// a result by the Rippling worker id; the work email is used only for the identity-provider lookup and the LMS join.

import type { Result, Source, SourceContext } from "../types.ts";
import { HRIS_CHECKS, hrisChecks, hrisOptionSpecs, hrisOptions, hrisSkipped, isoDay, type Person } from "./hris_common.ts";
import { IDP_SECRETS } from "./directory.ts";
import { arr, fetchRest, isObj, ok, realSleep, redact, str, why, withRetry, type Obj, type RestApi, type Sleep } from "./readonly_http.ts";

export const RIPPLING_ENV = { token: "RIPPLING_API_TOKEN" } as const;
export const RIPPLING_BASE = "https://rest.ripplingapis.com";
export const WORKERS = "/workers/?limit=100";
const FIELD = /^[A-Za-z0-9][A-Za-z0-9_ .-]{0,63}$/;

export function ripplingFromEnv(env: NodeJS.ProcessEnv, fetchFn: typeof fetch = fetch): RestApi | string {
  const token = env[RIPPLING_ENV.token];
  if (!token) return `${RIPPLING_ENV.token} is not set`;
  return fetchRest({ base: RIPPLING_BASE, fetchFn, headers: async () => ({ authorization: `Bearer ${token}` }) });
}

/** A custom field's value, from either item shape the reference allows. */
export function customField(w: Obj, name: string): unknown {
  const want = name.toLowerCase();
  for (const it of arr(w.custom_fields).filter(isObj)) {
    for (const [k, v] of Object.entries(it)) if (k.toLowerCase() === want) return v;
    const key = [it.name, it.label, it.api_name, it.field].find((x) => typeof x === "string" && x.toLowerCase() === want);
    if (key !== undefined) return it.value;
  }
  return undefined;
}

export function personOf(w: Obj, ackField?: string, backgroundField?: string): Person {
  const s = String(w.status ?? "").toUpperCase();
  const status = s === "ACTIVE" ? "active" : s === "TERMINATED" ? "terminated" : s.toLowerCase() || "unknown";
  return {
    id: String(w.id ?? "?").slice(0, 40),
    email: str(w.work_email)?.trim() || undefined,
    status,
    hired: isoDay(w.start_date),
    left: status === "terminated" ? isoDay(w.end_date) : undefined,
    managerId: str(w.manager_id)?.trim() || undefined,
    title: str(w.title)?.trim() || undefined,
    dates: { ack: ackField ? isoDay(customField(w, ackField)) : undefined, background: backgroundField ? isoDay(customField(w, backgroundField)) : undefined },
  };
}

export const rippling: Source = {
  name: "rippling",
  options: {
    "rippling-company": { type: "string", help: "a name for the Rippling company in results, e.g. its domain (the token decides what is read)" },
    ...hrisOptionSpecs("rippling"),
  },
  emits: HRIS_CHECKS.map((c) => `rippling.${c}`),
  describe: (opts) => `Rippling company ${typeof opts["rippling-company"] === "string" ? opts["rippling-company"] : "(token's company)"} (REST API, workers.read)`,
  validate(opts) {
    for (const k of ["rippling-ack-field", "rippling-background-field"]) {
      const v = opts[k];
      if (typeof v === "string" && v.trim() && !FIELD.test(v.trim())) return `--${k} must be a custom field name (letters, digits, space, _ . -)`;
    }
    return undefined;
  },
  async run(ctx: SourceContext): Promise<Result[]> {
    const company = typeof ctx.opts["rippling-company"] === "string" && ctx.opts["rippling-company"].trim() ? ctx.opts["rippling-company"].trim().slice(0, 100) : "company";
    const resource = `rippling ${company}`;
    const o = hrisOptions("rippling", ctx);
    if (typeof o === "string") return hrisSkipped("rippling", resource, o);
    const given = ctx.clients.rippling as RestApi | null | undefined;
    const built = given !== undefined ? given : ripplingFromEnv(ctx.env);
    if (!built || typeof built === "string") return hrisSkipped("rippling", resource, typeof built === "string" ? built : "no Rippling client");
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);

    const workers: Obj[] = [];
    let url: string | undefined = WORKERS, pages = 0;
    while (url && pages < 500) {
      const r = await api.get(url);
      if (!ok(r) || !isObj(r.body) || !Array.isArray(r.body.results)) {
        return redact(hrisSkipped("rippling", resource, `workers not readable: ${why(r)}`, r), [ctx.env[RIPPLING_ENV.token]]);
      }
      pages++;
      workers.push(...r.body.results.filter(isObj));
      url = str(r.body.next_link) || undefined;
    }
    const people = workers.map((w) => personOf(w, o.ackField, o.backgroundField));
    const read = { method: "config-read" as const, itemsRead: people.length, pagesRead: pages, complete: !url };
    let rs = await hrisChecks("rippling", resource, people, read, o, ctx);
    // A custom field no worker carries is more likely misnamed or not shared with the token than empty for everyone.
    for (const [check, field] of [["rippling.hire_acknowledgement", o.ackField], ["rippling.hire_background_check", o.backgroundField]] as const) {
      if (!field || workers.some((w) => customField(w, field) !== undefined)) continue;
      rs = rs.filter((r) => r.check !== check);
      rs.push({ check, resource, result: "skipped", detail: `no worker carries the custom field "${field}"; check its name and that the token can read custom fields` });
    }
    return redact(rs, [ctx.env[RIPPLING_ENV.token], ...IDP_SECRETS(ctx.env)]);
  },
};
