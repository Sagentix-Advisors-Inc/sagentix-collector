// BambooHR (GET only), with an API key the customer makes under their own user, read as joiners, leavers and the org
// chart (hris_common.ts). The key is the HTTP Basic user name; the password may be any string.
//
// From the BambooHR API documentation (all read 2026-11-07):
//   Requests go to https://{companyDomain}.bamboohr.com/api/; the only version is v1.
//     https://documentation.bamboohr.com/docs/api-details
//   A key carries the access of the user who made it: "The permissions of the user associated with the API request will
//   determine which fields" it can see. No read-only key exists, so the customer makes it under a user whose access level
//   reads the fields below and edits nothing. https://documentation.bamboohr.com/docs/getting-started
//   GET /api/v1/employees?filter[status]=active|inactive&fields=<comma list>&page[limit]=<at most 2500>
//     -> { data: [ { employeeId, status, jobTitleName, _restrictedFields, ...requested fields } ], meta: { total, page },
//          _links: { self, next? } }. Fields the caller cannot read come back null and are named in _restrictedFields;
//     unknown field names are ignored. Both statuses are asked for, so leavers are read as well as current staff.
//     https://documentation.bamboohr.com/reference/list-employees
//   Field names: workEmail, hireDate, terminationDate, supervisorEId (the supervisor's employee id), jobTitle.
//     https://documentation.bamboohr.com/docs/list-of-field-names
//   A 429 carries Retry-After; no rate is published. https://documentation.bamboohr.com/docs/api-details
// The code of conduct or acceptable-use acknowledgement and the background check have no standard field: the customer
// names the date field (often a custom field) that records each (--bamboohr-ack-field, --bamboohr-background-field).
// BambooHR's API has no e-signature endpoint; a signed file is a file in a category (GET /api/v1/employees/{id}/files/view),
// which shows a file exists, not what it says, so it is not read.
//
// Personal data: names, photos and every field not listed are never asked for. A person is named in a result by the
// employee id; the work email is used only for the identity-provider lookup and the LMS join.

import type { Result, Source, SourceContext } from "../types.ts";
import { HRIS_CHECKS, hrisChecks, hrisOptionSpecs, hrisOptions, hrisSkipped, isoDay, type Person } from "./hris_common.ts";
import { IDP_SECRETS } from "./directory.ts";
import { fetchRest, isObj, ok, realSleep, redact, str, why, withRetry, type HttpResponse, type Obj, type RestApi, type Sleep } from "./readonly_http.ts";

export const BAMBOOHR_ENV = { key: "BAMBOOHR_API_KEY" } as const;
export const SUBDOMAIN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
/** A field name as BambooHR spells it: letters, digits, underscore (custom fields are named this way too). */
export const FIELD = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const BASE_FIELDS = ["workEmail", "hireDate", "terminationDate", "supervisorEId", "jobTitle"];
export const PAGE = 1000;

export const employeesPath = (status: "active" | "inactive", fields: string[]) =>
  `/v1/employees?filter%5Bstatus%5D=${status}&fields=${encodeURIComponent(fields.join(","))}&page%5Blimit%5D=${PAGE}`;

/** A BambooHR client for a company subdomain from BAMBOOHR_API_KEY, or what is missing. */
export function bamboohrFromEnv(env: NodeJS.ProcessEnv, company: string | undefined, fetchFn: typeof fetch = fetch): RestApi | string {
  const key = env[BAMBOOHR_ENV.key];
  if (!company || !SUBDOMAIN.test(company)) return "--bamboohr-company must be the BambooHR subdomain (acme for acme.bamboohr.com)";
  if (!key) return `${BAMBOOHR_ENV.key} is not set`;
  const basic = `Basic ${Buffer.from(`${key}:x`).toString("base64")}`;
  return fetchRest({ base: `https://${company.toLowerCase()}.bamboohr.com/api`, fetchFn, headers: async () => ({ authorization: basic }) });
}

/** Every employee of one status, following _links.next (at most 100 pages). */
async function listStatus(api: RestApi, status: "active" | "inactive", fields: string[]): Promise<{ items: Obj[]; pages: number; truncated: boolean; total?: number } | { error: HttpResponse }> {
  const items: Obj[] = [];
  let url: string | undefined = employeesPath(status, fields), pages = 0, total: number | undefined;
  while (url && pages < 100) {
    const r = await api.get(url);
    if (!ok(r) || !isObj(r.body) || !Array.isArray(r.body.data)) return { error: r };
    pages++;
    items.push(...r.body.data.filter(isObj));
    if (isObj(r.body.meta) && Number.isFinite(Number(r.body.meta.total))) total = Number(r.body.meta.total);
    const links = isObj(r.body._links) ? r.body._links : {};
    url = isObj(links.next) ? str(links.next.href) : undefined;
  }
  return { items, pages, truncated: !!url, total };
}

const lower = (v: unknown) => (typeof v === "string" ? v.trim().toLowerCase() : "");

export function personOf(e: Obj, ackField?: string, backgroundField?: string): Person {
  const status = lower(e.status) === "active" ? "active" : lower(e.status) === "inactive" ? "terminated" : lower(e.status) || "unknown";
  const title = str(e.jobTitle) ?? str(e.jobTitleName);
  return {
    id: String(e.employeeId ?? e.id ?? "?").slice(0, 40),
    email: str(e.workEmail)?.trim() || undefined,
    status,
    hired: isoDay(e.hireDate),
    left: status === "terminated" ? isoDay(e.terminationDate) : undefined,
    managerId: str(e.supervisorEId)?.trim() || (typeof e.supervisorEId === "number" ? String(e.supervisorEId) : undefined),
    title: title?.trim() || undefined,
    dates: { ack: ackField ? isoDay(e[ackField]) : undefined, background: backgroundField ? isoDay(e[backgroundField]) : undefined },
  };
}

export const bamboohr: Source = {
  name: "bamboohr",
  options: {
    "bamboohr-company": { type: "string", help: "the BambooHR company subdomain (acme for acme.bamboohr.com)" },
    ...hrisOptionSpecs("bamboohr"),
  },
  emits: HRIS_CHECKS.map((c) => `bamboohr.${c}`),
  describe: (opts) => `BambooHR company ${typeof opts["bamboohr-company"] === "string" ? opts["bamboohr-company"] : "(none)"} (API v1, GET only)`,
  validate(opts) {
    for (const k of ["bamboohr-ack-field", "bamboohr-background-field"]) {
      const v = opts[k];
      if (typeof v === "string" && v.trim() && !FIELD.test(v.trim())) return `--${k} must be a BambooHR field name (letters, digits and _)`;
    }
    return undefined;
  },
  async run(ctx: SourceContext): Promise<Result[]> {
    const company = typeof ctx.opts["bamboohr-company"] === "string" ? ctx.opts["bamboohr-company"].trim() : undefined;
    const resource = `bamboohr ${company ?? "(unknown)"}`;
    const o = hrisOptions("bamboohr", ctx);
    if (typeof o === "string") return hrisSkipped("bamboohr", resource, o);
    const given = ctx.clients.bamboohr as RestApi | null | undefined;
    const built = given !== undefined ? given : bamboohrFromEnv(ctx.env, company);
    if (!built || typeof built === "string") return hrisSkipped("bamboohr", resource, typeof built === "string" ? built : "no BambooHR client");
    const api = withRetry(built, (ctx.clients.sleep as Sleep | undefined) ?? realSleep);
    const fields = [...BASE_FIELDS, ...[o.ackField, o.backgroundField].filter((f): f is string => !!f && FIELD.test(f))];
    const people: Person[] = [];
    let pages = 0, truncated = false;
    const restricted = new Set<string>();
    for (const status of ["active", "inactive"] as const) {
      const l = await listStatus(api, status, fields);
      if ("error" in l) return redact(hrisSkipped("bamboohr", resource, `employees (${status}) not readable: ${why(l.error)}`, l.error), [ctx.env[BAMBOOHR_ENV.key]]);
      pages += l.pages; truncated ||= l.truncated;
      for (const e of l.items) {
        for (const f of Array.isArray(e._restrictedFields) ? e._restrictedFields : []) if (typeof f === "string") restricted.add(f);
        people.push(personOf(e, o.ackField, o.backgroundField));
      }
    }
    // A field the key's user cannot read comes back null: say so, rather than fail people for an empty field.
    const hidden = fields.filter((f) => restricted.has(f));
    const read = { method: "config-read" as const, itemsRead: people.length, pagesRead: pages, complete: !truncated && !hidden.length };
    let rs = await hrisChecks("bamboohr", resource, people, read, o, ctx);
    for (const [check, field] of [["bamboohr.hire_acknowledgement", o.ackField], ["bamboohr.hire_background_check", o.backgroundField]] as const) {
      if (!field || !hidden.includes(field)) continue;
      rs = rs.filter((r) => r.check !== check);
      rs.push({ check, resource, result: "skipped", detail: `the API key's user cannot read the field ${field} (BambooHR lists it in _restrictedFields); give that user read access to it` });
    }
    return redact(rs, [ctx.env[BAMBOOHR_ENV.key], ...IDP_SECRETS(ctx.env)]);
  },
};
