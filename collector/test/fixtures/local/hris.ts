// Fixtures for the hris source, shared by test/hris.test.ts and the end-to-end run (test/e2e.test.ts).
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bamboohr, bamboohrFromEnv, employeesPath } from "../../../src/sources/bamboohr.ts";
import { customField, rippling, ripplingFromEnv, WORKERS } from "../../../src/sources/rippling.ts";
import { entraDirectory, googleDirectory, jumpcloudDirectory, oktaDirectory } from "../../../src/sources/directory.ts";
import { HRIS_CHECKS } from "../../../src/sources/hris_common.ts";
import type { HttpResponse, RestApi } from "../../../src/sources/readonly_http.ts";
import type { OptionValue, Result } from "../../../src/types.ts";
import { NOW } from "../../helpers.ts";
import { fakeRest, of, res } from "../../rest_fakes.ts";

export const ok = (b: unknown) => res(200, b);
export const BHR = "https://acme.bamboohr.com/api";
export const q = (url: string) => new URL(`https://x${url}`).searchParams;

/** BambooHR rows: a CEO, a June hire, two leavers in the period (one disabled in time, one still active) and an old one. */
export const active = () => [
  { employeeId: "1", status: "Active", firstName: "Dana", lastName: "Root", jobTitleName: "CEO", jobTitle: "CEO", workEmail: "dana@acme.example", hireDate: "2019-01-07", supervisorEId: null, _restrictedFields: [] },
  { employeeId: "2", status: "Active", firstName: "Eli", lastName: "New", jobTitle: "Engineer", workEmail: "eli@acme.example", hireDate: "2026-06-01", supervisorEId: "1",
    customCodeOfConduct: "2026-06-01", customBackground: "2026-05-20", _restrictedFields: [] },
];
export const inactive = () => [
  { employeeId: "3", status: "Inactive", firstName: "Fay", jobTitle: "Analyst", workEmail: "fay@acme.example", hireDate: "2021-03-01", terminationDate: "2026-09-30", supervisorEId: "1", _restrictedFields: [] },
  { employeeId: "4", status: "Inactive", firstName: "Gus", jobTitle: "Sales", workEmail: "gus@acme.example", hireDate: "2022-03-01", terminationDate: "2026-10-10", supervisorEId: "1", _restrictedFields: [] },
  { employeeId: "5", status: "Inactive", firstName: "Hal", jobTitle: "Ops", workEmail: "hal@acme.example", hireDate: "2018-03-01", terminationDate: "2024-02-01", supervisorEId: "1", _restrictedFields: [] },
];
export const page = (data: unknown[]) => ok({ data, meta: { total: data.length, page: { limit: 1000, nextCursor: null, prevCursor: null } }, _links: { self: { href: "x" } } });
export const bambooRoutes = (over: { active?: unknown[]; inactive?: unknown[] } = {}) => ({
  "/v1/employees": (url: string) => page(q(url).get("filter[status]") === "active" ? over.active ?? active() : over.inactive ?? inactive()),
});

/** Okta: Fay deprovisioned 5 h after her last day ended, Gus still active. */
export const OKTA = "https://acme.okta.com";
export const oktaUsers: Record<string, unknown> = {
  "fay@acme.example": { id: "00u-fay", status: "DEPROVISIONED", statusChanged: "2026-10-01T05:00:00.000Z", profile: { email: "fay@acme.example", firstName: "Fay" } },
  "gus@acme.example": { id: "00u-gus", status: "ACTIVE", statusChanged: "2022-03-01T09:00:00.000Z", profile: { email: "gus@acme.example" } },
};
export const okta = (calls: string[] = []) => fakeRest(OKTA, {
  "/api/v1/users": (url) => {
    const m = /profile\.email eq "([^"]+)"/.exec(q(url).get("search") ?? "");
    const u = m ? oktaUsers[m[1]] : undefined;
    return ok(u ? [u] : []);
  },
}, calls);

export let csvDir: string | undefined;
export function trainingCsv(rows: string): string {
  csvDir ??= mkdtempSync(join(tmpdir(), "hris-"));
  const p = join(csvDir, `t${Math.random().toString(36).slice(2)}.csv`);
  writeFileSync(p, `person_id,course,completed_on\n${rows}`);
  return p;
}

export const BOPTS: Record<string, OptionValue> = { "bamboohr-company": "acme", "bamboohr-idp": "okta", "bamboohr-ack-field": "customCodeOfConduct",
  "bamboohr-background-field": "customBackground" };

export const RIP = "https://rest.ripplingapis.com";
export const workers = () => [
  { id: "w1", status: "ACTIVE", work_email: "dana@acme.example", title: "CEO", start_date: "2019-01-07", manager_id: null, custom_fields: [] },
  { id: "w2", status: "ACTIVE", work_email: "eli@acme.example", title: "Engineer", start_date: "2026-06-01", manager_id: "w1",
    custom_fields: [{ "Code of conduct signed": "2026-06-02" }, { name: "Background check", value: "2026-05-25" }] },
  { id: "w3", status: "TERMINATED", work_email: "fay@acme.example", title: "Analyst", start_date: "2021-03-01", end_date: "2026-09-30", manager_id: "w1",
    termination_details: { type: "VOLUNTARY", reason: "moved" }, custom_fields: [] },
];
export const ripRoutes = (ws = workers()) => ({
  "/workers/": (url: string) => (q(url).get("cursor") ? ok({ __meta: {}, results: ws.slice(2), next_link: null })
    : ok({ __meta: {}, results: ws.slice(0, 2), next_link: `${RIP}/workers/?limit=100&cursor=abc` })),
});
export const ROPTS: Record<string, OptionValue> = { "rippling-company": "acme.example", "rippling-idp": "okta", "rippling-ack-field": "Code of conduct signed",
  "rippling-background-field": "Background check" };
