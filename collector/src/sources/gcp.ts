// Google Cloud: per-project checks over Google's REST APIs with a read-only service account's access
// token (GOOGLE_OAUTH_ACCESS_TOKEN). Every call is a GET, except POST :getIamPolicy and :getAncestry, which read.

import type { Source } from "../types.ts";
import { Results, allSkipped, list, scrub } from "./shared-cloud.ts";
import { GCP_TOKEN_ENV, Gcp, fetchGcpTransport, type GcpTransport } from "./gcp/api.ts";
import { DEFAULT_KEY_MAX_AGE_DAYS, DEFAULT_ORG_CONSTRAINTS, GCP_CHECKS, projectChecks, type GcpCheck } from "./gcp/project.ts";

export const gcp: Source = {
  name: "gcp",
  options: {
    "gcp-project": { type: "string", multiple: true, help: "GCP project id (repeatable or comma-separated); required" },
    "gcp-org-constraints": { type: "string", help: `boolean org policy constraints that must be enforced (default ${DEFAULT_ORG_CONSTRAINTS.join(",")})` },
    "gcp-key-max-age-days": { type: "string", help: `oldest a user-managed service account key may be (default ${DEFAULT_KEY_MAX_AGE_DAYS})` },
  },
  emits: GCP_CHECKS.map((c) => `gcp.${c}`),
  describe(opts) {
    const p = list(opts["gcp-project"]);
    return p.length ? `projects ${p.join(",")}` : "no project given";
  },
  async run(ctx) {
    const projects = list(ctx.opts["gcp-project"]);
    const token = ctx.env[GCP_TOKEN_ENV];
    const t = ctx.clients.gcp !== undefined ? (ctx.clients.gcp as GcpTransport | null) : token ? fetchGcpTransport(token) : null;
    if (!projects.length) return allSkipped("gcp", GCP_CHECKS, "project (none listed)", "no --gcp-project given");
    if (!t) return projects.flatMap((p) => allSkipped("gcp", GCP_CHECKS, `project ${p}`, `${GCP_TOKEN_ENV} is not set`));
    const constraints = list(ctx.opts["gcp-org-constraints"]);
    const maxAge = Number(ctx.opts["gcp-key-max-age-days"] ?? DEFAULT_KEY_MAX_AGE_DAYS);
    const api = new Gcp(t);
    const out = new Results<GcpCheck>("gcp");
    for (const p of projects) {
      await projectChecks(api, p, {
        orgConstraints: constraints.length ? constraints : DEFAULT_ORG_CONSTRAINTS,
        keyMaxAgeDays: Number.isFinite(maxAge) && maxAge > 0 ? maxAge : DEFAULT_KEY_MAX_AGE_DAYS,
        now: ctx.now,
      }, out);
    }
    return scrub(out.results, [token]);
  },
};
