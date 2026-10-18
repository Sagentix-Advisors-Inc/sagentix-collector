// What every source returns, and the shape a source module exports.
//
// A source reads one kind of system read-only and reports one Result per (check, resource).
// "skipped" means the collector could not see the thing (no permission, not on the plan, no tool);
// it is never counted as a pass.

import type { CloudflareApi } from "./sources/cloudflare/api.ts";
import type { OpaRunner } from "./sources/cloudflare/opa.ts";

export type Outcome = "pass" | "fail" | "skipped";

export interface Result {
  /** A check id from the catalogue (apps/sos-app/src/data/checks/<source>.json), e.g. "cloudflare.dnssec". */
  check: string;
  /** What was looked at, e.g. "zone example.com" or "tofu cloudflare_zone_dnssec.this". */
  resource: string;
  result: Outcome;
  /** What was observed, in words (sent truncated to 1000 characters). */
  detail: string;
}

/** Injectable clients. A source uses the one given here, or builds its own from the environment. */
export interface Clients {
  /** null means "no read-only token": every API check is skipped. */
  cloudflare?: CloudflareApi | null;
  opa?: OpaRunner;
  [name: string]: unknown;
}

export type OptionValue = string | boolean | string[] | undefined;

export interface OptionSpec {
  type: "string" | "boolean";
  multiple?: boolean;
  /** One line for the usage text. */
  help: string;
}

export interface SourceContext {
  /** The parsed command-line options (every source's options; a source reads its own). */
  opts: Record<string, OptionValue>;
  env: NodeJS.ProcessEnv;
  clients: Clients;
  now: Date;
  /** For warnings a person running the collector should see (stderr). */
  warn: (s: string) => void;
}

export interface Source {
  /** The catalogue's `source` and the --source value. */
  name: string;
  /** Command-line options this source reads. Names must not collide with another source's. */
  options: Record<string, OptionSpec>;
  /** Every check id this source can emit; a test holds this against the catalogue. */
  emits: readonly string[];
  /** The `scope` string sent with the push, e.g. "account 0123 / zones a,b". */
  describe(opts: Record<string, OptionValue>): string;
  /** Optional: why these options cannot run (the CLI exits 2 with this message), or undefined. */
  validate?(opts: Record<string, OptionValue>): string | undefined;
  run(ctx: SourceContext): Promise<Result[]>;
}
