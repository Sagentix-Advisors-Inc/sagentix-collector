#!/usr/bin/env node
// Times a full dry run of every source against the recorded replies in test/e2e_fixtures.ts (no network).
//   node test/bench.ts [--latency-ms 20] [--runs 3] [--json] [-- extra run options, e.g. --concurrency 1]
// `--latency-ms` makes each fake call wait that long, standing in for a provider's round trip. Prints the median wall
// time, the result count and a digest of the results, so two versions of the collector can be compared.
import { createHash } from "node:crypto";
import { parseArgs } from "node:util";
import { main, type Deps } from "../src/cli.ts";
import { SOURCES } from "../src/sources/index.ts";
import { e2eSetup, E2E_NOW } from "./e2e_fixtures.ts";

const split = process.argv.indexOf("--");
const own = split < 0 ? process.argv.slice(2) : process.argv.slice(2, split);
const extra = split < 0 ? [] : process.argv.slice(split + 1);
const { values } = parseArgs({ args: own, options: { "latency-ms": { type: "string", default: "0" }, runs: { type: "string", default: "3" }, json: { type: "boolean" } } });
const latencyMs = Number(values["latency-ms"]), runs = Math.max(1, Number(values.runs));

const times: number[] = [];
let digest = "", results = 0, code = -1, calls = 0, byClient: Record<string, number> = {};
for (let i = 0; i < runs; i++) {
  const s = e2eSetup({ latencyMs });
  const out: string[] = [];
  const deps: Deps = { fetch: (async () => { throw new Error("no network in the bench"); }) as unknown as typeof fetch,
    channel: (async () => { throw new Error("no network in the bench"); }) as unknown as typeof fetch,
    cwd: s.dir, clients: s.clients, sources: SOURCES, env: s.env, now: () => E2E_NOW, out: (x) => out.push(x), err: () => {} };
  const t0 = performance.now();
  code = await main(["run", ...s.args, "--dry-run", ...extra], deps);
  times.push(performance.now() - t0);
  const j = JSON.parse(out.join("\n"));
  const rs = (j.pushes ?? [j]).flatMap((p: { payload: { results: unknown[] } }) => p.payload.results);
  results = rs.length;
  calls = [...s.calls.values()].reduce((a, b) => a + b, 0);
  byClient = Object.fromEntries([...s.calls].sort());
  digest = createHash("sha256").update(JSON.stringify(rs).split(s.dir).join("<dir>")).digest("hex").slice(0, 16);
}
times.sort((a, b) => a - b);
const median = Math.round(times[Math.floor(times.length / 2)]);
const r = { latencyMs, runs, medianMs: median, minMs: Math.round(times[0]), maxMs: Math.round(times.at(-1)!), exitCode: code, results, digest, calls, byClient, extra: extra.join(" ") };
console.log(values.json ? JSON.stringify(r) : `dry run of every source, ${latencyMs} ms per fake call: median ${median} ms over ${runs} run(s) (min ${r.minMs}, max ${r.maxMs}); exit ${code}; ${results} results; ${calls} fake API calls; digest ${digest}${extra.length ? `; options ${r.extra}` : ""}`);
