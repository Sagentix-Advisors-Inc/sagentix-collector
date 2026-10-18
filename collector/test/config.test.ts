// collector.config.json: the schema file, validation, secrets refused, and the command line overriding the file.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main, EXIT } from "../src/cli.ts";
import { CONFIG_SCHEMA, configValues } from "../src/config.ts";
import { SOURCES } from "../src/sources/index.ts";
import { capture } from "./helpers.ts";

const dir = mkdtempSync(join(tmpdir(), "collector-config-"));
const write = (doc: unknown, name = "c.json") => { const p = join(dir, name); writeFileSync(p, typeof doc === "string" ? doc : JSON.stringify(doc)); return p; };
const base = { endpoint: "https://sos.example.test", keyId: "k-1", sources: { cloudflare: { zone: ["0123456789abcdef0123456789abcdef"] } } };

test("collector.config.schema.json is the schema the code validates with", () => {
  const file = JSON.parse(readFileSync(new URL("../collector.config.schema.json", import.meta.url), "utf8"));
  assert.deepEqual(file, JSON.parse(JSON.stringify(CONFIG_SCHEMA)));
});

test("a valid file becomes the same options as the command line", () => {
  const r = configValues({ ...base, out: "push.json", dryRun: true, sources: { ...base.sources, web: { "web-url": "https://www.example.ca/", "web-skip-proof": true }, macos: {} } }, SOURCES);
  assert.ok("values" in r, JSON.stringify(r));
  assert.deepEqual(r.values.source, ["cloudflare", "web", "macos"]);
  assert.deepEqual(r.values["web-url"], ["https://www.example.ca/"]);   // a repeatable option given once becomes a list
  assert.equal(r.values["key-id"], "k-1");
  assert.equal(r.values["dry-run"], true);
});

test("schema, unknown source, unknown option and wrong types are each refused with a path", () => {
  const p = (doc: unknown) => { const r = configValues(doc, SOURCES); return "problems" in r ? r.problems.join("\n") : ""; };
  assert.match(p({ sources: {} }), /must have required property 'endpoint'/);
  assert.match(p({ ...base, extra: 1 }), /must NOT have additional properties/);
  assert.match(p({ ...base, sources: { nope: {} } }), /\/sources\/nope is not a source/);
  assert.match(p({ ...base, sources: { macos: { zone: "x" } } }), /\/sources\/macos\/zone is not an option of macos/);
  assert.match(p({ ...base, sources: { web: { "web-skip-proof": "yes" } } }), /must be true or false/);
  assert.match(p({ ...base, sources: { cloudflare: { "max-super-admins": ["1", "2"] } } }), /takes one value, not a list/);
  assert.match(p({ ...base, sources: { web: { "web-url": 3 } } }), /must match a schema in anyOf/);
});

test("a secret in the file is refused: credentials stay in the environment", () => {
  const p = (doc: unknown) => { const r = configValues(doc, SOURCES); return "problems" in r ? r.problems.join("\n") : ""; };
  assert.match(p({ ...base, keyFile: "-----BEGIN PRIVATE KEY-----\nMC4CAQ..." }), /\/keyFile looks like a secret/);
  assert.match(p({ ...base, sources: { github: { "github-org": "ghp_abcdefghijklmnopqrstuvwxyz0123456789" } } }), /looks like a secret/);
  assert.match(p({ ...base, key: "x" }), /must NOT have additional properties/);
});

test("run --config dry-runs the file's sources; command-line options override it; a bad file exits 2", async () => {
  const path = write({ ...base, dryRun: true, sources: { cloudflare: { "max-super-admins": "1" } } });
  const c = capture();
  assert.equal(await main(["run", "--config", path], c.deps), EXIT.ok, c.stderr.join("\n"));
  const out = JSON.parse(c.stdout.join("\n"));
  assert.equal(out.dryRun, true);
  assert.equal(out.endpoint, "https://sos.example.test/api/collect");
  assert.equal(c.posts.length, 0);
  const o = capture();
  assert.equal(await main(["run", "--config", path, "--endpoint", "https://other.example.test"], o.deps), EXIT.ok, o.stderr.join("\n"));
  assert.equal(JSON.parse(o.stdout.join("\n")).endpoint, "https://other.example.test/api/collect");
  const bad = capture();
  assert.equal(await main(["run", "--config", write("{not json", "bad.json")], bad.deps), EXIT.usage);
  assert.match(bad.stderr.join("\n"), /is not valid JSON/);
  const missing = capture();
  assert.equal(await main(["run", "--config", join(dir, "absent.json")], missing.deps), EXIT.usage);
});

test("config-schema prints the schema", async () => {
  const c = capture();
  assert.equal(await main(["config-schema"], c.deps), EXIT.ok);
  assert.equal(JSON.parse(c.stdout.join("\n")).title, CONFIG_SCHEMA.title);
});
