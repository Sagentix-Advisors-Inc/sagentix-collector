// The collector's config file (collector.config.json): the sources to run and their options in one file, so a
// setup is one file plus one command, `collector run --config collector.config.json`. sos-app's "Connect your
// environment" screen writes it.
//
//   { "$schema": "...", "endpoint": "https://<sos-app host>", "keyId": "<key id>", "keyFile": "sagentix-collector.pem",
//     "out": "sagentix-push.json", "dryRun": false, "catalog": "<checks dir>",
//     "sources": { "web": { "web-url": ["https://www.example.com/"], "web-proof": ["www.example.com=<token>"] },
//                  "macos": {} } }
//
// A source's options are its command-line options without the leading "--". The file holds no secret: the private
// key comes from keyFile (a path) or SAGENTIX_COLLECTOR_KEY, and each source reads its credentials from the
// environment as before. Paths are relative to the directory the command runs in. Options given on the command
// line override the file's.

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import type { OptionValue, Source } from "./types.ts";

export const CONFIG_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://github.com/Sagentix-Advisors-Inc/sagentix-collector/collector.config.schema.json",
  title: "Sagentix evidence collector configuration",
  type: "object",
  additionalProperties: false,
  required: ["endpoint", "sources"],
  properties: {
    $schema: { type: "string" },
    endpoint: { type: "string", pattern: "^https?://", description: "The sos-app origin; https (http only for localhost)." },
    keyId: { type: "string", minLength: 1, maxLength: 100, description: "The key id sos-app gave when the public key was registered." },
    keyFile: { type: "string", minLength: 1, description: "Path to the Ed25519 private key (PEM). Omit to read SAGENTIX_COLLECTOR_KEY." },
    out: { type: "string", minLength: 1, description: "Also write the signed payload to this file." },
    dryRun: { type: "boolean", description: "Print the payload and send nothing." },
    catalog: { type: "string", minLength: 1, description: "The check catalogue directory." },
    sources: {
      type: "object",
      minProperties: 1,
      description: "Source name to its options (command-line option names without --).",
      additionalProperties: {
        type: "object",
        additionalProperties: {
          anyOf: [{ type: "string" }, { type: "boolean" }, { type: "array", items: { type: "string" } }],
        },
      },
    },
  },
} as const;

interface AjvLike {
  compile(s: object): ((d: unknown) => boolean) & { errors?: { instancePath: string; message?: string }[] | null };
}

let validator: ReturnType<AjvLike["compile"]> | undefined;
function validateSchema(doc: unknown): string[] {
  if (!validator) {
    const require = createRequire(import.meta.url);
    const { Ajv2020 } = require("ajv/dist/2020.js") as { Ajv2020: new (o: object) => AjvLike };
    validator = new Ajv2020({ strict: true, allErrors: true }).compile(CONFIG_SCHEMA);
  }
  return validator(doc) ? [] : (validator.errors ?? []).slice(0, 20).map((e) => `${e.instancePath || "/"} ${e.message ?? "invalid"}`);
}

/** Text that looks like a secret: a PEM block, or a token with a well-known prefix. */
const SECRET = /-----BEGIN|^(ghp_|gho_|ghs_|github_pat_|xox[abp]-|AKIA|ASIA|sk_live_|SSWS )/;

/**
 * The option values a config file stands for, as the CLI's parsed options; or the problems found. Checks the
 * schema, then that each source exists and each option belongs to it with the right type.
 */
export function configValues(doc: unknown, sources: readonly Source[]): { values: Record<string, OptionValue> } | { problems: string[] } {
  const problems = validateSchema(doc);
  if (problems.length) return { problems };
  const c = doc as { endpoint: string; keyId?: string; keyFile?: string; out?: string; dryRun?: boolean; catalog?: string; sources: Record<string, Record<string, OptionValue>> };
  const values: Record<string, OptionValue> = { endpoint: c.endpoint };
  if (c.keyId !== undefined) values["key-id"] = c.keyId;
  if (c.keyFile !== undefined) values.key = c.keyFile;
  if (c.out !== undefined) values.out = c.out;
  if (c.dryRun !== undefined) values["dry-run"] = c.dryRun;
  if (c.catalog !== undefined) values.catalog = c.catalog;
  values.source = Object.keys(c.sources);
  for (const [name, opts] of Object.entries(c.sources)) {
    const s = sources.find((x) => x.name === name);
    if (!s) { problems.push(`/sources/${name} is not a source; known: ${sources.map((x) => x.name).join(", ")}`); continue; }
    for (const [k, v] of Object.entries(opts)) {
      const spec = s.options[k];
      if (!spec) { problems.push(`/sources/${name}/${k} is not an option of ${name}${Object.keys(s.options).length ? `; it takes ${Object.keys(s.options).join(", ")}` : "; it takes none"}`); continue; }
      const strs = Array.isArray(v) ? v : typeof v === "string" ? [v] : [];
      if (strs.some((x) => SECRET.test(x))) { problems.push(`/sources/${name}/${k} looks like a secret; credentials go in the environment, never in this file`); continue; }
      if (spec.type === "boolean" && typeof v !== "boolean") problems.push(`/sources/${name}/${k} must be true or false`);
      else if (spec.type === "string" && typeof v === "boolean") problems.push(`/sources/${name}/${k} must be a string${spec.multiple ? " or a list of strings" : ""}`);
      else if (Array.isArray(v) && !spec.multiple) problems.push(`/sources/${name}/${k} takes one value, not a list`);
      else values[k] = spec.multiple && typeof v === "string" ? [v] : v;
    }
  }
  for (const k of ["endpoint", "keyId", "keyFile", "out", "catalog"] as const) if (typeof c[k] === "string" && SECRET.test(c[k]!)) problems.push(`/${k} looks like a secret; give keyFile as a path, or set SAGENTIX_COLLECTOR_KEY`);
  return problems.length ? { problems } : { values };
}

export function loadConfig(path: string, sources: readonly Source[]): { values: Record<string, OptionValue> } | { problems: string[] } {
  let text: string;
  try { text = readFileSync(path, "utf8"); } catch (e) { return { problems: [`cannot read ${path} (${(e as NodeJS.ErrnoException).code ?? String(e)})`] }; }
  let doc: unknown;
  try { doc = JSON.parse(text.replace(/^﻿/, "")); } catch (e) { return { problems: [`${path} is not valid JSON: ${(e as Error).message}`] }; }
  return configValues(doc, sources);
}
