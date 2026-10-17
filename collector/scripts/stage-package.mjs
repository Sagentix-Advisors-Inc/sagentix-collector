#!/usr/bin/env node
// Lays out the npm package of the collector in collector/build/ (Sagentix, 2026-10-15; used by
// .github/workflows/collector-release.yml). Run from collector/: `node scripts/stage-package.mjs`.
//
// The collector finds its data by the repository layout (src/catalog.ts reads ../../apps/sos-app/src/data/checks/,
// src/v1/rules.ts ../../../apps/sos-app/src/data/fedramp_rules.json, src/payload.ts ../package.json), so the
// package keeps that layout under its root instead of changing those paths:
//
//   build/package.json                       the published manifest (no "private", no dev dependencies)
//   build/collector/package.json             the same file, where src/payload.ts reads the version
//   build/collector/src/**.js                tsc output (tsconfig.build.json)
//   build/apps/sos-app/src/data/checks/      the check catalogues, without control mappings (public-catalogue.mjs)
//   build/apps/sos-app/src/data/fedramp_rules.json
// The OPA policies (iac/policy/cloudflare) stay out: Sagentix rules are not published (2026-10-17).
//
// It never publishes. The workflow runs `npm publish` on build/ after its own checks.
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(dirname(fileURLToPath(import.meta.url)));   // collector/
const repo = dirname(here);
const out = join(here, "build");
rmSync(out, { recursive: true, force: true });
execFileSync(process.execPath, [join(here, "node_modules/typescript/bin/tsc"), "-p", join(here, "tsconfig.build.json")], { stdio: "inherit" });

const copy = (from, to) => { mkdirSync(dirname(join(out, to)), { recursive: true }); cpSync(join(repo, from), join(out, to), { recursive: true }); };
execFileSync(process.execPath, [join(here, "scripts/public-catalogue.mjs"), join(repo, "apps/sos-app/src/data/checks"), join(out, "apps/sos-app/src/data/checks")], { stdio: "inherit" });
copy("apps/sos-app/src/data/fedramp_rules.json", "apps/sos-app/src/data/fedramp_rules.json");
execFileSync(process.execPath, [join(here, "scripts/public-docs.mjs"), join(here, "README.md"), join(out, "README.md")], { stdio: "inherit" });
copy("collector/THIRD_PARTY_NOTICES.md", "THIRD_PARTY_NOTICES.md");
copy("collector/LICENSE", "LICENSE");
copy("collector/NOTICE", "NOTICE");

const pkg = JSON.parse(readFileSync(join(here, "package.json"), "utf8"));
const repoUrl = process.env.PACKAGE_REPOSITORY_URL;   // e.g. https://github.com/<owner>/<repo>; npm provenance checks it
const manifest = {
  name: pkg.name, version: pkg.version, description: pkg.description, type: "module", engines: pkg.engines,
  license: pkg.license ?? "UNLICENSED",
  bin: { collector: "collector/src/cli.js" },
  files: ["collector/", "apps/", "README.md", "THIRD_PARTY_NOTICES.md", "LICENSE", "NOTICE"],
  dependencies: pkg.dependencies,
  ...(repoUrl ? { repository: { type: "git", url: `git+${repoUrl}.git`, directory: "collector" } } : {}),
  publishConfig: { access: "public", provenance: true },
};
writeFileSync(join(out, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`);
writeFileSync(join(out, "collector/package.json"), `${JSON.stringify({ name: pkg.name, version: pkg.version, type: "module" }, null, 2)}\n`);
console.log(`staged ${pkg.name}@${pkg.version} in ${out}`);
