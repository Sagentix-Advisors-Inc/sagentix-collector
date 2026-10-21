// scripts/public-catalogue.mjs: what reaches the public mirror, the npm package and the runner image. It drops
// Sagentix's control mappings and keeps every field the collector itself reads. On 2026-10-21 it dropped retiredIn,
// so a mirror's collector would have scored ScubaGear 2.0.0 reports on 50 policies CISA retired; this holds both.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const catalogues = join(here, "../../apps/sos-app/src/data/checks");

test("public catalogue: no control mappings, and the retirement facts scuba.ts reads are kept", () => {
  const out = mkdtempSync(join(tmpdir(), "public-catalogue-"));
  try {
    execFileSync(process.execPath, [join(here, "../scripts/public-catalogue.mjs"), catalogues, out], { stdio: "pipe" });
    for (const f of readdirSync(out)) {
      const text = readFileSync(join(out, f), "utf8");
      assert.doesNotMatch(text, /"(hub|ksis|coverage|hubBasis|ksiBasis)":/, f);
    }
    const scuba = JSON.parse(readFileSync(join(out, "scubagear.json"), "utf8"));
    const exo = scuba.checks.find((c: { id: string }) => c.id === "scubagear.ms.exo.11.2v1");
    assert.equal(exo.retiredIn, "2.0.0");
    assert.equal(exo.replacedBy, "MS.SECURITYSUITE.2.4v1");
    assert.ok(exo.removed);
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});
