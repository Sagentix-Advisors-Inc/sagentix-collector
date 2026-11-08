// `collector policies`: the organization's policy folder, pushed for sos-app to match (2026-11-05).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, publicKeyFromPrivate } from "../src/keys.ts";
import { verifiesV2 } from "./helpers.ts";
import { policyFiles, pushPolicies } from "../src/policies.ts";
import { policiesCommand } from "../src/cli.ts";
import { SOURCES } from "../src/sources/index.ts";

function folder() {
  const d = mkdtempSync(join(tmpdir(), "policies-"));
  writeFileSync(join(d, "POL-06_access-control-policy.pdf"), "%PDF-1.4 Access Control Policy");
  writeFileSync(join(d, "POL-04_code-of-conduct.md"), "# Code of Professional Conduct");
  writeFileSync(join(d, "notes.xlsx"), "not a policy type");
  writeFileSync(join(d, ".DS_Store"), "x");
  writeFileSync(join(d, "~$draft.docx"), "Word lock file");
  mkdirSync(join(d, "superseded"));
  writeFileSync(join(d, "superseded", "POL-06_old.pdf"), "%PDF-1.4 old");
  return d;
}

test("policies: only PDF, Word and text files at the top of the folder; no hidden, lock or archived files", () => {
  assert.deepEqual(policyFiles([folder()]).map((f) => f.name), ["POL-04_code-of-conduct.md", "POL-06_access-control-policy.pdf"]);
});

test("policies: one file per policy when it comes in several formats, the PDF first, then Word, then text", () => {
  const d = folder();
  writeFileSync(join(d, "POL-06_access-control-policy.md"), "# Access Control Policy");
  writeFileSync(join(d, "POL-06_access-control-policy.docx"), "PK word");
  writeFileSync(join(d, "POL-04_code-of-conduct.docx"), "PK word");
  assert.deepEqual(policyFiles([d]).map((f) => f.name), ["POL-04_code-of-conduct.docx", "POL-06_access-control-policy.pdf"]);
});

test("policies: each file goes to the document door signed with the documents key, target {policy: auto}; outcomes read back", async () => {
  const d = folder(), { privatePem } = generateKeyPair();
  const pub = createPublicKey(privatePem);
  const seen: { manifest: Record<string, unknown>; type: string }[] = [];
  const fetchFn = (async (url: string, init: RequestInit) => {
    assert.equal(url, "https://comply.example/api/collect/document");
    const h = init.headers as Record<string, string>;
    const mBytes = Buffer.from(h["x-sagentix-document"], "base64url");
    assert.ok(verify(null, mBytes, pub, Buffer.from(h["x-sagentix-content-signature"], "base64")), "the content signature binds the manifest");
    assert.ok(verifiesV2(publicKeyFromPrivate(privatePem), h, "POST", "/api/collect/document", mBytes), "signature v2 hashes the manifest");
    const manifest = JSON.parse(mBytes.toString()) as Record<string, unknown>;
    seen.push({ manifest, type: h["content-type"] });
    if (String(manifest.filename).includes("conduct")) return new Response(JSON.stringify({ error: "Not matched", code: "policy_unmatched" }), { status: 422 });
    return new Response(JSON.stringify({ id: "p1", family: "ac", version: 2, origin: "uploaded" }), { status: 201 });
  }) as unknown as typeof fetch;
  const out = await pushPolicies({ endpoint: "https://comply.example", organization: "org-1", keyId: "k1", pem: privatePem, dirs: [d], fetch: fetchFn, now: () => new Date("2026-11-05T15:00:00Z") });
  assert.deepEqual(out.map((r) => [r.file, r.outcome]), [["POL-04_code-of-conduct.md", "unmatched"], ["POL-06_access-control-policy.pdf", "filed"]]);
  assert.match(out[1].detail, /AC version 2/);
  for (const s of seen) assert.deepEqual([s.manifest.target, s.manifest.kind, s.manifest.organization], [{ policy: "auto" }, "policy", "org-1"]);
  assert.equal(seen.find((s) => String(s.manifest.filename).endsWith(".md"))!.type, "text/plain");
});

test("policies: the command reads the config's policies block and reports a count; without a block there is nothing to do", async () => {
  const d = folder(), { privatePem } = generateKeyPair();
  writeFileSync(join(d, "docs.pem"), privatePem);
  const cfg = join(d, "c.json");
  writeFileSync(cfg, JSON.stringify({ endpoint: "https://comply.example", sources: { macos: {} }, policies: { dir: ".", keyId: "k1", organization: "org-1", keyFile: "docs.pem" } }));
  const lines: string[] = [], errs: string[] = [];
  const deps = { fetch: (async () => new Response(JSON.stringify({ duplicate: true, family: "ac", version: 1 }), { status: 200 })) as unknown as typeof fetch,
    clients: {}, sources: SOURCES, env: {}, now: () => new Date(), out: (s: string) => lines.push(s), err: (s: string) => errs.push(s) };
  assert.equal(await policiesCommand(["--config", cfg], deps as never), 0);
  assert.equal(lines.length, 2);
  assert.match(errs.join("\n"), /2 file\(s\); 0 filed as drafts, 2 unchanged/);
  writeFileSync(cfg, JSON.stringify({ endpoint: "https://comply.example", sources: { macos: {} } }));
  assert.equal(await policiesCommand(["--config", cfg], deps as never), 3);
});

test("policies: the approved versions come back into approved/, versioned, never overwriting, never pushed again (2026-11-05)", async () => {
  const { writeApproved } = await import("../src/policies.ts");
  const d = folder();
  const approved = [
    { family: "ac", title: "Access Control Policy", version: 3, origin: "tailored", filename: null, sha256: "x".repeat(64), approvedAt: "2026-11-05T15:00:00Z", body: "# Access Control Policy\n\nReviewed every quarter." },
    { family: "ir", title: "Incident Response Policy", version: 1, origin: "uploaded", filename: "POL-06_access-control-policy.pdf",
      sha256: (await import("node:crypto")).createHash("sha256").update("%PDF-1.4 Access Control Policy").digest("hex"), approvedAt: "2026-11-05T15:00:00Z" },
    { family: "pe", title: "Physical and Environmental Protection Policy", version: 2, origin: "uploaded", filename: "gone.pdf", sha256: "0".repeat(64), approvedAt: "2026-11-05T15:00:00Z" },
  ];
  const first = writeApproved([d], approved);
  assert.deepEqual(first.map((w) => [w.file, w.outcome]), [
    ["ac-access-control-policy.v3.md", "written"], ["POL-06_access-control-policy.v1.pdf", "written"], ["gone.v2.md", "missing"]]);
  const { readFileSync } = await import("node:fs");
  assert.match(readFileSync(join(d, "approved", "ac-access-control-policy.v3.md"), "utf8"), /version 3, approved .* in Sagentix Comply[\s\S]*Reviewed every quarter/);
  assert.deepEqual(writeApproved([d], approved).map((w) => w.outcome), ["present", "present", "missing"], "a second run writes nothing");
  assert.deepEqual(policyFiles([d]).map((f) => f.name), ["POL-04_code-of-conduct.md", "POL-06_access-control-policy.pdf"], "approved/ is never pushed");
});
