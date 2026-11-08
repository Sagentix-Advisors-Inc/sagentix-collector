// THE ORGANIZATION'S POLICIES, PUSHED FROM WHERE IT KEEPS THEM (Stéphane, 2026-11-05: "the collector would point to the
// location where the policies are stored - then the collector push them to the app - and the app match them
// automatically to the proper security controls").
//
//   collector policies --config collector.config.json      reads the config's "policies" block
//
// Each PDF, Word or text file in the folders goes to sos-app's signed document door (POST /api/collect/document,
// apps/sos-app/src/routes/documents.ts) with target {policy: "auto"}: sos-app reads its title and text, matches it to a
// NIST SP 800-53 control family and files it as that family's draft policy for a person to approve, or says why not.
// Signed with a 'documents' key, never the collector key, so a collector key in CI never files documents. Files are only
// read; sending the same bytes again files nothing (sos-app answers "duplicate"). Nothing is deleted or moved.
import { createHash } from "node:crypto";
import { constants as fsConstants, copyFileSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, extname, join } from "node:path";
import { signBody, signRequest } from "./keys.ts";

export const DOCUMENTS_KEY_ENV = "SAGENTIX_DOCUMENTS_KEY";
export const DOCUMENT_PATH = "/api/collect/document";
export const POLICY_TYPES: Record<string, string> = {
  ".pdf": "application/pdf",
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".txt": "text/plain", ".md": "text/plain",
};
const MAX_BYTES = 10 * 1024 * 1024;

export interface PoliciesConfig { dir: string | string[]; keyId: string; organization: string; keyFile?: string }
export interface PolicyOutcome { file: string; status: number; outcome: "filed" | "duplicate" | "evidence" | "unmatched" | "taken" | "refused" | "skipped"; detail: string }

/** One file per policy when the same name comes in several formats (POL-06.pdf, .docx, .md): the PDF first, the document
 *  of record a reader opens, then Word, then text (Sagentix's folder holds all three, 2026-11-05). */
export const FORMAT_ORDER = [".pdf", ".docx", ".md", ".txt"];

/** The policy files in the folders, sorted, one level deep (no hidden files, no sub-folders: an archive folder stays out). */
export function policyFiles(dirs: string[]): { path: string; name: string; type: string }[] {
  const all = allPolicyFiles(dirs), best = new Map<string, { path: string; name: string; type: string }>();
  const rank = (n: string) => FORMAT_ORDER.indexOf(extname(n).toLowerCase());
  for (const f of all) {
    const key = join(dirname(f.path), basename(f.name, extname(f.name)).toLowerCase());
    const had = best.get(key);
    if (!had || rank(f.name) < rank(had.name)) best.set(key, f);
  }
  return [...best.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function allPolicyFiles(dirs: string[]): { path: string; name: string; type: string }[] {
  const out: { path: string; name: string; type: string }[] = [];
  for (const d of dirs) {
    for (const name of readdirSync(d).sort()) {
      const type = POLICY_TYPES[extname(name).toLowerCase()];
      if (!type || name.startsWith(".") || name.startsWith("~$")) continue;
      const path = join(d, name);
      if (statSync(path).isFile()) out.push({ path, name, type });
    }
  }
  return out;
}

const b64url = (b: Uint8Array) => Buffer.from(b).toString("base64url");

/** Pushes every policy file; one outcome per file. `organization` is the key's organization id (sos-app checks it). */
export async function pushPolicies(o: { endpoint: string; organization: string; keyId: string; pem: string; dirs: string[]; fetch: typeof fetch; now: () => Date }): Promise<PolicyOutcome[]> {
  const url = new URL(DOCUMENT_PATH, o.endpoint).toString();
  const results: PolicyOutcome[] = [];
  for (const f of policyFiles(o.dirs)) {
    const bytes = readFileSync(f.path);
    if (bytes.byteLength > MAX_BYTES || bytes.byteLength === 0) { results.push({ file: f.name, status: 0, outcome: "skipped", detail: "empty or over 10 MB" }); continue; }
    const manifest = {
      format: "sagentix-document/1", issuedAt: o.now().toISOString(), organization: o.organization, target: { policy: "auto" },
      filename: f.name.slice(0, 120), contentType: f.type, sha256: createHash("sha256").update(bytes).digest("hex"), size: bytes.byteLength, kind: "policy",
    };
    const mBytes = new TextEncoder().encode(JSON.stringify(manifest));
    let res: Response;
    try {
      // Signature v2 over the manifest's hash (the manifest names the file's SHA-256); the manifest's own signature goes
      // beside it as x-sagentix-content-signature, the one sos-app keeps for the assessor.
      res = await o.fetch(url, { method: "POST", body: bytes, headers: { "content-type": f.type,
        ...signRequest(o.pem, o.keyId, "POST", DOCUMENT_PATH, mBytes, o.now().getTime()).headers,
        "x-sagentix-content-signature": signBody(o.pem, mBytes), "x-sagentix-document": b64url(mBytes) } });
    } catch (e) { results.push({ file: f.name, status: 0, outcome: "refused", detail: String((e as Error)?.message ?? e) }); continue; }
    const text = await res.text();
    let j: Record<string, unknown> = {};
    try { j = JSON.parse(text); } catch { /* not JSON */ }
    const fam = typeof j.family === "string" ? j.family.toUpperCase() : "";
    if (res.status === 201 && j.family) results.push({ file: f.name, status: 201, outcome: "filed", detail: `${fam} version ${j.version}, a draft for approval` });
    else if (res.status === 201) results.push({ file: f.name, status: 201, outcome: "evidence", detail: `policy evidence on ${String(j.control ?? "?").toUpperCase()}` });
    else if (res.status === 200 && j.duplicate) results.push({ file: f.name, status: 200, outcome: "duplicate", detail: fam ? `${fam} version ${j.version}, unchanged` : "unchanged" });
    else if (j.code === "policy_unmatched") results.push({ file: f.name, status: res.status, outcome: "unmatched", detail: String(j.error ?? "") });
    else if (j.code === "policy_family_taken") results.push({ file: f.name, status: res.status, outcome: "taken", detail: String(j.error ?? "") });
    else results.push({ file: f.name, status: res.status, outcome: "refused", detail: String(j.error ?? text).slice(0, 300) });
  }
  return results;
}

export const PULL_PATH = "/api/collect/policies/approved";
export const APPROVED_DIR = "approved";
export interface ApprovedPolicy { family: string; title: string; version: number; origin: string; filename: string | null; sha256: string; approvedAt: string; body?: string }

/** The organization's approved policies, read with the documents key (sos-app src/routes/documents.ts pullApprovedPolicies). */
export async function pullApproved(o: { endpoint: string; organization: string; keyId: string; pem: string; fetch: typeof fetch; now: () => Date }): Promise<ApprovedPolicy[]> {
  const m = new TextEncoder().encode(JSON.stringify({ format: "sagentix-policies-pull/1", issuedAt: o.now().toISOString(), organization: o.organization }));
  const res = await o.fetch(new URL(PULL_PATH, o.endpoint).toString(), { method: "POST", headers: {
    ...signRequest(o.pem, o.keyId, "POST", PULL_PATH, m, o.now().getTime()).headers, "x-sagentix-document": b64url(m) } });
  const text = await res.text();
  if (!res.ok) throw new Error(`sos-app answered HTTP ${res.status} for the approved policies: ${text.slice(0, 200)}`);
  return (JSON.parse(text) as { policies: ApprovedPolicy[] }).policies;
}

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

/** Writes each approved version into <first folder>/approved/ (Stéphane, 2026-11-05: an approved policy must never be
 *  overwritten by the next push, and the folder should hold the text in force). A version made in sos-app is written as
 *  Markdown; an approved uploaded file is copied from the folder when the folder holds those exact bytes. Each name
 *  carries its version (…v3.md), so nothing is ever overwritten; earlier approved copies stay as history. The push never
 *  reads sub-folders, so these copies are never sent back. */
export function writeApproved(dirs: string[], approved: ApprovedPolicy[]): { file: string; outcome: "written" | "present" | "missing"; detail: string }[] {
  const out: { file: string; outcome: "written" | "present" | "missing"; detail: string }[] = [];
  if (!dirs.length) return out;
  const target = join(dirs[0], APPROVED_DIR);
  const local = allPolicyFiles(dirs).map((f) => ({ ...f, sha: createHash("sha256").update(readFileSync(f.path)).digest("hex") }));
  for (const p of approved) {
    const fromFile = p.origin === "uploaded" ? local.find((f) => f.sha === p.sha256) : undefined;
    const stem = fromFile ? basename(fromFile.name, extname(fromFile.name)) : p.filename ? basename(p.filename, extname(p.filename)) : `${p.family}-${slug(p.title)}`;
    const name = `${stem}.v${p.version}${fromFile ? extname(fromFile.name).toLowerCase() : ".md"}`;
    const dest = join(target, name);
    // One exclusive create each (flag "wx", COPYFILE_EXCL), never a check then a write (CodeQL js/file-system-race):
    // a file already there is the answer "present", and nothing is ever overwritten.
    const present = (e: unknown) => (e as NodeJS.ErrnoException)?.code === "EEXIST";
    if (p.body !== undefined) {
      mkdirSync(target, { recursive: true });
      try {
        writeFileSync(dest, `<!-- ${p.title}, version ${p.version}, approved ${p.approvedAt} in Sagentix Comply. This is the text in force: edit a copy of it in the folder above. -->\n\n${p.body}`, { flag: "wx" });
        out.push({ file: name, outcome: "written", detail: `${p.family.toUpperCase()} version ${p.version}, the text approved in sos-app` });
      } catch (e) { if (!present(e)) throw e; out.push({ file: name, outcome: "present", detail: `${p.family.toUpperCase()} version ${p.version}, already here` }); }
    } else if (fromFile) {
      mkdirSync(target, { recursive: true });
      try {
        copyFileSync(fromFile.path, dest, fsConstants.COPYFILE_EXCL);
        out.push({ file: name, outcome: "written", detail: `${p.family.toUpperCase()} version ${p.version}, your approved file` });
      } catch (e) { if (!present(e)) throw e; out.push({ file: name, outcome: "present", detail: `${p.family.toUpperCase()} version ${p.version}, already here` }); }
    } else out.push({ file: name, outcome: "missing", detail: `${p.family.toUpperCase()} version ${p.version} is an uploaded file this folder no longer holds (SHA-256 ${p.sha256.slice(0, 12)}…)` });
  }
  return out;
}
