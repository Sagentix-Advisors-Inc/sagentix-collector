// SBOMs: one file per release, as Syft (Anchore, Apache-2.0) or any other generator writes it.
// Three formats are read, each confirmed against Syft's own encoder snapshots
// (syft/format/{cyclonedxjson,spdxjson,syftjson}/testdata/snapshot/*.golden):
//
//   CycloneDX JSON  { bomFormat: "CycloneDX", specVersion, metadata: { timestamp }, components: [ { name, version, purl, cpe } ] }
//   SPDX JSON       { spdxVersion: "SPDX-2.x", creationInfo: { created }, packages: [ { name, versionInfo, externalRefs: [ { referenceType: "purl", referenceLocator } ] } ] }
//   Syft JSON       { artifacts: [ { name, version, purl, cpes } ], descriptor: { name: "syft" } }
//
// Nothing about a component leaves the machine except counts. No network.

import { basename } from "node:path";
import type { Result, Source, SourceContext } from "../types.ts";
import { arr, isObj, str, Results, type Obj } from "./shared-cloud.ts";
import { nonNegNum, paths, readJsonFile, staleness } from "./report_files.ts";

export const SYFT_CHECKS = ["sbom_present", "sbom_components_identified"] as const;
type C = (typeof SYFT_CHECKS)[number];
const DEFAULTS = { maxAgeDays: 0, minPurlPercent: 90 };

export interface Sbom { format: string; created?: string; components: { version: boolean; purl: boolean }[] }

/** The SBOM's format, creation time and, per component, whether it has a version and a package URL. */
export function parseSbom(d: unknown): Sbom | { error: string } {
  if (!isObj(d)) return { error: "not a JSON object" };
  if (d.bomFormat === "CycloneDX") {
    const flat: Obj[] = [];
    const walk = (cs: unknown) => { for (const c of arr(cs).filter(isObj)) { flat.push(c); walk(c.components); } };
    walk(d.components);
    return {
      format: `CycloneDX ${str(d.specVersion) ?? "?"}`, created: isObj(d.metadata) ? str(d.metadata.timestamp) : undefined,
      components: flat.map((c) => ({ version: !!str(c.version), purl: !!str(c.purl) })),
    };
  }
  if (typeof d.spdxVersion === "string") {
    const describes = new Set(arr(d.documentDescribes).map(String));
    const pkgs = arr(d.packages).filter(isObj).filter((p) => !describes.has(String(p.SPDXID)));
    return {
      format: d.spdxVersion, created: isObj(d.creationInfo) ? str(d.creationInfo.created) : undefined,
      components: pkgs.map((p) => ({
        version: !!str(p.versionInfo),
        purl: arr(p.externalRefs).filter(isObj).some((e) => String(e.referenceType).toLowerCase() === "purl" && !!str(e.referenceLocator)),
      })),
    };
  }
  if (Array.isArray(d.artifacts) && isObj(d.descriptor)) {
    return {
      format: `Syft JSON (${str(d.descriptor.name) ?? "?"} ${str(d.descriptor.version) ?? ""})`.replace(" )", ")"),
      components: d.artifacts.filter(isObj).map((a) => ({ version: !!str(a.version), purl: !!str(a.purl) })),
    };
  }
  return { error: "neither CycloneDX (bomFormat), SPDX (spdxVersion) nor Syft JSON (artifacts, descriptor)" };
}

export const syft: Source = {
  name: "syft",
  options: {
    "sbom-file": { type: "string", multiple: true, help: "an SBOM of a current release (CycloneDX JSON, SPDX JSON or Syft JSON, e.g. `syft <image> -o cyclonedx-json=<file>`); repeatable" },
    "sbom-max-age-days": { type: "string", help: "days an SBOM may be old (default 0: no limit, the release decides)" },
    "sbom-min-purl-percent": { type: "string", help: `share of components that must carry a package URL (default ${DEFAULTS.minPurlPercent})` },
  },
  emits: SYFT_CHECKS.map((c) => `syft.${c}`),
  describe(opts) {
    const ps = paths(opts["sbom-file"]);
    return `SBOMs ${ps.length ? ps.map((p) => basename(p)).join(", ") : "(none given)"}`;
  },
  async run(ctx: SourceContext): Promise<Result[]> {
    const out = new Results<C>("syft");
    const files = paths(ctx.opts["sbom-file"]);
    if (!files.length) {
      out.skipAll(SYFT_CHECKS, "sbom", "give --sbom-file <file> for each current release, e.g. `syft <image> -o cyclonedx-json=<file>`");
      return out.results;
    }
    const maxAge = nonNegNum(ctx.opts["sbom-max-age-days"], DEFAULTS.maxAgeDays);
    const minPct = Math.min(100, nonNegNum(ctx.opts["sbom-min-purl-percent"], DEFAULTS.minPurlPercent));
    for (const f of files) {
      const resource = `sbom ${basename(f)}`;
      const r = readJsonFile(f);
      if ("error" in r) {
        // A named SBOM that is missing or unreadable is a failed release, not an unseen one.
        out.add("sbom_present", resource, "fail", `${r.error}; a parseable SBOM required`);
        out.skip("sbom_components_identified", resource, r.error);
        continue;
      }
      const s = parseSbom(r.data);
      if ("error" in s) {
        out.add("sbom_present", resource, "fail", `${basename(f)} is ${s.error}; a CycloneDX or SPDX SBOM required`);
        out.skip("sbom_components_identified", resource, "not an SBOM");
        continue;
      }
      const stale = maxAge > 0 ? staleness(s.created ?? r.mtime.toISOString(), ctx.now, maxAge, s.created ? "SBOM" : "SBOM file (no creation time; file time used)") : undefined;
      const n = s.components.length;
      if (!n) out.add("sbom_present", resource, "fail", `${s.format}: lists no component; an SBOM with its components required`);
      else if (stale) out.add("sbom_present", resource, "fail", `${s.format}, ${n} component(s), but ${stale}`);
      else out.add("sbom_present", resource, "pass", `${s.format}, ${n} component(s)${s.created ? `, created ${s.created.slice(0, 10)}` : ""}; a parseable SBOM with components required`);
      if (!n) { out.skip("sbom_components_identified", resource, "the SBOM lists no component"); continue; }
      const withPurl = s.components.filter((c) => c.purl).length, withVersion = s.components.filter((c) => c.version).length;
      const pct = Math.floor((withPurl / n) * 1000) / 10;
      out.add("sbom_components_identified", resource, pct >= minPct ? "pass" : "fail",
        `${withPurl} of ${n} component(s) (${pct}%) carry a package URL, ${withVersion} a version; at least ${minPct}% with a package URL required`);
    }
    return out.results;
  },
};
