// What a privacy notice, a consent banner and a privacy-request channel look like from outside: the judges the web
// source (web.ts) applies to the HTML of a page the organization declared. Pure functions over a string; nothing here
// touches the network. Every scan is a plain indexOf or a bounded, anchored pattern, so a hostile page cannot make it
// slow (CodeQL js/polynomial-redos).
//
// A result names what was found (a topic, a date, a vendor, the kind of channel and a mail domain), never page text,
// a cookie or a person: a mailbox's local part is dropped.

/** The longest page body read, in bytes. A privacy notice or a home page stays well under it. */
export const MAX_PAGE_BYTES = 2 * 1024 * 1024;

// ── Consent-management platforms ──────────────────────────────────────────────────────────────────
// The script host each vendor's own installation page tells a site to embed, each page read 2026-11-07 (URL in `doc`).
// A host seen anywhere in the page (a script src, or an inline loader that names it) counts. A banner loaded later
// through a tag manager is invisible to one GET, so a miss is reported as such, never as proof that no banner exists.
// Left out because no public page could be read on 2026-11-07: Ketch (docs.ketch.com asks for a sign-in) and
// embeds.iubenda.com (not on iubenda's page). A privacy-request portal host is not matched either: OneTrust, Osano and
// Transcend publish none that a public page names, so a request form is recognized by its link text instead.
export interface Cmp { vendor: string; hosts: string[]; doc: string }
export const CMPS: Cmp[] = [
  // `src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js" … data-domain-script=`
  { vendor: "OneTrust", hosts: ["cdn.cookielaw.org"], doc: "https://developer.onetrust.com/onetrust/docs/google-tag-manager" },
  // "https://cmp.osano.com/{customer_id}/{configuration_id}/osano.js" (page updated 2026-10)
  { vendor: "Osano", hosts: ["cmp.osano.com"], doc: "https://docs.osano.com/en-US/osano/article/2NM_rejJ-installing-osano-on-shopify" },
  // `src="https://consent.cookiebot.com/uc.js" data-cbid=`
  { vendor: "Cookiebot", hosts: ["consent.cookiebot.com"], doc: "https://www.cookiebot.com/en/manual-implementation/" },
  // V3 web.cmp.usercentrics.eu/ui/loader.js; V2 and V1 app.usercentrics.eu
  { vendor: "Usercentrics", hosts: ["web.cmp.usercentrics.eu", "app.usercentrics.eu"], doc: "https://support.usercentrics.com/hc/en-us/articles/16048416515868-Establishing-the-version-of-the-Consent-Management-Platform" },
  // `src="//consent.trustarc.com/v2/notice/{cmId}"` (implementation guide v3.2, 2026-05-15)
  { vendor: "TrustArc", hosts: ["consent.trustarc.com"], doc: "https://consent.trustarc.com/asset/TrustArc_Cookie_Consent_Manager_Implementation_Guide.pdf" },
  // `src="https://app.termly.io/resource-blocker/YOUR-WEBSITE-UUID?autoBlock=on"`
  { vendor: "Termly", hosts: ["app.termly.io"], doc: "https://support.termly.io/hc/en-us/articles/30710458065681-Termly-CMP-embed-script-versions" },
  // `src="//cdn.iubenda.com/cs/iubenda_cs.js"` (page updated 2026-10-23)
  { vendor: "iubenda", hosts: ["cdn.iubenda.com"], doc: "https://www.iubenda.com/en/help/1205-how-to-configure-your-cookie-solution-advanced-guide" },
  // "whitelist https://sdk.privacy-center.org/ and https://api.privacy-center.org/"
  { vendor: "Didomi", hosts: ["sdk.privacy-center.org"], doc: "https://developers.didomi.io/cmp/web-sdk/getting-started" },
  // "script-src 'self' cdn-cookieyes.com"
  { vendor: "CookieYes", hosts: ["cdn-cookieyes.com"], doc: "https://www.cookieyes.com/documentation/content-security-policy/" },
  // "Your bundle URL looks like https://transcend-cdn.com/cm/<your-bundle-id>/airgap.js"
  { vendor: "Transcend", hosts: ["transcend-cdn.com"], doc: "https://docs.transcend.io/docs/articles/consent-management/configuration/installing-airgap/installing-airgap-js" },
];

/** Lowercase, entities for spaces and apostrophes undone. */
const lower = (s: string) => s.toLowerCase().replace(/&nbsp;|&#160;/g, " ").replace(/&#39;|&rsquo;|&#8217;/g, "'");

/** The page's text without script and style blocks or tags, collapsed to single spaces; linear time. */
export function pageText(html: string): string {
  const h = lower(html);
  let out = "", i = 0;
  while (i < h.length) {
    const lt = h.indexOf("<", i);
    if (lt < 0) { out += h.slice(i); break; }
    out += h.slice(i, lt) + " ";
    for (const block of ["script", "style", "noscript", "template"]) {
      if (h.startsWith(`<${block}`, lt)) {
        const end = h.indexOf(`</${block}`, lt);
        i = end < 0 ? h.length : end;
        break;
      }
    }
    const gt = h.indexOf(">", Math.max(i, lt));
    if (gt < 0) break;
    i = gt + 1;
  }
  return out.replace(/&amp;/g, "&").replace(/\s+/g, " ").trim();
}

/** The value of each `attr="…"` (or '…') inside tags named `tag`, in order; linear time. */
export function attrValues(html: string, tag: string, attr: string): string[] {
  const h = lower(html), out: string[] = [];
  let i = 0;
  while ((i = h.indexOf(`<${tag}`, i)) >= 0) {
    const end = h.indexOf(">", i);
    if (end < 0) break;
    const t = html.slice(i, end), tl = h.slice(i, end);
    let k = tl.indexOf(` ${attr}=`);
    if (k < 0) k = tl.indexOf(`\n${attr}=`);
    if (k >= 0) {
      let v = t.slice(k + attr.length + 2).trim();
      const q = v[0];
      if (q === '"' || q === "'") { const close = v.indexOf(q, 1); v = close < 0 ? v.slice(1) : v.slice(1, close); }
      else v = v.split(/\s/)[0];
      out.push(v.trim());
    }
    i = end + 1;
  }
  return out;
}

const hostOf = (raw: string, base: URL): string | undefined => {
  try { const u = new URL(raw.replace(/&amp;/g, "&"), base); return u.protocol === "https:" || u.protocol === "http:" ? u.hostname.toLowerCase() : undefined; } catch { return undefined; }
};
const site = (host: string) => host.split(".").slice(-2).join(".");

export interface ConsentFinding { result: "pass" | "fail" | "skipped"; detail: string; vendors: string[] }

/** Is a known consent-management platform loaded by the page? */
export function judgeConsent(html: string, page: URL): ConsentFinding {
  const h = lower(html);
  const vendors = CMPS.filter((c) => c.hosts.some((x) => h.includes(x))).map((c) => c.vendor);
  const scripts = attrValues(html, "script", "src").map((s) => hostOf(s, page)).filter((x): x is string => !!x);
  const third = [...new Set(scripts.filter((x) => site(x) !== site(page.hostname)))].sort();
  if (vendors.length) return { result: "pass", vendors, detail: `consent-management platform script on the page: ${vendors.join(", ")}` };
  if (!third.length) return { result: "skipped", vendors, detail: "the page loads no script from another site, so there is no third-party tracker for a consent banner to govern (a banner loaded later by a tag manager would not show in one GET)" };
  return { result: "fail", vendors, detail: `${third.length} script host(s) from other sites (${third.slice(0, 15).join(", ")}${third.length > 15 ? ", …" : ""}) and no known consent-management platform (${CMPS.map((c) => c.vendor).join(", ")}); a self-built banner or one loaded by a tag manager is not recognized: confirm it by hand` };
}

// ── The notice itself ─────────────────────────────────────────────────────────────────────────────

/** A page that calls itself a privacy notice: in its title or first heading, in English or French. */
export function looksLikeNotice(html: string): boolean {
  const h = lower(html);
  const between = (open: string, close: string) => { const i = h.indexOf(open); if (i < 0) return ""; const j = h.indexOf(close, i); return h.slice(i, j < 0 ? i + 400 : Math.min(j, i + 2000)); };
  return /privacy|personal information|data protection|confidentialit|vie privée|renseignements personnels|protection des (données|renseignements)/.test(`${between("<title", "</title")} ${between("<h1", "</h1")}`);
}

// Topics a notice must cover, each page read 2026-11-07:
//   NIST SP 800-53 Rev. 5 PT-5 (OSCAL catalogue v5.2.0, github.com/usnistgov/oscal-content): the notice "Identifies the
//     purposes" and the authority, and is "clear and easy-to-understand".
//   PIPEDA Schedule 1 clause 4.8.2 (laws-lois.justice.gc.ca/eng/acts/P-8.6/page-7.html, current to 2026-10-19): the
//     person accountable and their address, "the means of gaining access", "a description of the type of personal
//     information held", and what is made available to related organizations; clause 4.5 for retention.
//   Office of the Privacy Commissioner of Canada, Guidelines for obtaining meaningful consent (priv.gc.ca/en/
//     privacy-topics/collecting-personal-information/consent/gl_omc_201805/, modified 2025-08-11): what is collected,
//     with which parties it is shared, and for what purposes.
// Each topic is a set of English and French phrases; one is enough, and a person confirms the wording.
export const TOPICS: { id: string; en: string; phrases: string[] }[] = [
  { id: "collected", en: "what personal information is collected", phrases: ["information we collect", "information collected", "we collect", "collect the following", "collection of personal", "types of personal", "categories of personal", "renseignements que nous recueillons", "nous recueillons", "collecte de renseignements", "collecte des renseignements", "données que nous collectons", "nous collectons"] },
  { id: "purposes", en: "the purposes it is used for", phrases: ["purpose", "how we use", "use your", "use of your", "uses of personal", "fins", "nous utilisons", "utilisation de vos", "utilisation des renseignements"] },
  { id: "sharing", en: "to whom it is disclosed", phrases: ["share", "disclos", "third part", "service provider", "communiquons", "communication de", "tiers", "fournisseurs de services"] },
  { id: "retention", en: "how long it is kept", phrases: ["retain", "retention", "how long", "keep your", "conserv"] },
  { id: "access", en: "how to see or correct it", phrases: ["access to your", "access your", "right to access", "request access", "correct", "rectif", "accès à vos", "accéder à vos", "droit d'accès", "demande d'accès"] },
  { id: "contact", en: "whom to contact about it", phrases: ["privacy officer", "data protection officer", "contact us", "contact our", "how to contact", "questions about", "agent de protection", "responsable de la protection", "nous joindre", "communiquer avec nous", "nous contacter"] },
  { id: "choice", en: "consent and how to withdraw it", phrases: ["consent", "opt out", "opt-out", "withdraw", "unsubscribe", "consentement", "retirer", "désabonner"] },
];

export function noticeTopics(text: string): { found: string[]; missing: string[] } {
  const found: string[] = [], missing: string[] = [];
  for (const t of TOPICS) (t.phrases.some((p) => text.includes(p)) ? found : missing).push(t.id);
  return { found, missing };
}

const MONTHS: Record<string, number> = {
  january: 1, february: 2, march: 3, april: 4, may: 5, june: 6, july: 7, august: 8, september: 9, october: 10, november: 11, december: 12,
  jan: 1, feb: 2, mar: 3, apr: 4, jun: 6, jul: 7, aug: 8, sep: 9, sept: 9, oct: 10, nov: 11, dec: 12,
  janvier: 1, février: 2, fevrier: 2, mars: 3, avril: 4, mai: 5, juin: 6, juillet: 7, août: 8, aout: 8, septembre: 9, octobre: 10, novembre: 11, décembre: 12, decembre: 12,
};
const LABELS = ["last updated", "last update", "last modified", "last revised", "updated on", "updated:", "effective date", "effective as of", "effective:", "revised", "date of last revision", "dernière mise à jour", "derniere mise a jour", "mis à jour le", "mise à jour :", "en vigueur", "date d'entrée en vigueur", "révisé le", "dernière révision"];

const iso = (y: number, m: number, d: number) => {
  if (y < 1995 || y > 2100 || m < 1 || m > 12 || d < 1 || d > 31) return undefined;
  const t = Date.UTC(y, m - 1, d);
  return new Date(t).getUTCDate() === d ? new Date(t).toISOString().slice(0, 10) : undefined;
};

/** The first date in a short stretch of text: 2026-03-01, March 1, 2026, 1 March 2026, 1er mars 2026, or March 2026 (the 1st). */
export function firstDate(s: string): string | undefined {
  const a = s.match(/\b(\d{4})-(\d{2})-(\d{2})\b/);
  const b = s.match(/\b([a-zéû]{3,9})\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})\b/);
  const c = s.match(/\b(\d{1,2})(?:er|st|nd|rd|th)?\s+([a-zéû]{3,9})\.?,?\s+(\d{4})\b/);
  const d = s.match(/\b([a-zéû]{3,9})\.?,?\s+(\d{4})\b/);
  const cands: { at: number; v: string | undefined }[] = [];
  if (a) cands.push({ at: a.index!, v: iso(+a[1], +a[2], +a[3]) });
  if (b && MONTHS[b[1]]) cands.push({ at: b.index!, v: iso(+b[3], MONTHS[b[1]], +b[2]) });
  if (c && MONTHS[c[2]]) cands.push({ at: c.index!, v: iso(+c[3], MONTHS[c[2]], +c[1]) });
  if (d && MONTHS[d[1]]) cands.push({ at: d.index! + 0.5, v: iso(+d[2], MONTHS[d[1]], 1) });
  return cands.filter((x) => x.v).sort((x, y) => x.at - y.at)[0]?.v;
}

/** The notice's own "last updated" or "effective" date: the first date within 60 characters after such a label. */
export function noticeDate(text: string): { date: string; label: string } | undefined {
  let best: { at: number; date: string; label: string } | undefined;
  for (const label of LABELS) {
    let i = 0;
    while ((i = text.indexOf(label, i)) >= 0) {
      const date = firstDate(text.slice(i + label.length, i + label.length + 60));
      if (date && (!best || i < best.at)) best = { at: i, date, label: label.replace(/[:\s]+$/, "") };
      i += label.length;
      if (date) break;
    }
  }
  return best && { date: best.date, label: best.label };
}

const REQUEST_WORDS = ["data subject", "subject access", "access request", "privacy request", "request form", "dsar", "your privacy choices", "do not sell", "exercise your rights", "demande d'accès", "demande de renseignements personnels", "accès à l'information", "exercer vos droits", "formulaire de demande", "privacy-request", "privacy_request"];
const PRIVACY_MAILBOX = /^(privacy|privacidad|dpo|data-?protection|dataprotection|gdpr|ccpa|confidentialite|vieprivee|vie-privee|protection|aiprp|atip|access|legal)\b/;

export interface RequestChannel { pass: boolean; detail: string }

/** A way to ask for one's own information, published on the notice: a privacy mailbox or a link to a request form. */
export function judgeRequestChannel(html: string, page: URL): RequestChannel {
  const hrefs = attrValues(html, "a", "href");
  const mail = hrefs.filter((x) => /^mailto:/i.test(x)).map((x) => x.slice(7).split("?")[0].trim().toLowerCase()).filter((x) => x.includes("@"));
  const roleMail = mail.filter((m) => PRIVACY_MAILBOX.test(m.split("@")[0]));
  // A link to a form: its address or its text names a privacy request.
  const h = lower(html);
  let forms = 0, i = 0;
  while ((i = h.indexOf("<a", i)) >= 0) {
    const close = h.indexOf("</a", i);
    if (close < 0) break;
    const chunk = h.slice(i, Math.min(close, i + 2000));
    if (REQUEST_WORDS.some((w) => chunk.includes(w)) && !chunk.includes("mailto:")) forms++;
    i = close + 3;
  }
  const kinds = [roleMail.length && `${roleMail.length} privacy mailbox link(s) at ${[...new Set(roleMail.map((m) => m.split("@")[1]))].join(", ")}`,
    forms && `${forms} link(s) to a privacy-request form`].filter(Boolean) as string[];
  if (kinds.length) return { pass: true, detail: `privacy-request channel published: ${kinds.join("; ")}` };
  const other = mail.length ? `; ${mail.length} other mailto link(s) not named for privacy` : "";
  return { pass: false, detail: `no privacy mailbox (privacy@, dpo@, …) or privacy-request form linked from the notice${other}` };
}

// ── robots.txt (RFC 9309) ─────────────────────────────────────────────────────────────────────────

/**
 * Does robots.txt let `agent` fetch `path`? The group naming the agent's product token wins over `*` (§2.2.1); within
 * it the longest matching Allow or Disallow rule decides, Allow on a tie (§2.2.2); `*` and a trailing `$` are honoured.
 */
export function robotsAllows(robots: string, agent: string, path: string): boolean {
  const token = agent.split("/")[0].toLowerCase();
  type G = { agents: string[]; rules: { allow: boolean; path: string }[] };
  const groups: G[] = [];
  let cur: G | undefined, lastWasAgent = false;
  for (const raw of robots.split(/\r?\n/).slice(0, 5000)) {
    const line = raw.replace(/#.*$/, "").trim();
    const k = line.indexOf(":");
    if (k < 0) continue;
    const key = line.slice(0, k).trim().toLowerCase(), val = line.slice(k + 1).trim();
    if (key === "user-agent") {
      if (!cur || !lastWasAgent) { cur = { agents: [], rules: [] }; groups.push(cur); }
      cur.agents.push(val.toLowerCase());
      lastWasAgent = true;
    } else if ((key === "allow" || key === "disallow") && cur) {
      lastWasAgent = false;
      if (val) cur.rules.push({ allow: key === "allow", path: val });
    } else lastWasAgent = false;
  }
  const mine = groups.filter((g) => g.agents.some((a) => a !== "*" && token.startsWith(a)));
  const rules = (mine.length ? mine : groups.filter((g) => g.agents.includes("*"))).flatMap((g) => g.rules);
  const matches = (rule: string) => {
    const anchored = rule.endsWith("$"), parts = (anchored ? rule.slice(0, -1) : rule).split("*");
    if (!path.startsWith(parts[0])) return false;
    if (parts.length === 1) return !anchored || path === parts[0];
    let at = parts[0].length;
    for (const p of parts.slice(1, -1)) { const f = path.indexOf(p, at); if (f < 0) return false; at = f + p.length; }
    const last = parts[parts.length - 1];
    return anchored ? path.length - last.length >= at && path.endsWith(last) : last === "" || path.indexOf(last, at) >= 0;
  };
  let best: { allow: boolean; len: number } | undefined;
  for (const r of rules) if (matches(r.path) && (!best || r.path.length > best.len || (r.path.length === best.len && r.allow))) best = { allow: r.allow, len: r.path.length };
  return best ? best.allow : true;
}
