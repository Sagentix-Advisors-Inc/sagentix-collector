// A small XML reader for AWS's query-protocol (IAM, EC2, RDS, STS) and S3 responses: elements and
// text only. Attributes, namespaces, comments and processing instructions are dropped. It is not a
// general XML parser; it reads the well-formed documents AWS returns.

export interface XNode { tag: string; text: string; kids: XNode[] }

const ENT: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };
const decode = (s: string) => s.replace(/&(#x[0-9a-fA-F]+|#\d+|amp|lt|gt|quot|apos);/g, (_, e: string) =>
  e[0] === "#" ? String.fromCodePoint(e[1] === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)) : ENT[e]);

/** Parses a document into a root node whose kids are the top-level elements. Throws on broken nesting. */
export function parseXml(src: string): XNode {
  const root: XNode = { tag: "#document", text: "", kids: [] };
  const stack: XNode[] = [root];
  const re = /<!\[CDATA\[([\s\S]*?)\]\]>|<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!DOCTYPE[^>]*>|<\/\s*([^\s>]+)\s*>|<\s*([^\s/>]+)[^>]*?(\/?)>|([^<]+)/g;
  for (const m of src.matchAll(re)) {
    const top = stack[stack.length - 1];
    if (m[1] !== undefined) top.text += m[1];
    else if (m[2] !== undefined) {
      const name = local(m[2]);
      if (stack.length < 2 || top.tag !== name) throw new Error(`XML: unexpected </${name}>`);
      top.text = top.text.trim();
      stack.pop();
    } else if (m[3] !== undefined) {
      const node: XNode = { tag: local(m[3]), text: "", kids: [] };
      top.kids.push(node);
      if (m[4] !== "/") stack.push(node);
    } else if (m[5] !== undefined) top.text += decode(m[5]);
  }
  if (stack.length !== 1) throw new Error(`XML: <${stack[stack.length - 1].tag}> is not closed`);
  return root;
}

const local = (name: string) => name.slice(name.indexOf(":") + 1);

/** Direct children with this tag. */
export const kids = (n: XNode | undefined, tag: string): XNode[] => (n ? n.kids.filter((k) => k.tag === tag) : []);
/** Follows direct children tag by tag. */
export function path(n: XNode | undefined, ...tags: string[]): XNode | undefined {
  let cur = n;
  for (const t of tags) cur = cur?.kids.find((k) => k.tag === t);
  return cur;
}
/** The first descendant with this tag, depth first. */
export function deep(n: XNode | undefined, tag: string): XNode | undefined {
  if (!n) return undefined;
  for (const k of n.kids) {
    if (k.tag === tag) return k;
    const d = deep(k, tag);
    if (d) return d;
  }
  return undefined;
}
/** Text of the first descendant with this tag. */
export const deepText = (n: XNode | undefined, tag: string): string | undefined => deep(n, tag)?.text;
/** Text of the direct child with this tag. */
export const kidText = (n: XNode | undefined, tag: string): string | undefined => path(n, tag)?.text;
/** The `item` (EC2) or `member` (IAM, RDS) children of a list element. */
export const items = (n: XNode | undefined): XNode[] => (n ? n.kids.filter((k) => k.tag === "item" || k.tag === "member") : []);
