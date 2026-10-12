import { isAlias, isMap, isPair, isScalar, isSeq, LineCounter, Parser, parseAllDocuments } from 'yaml';
import { FileDetail as D, type FileFindingAction } from './types';

/** What the YAML rules report and change, by index into the text. */
export interface YamlHooks {
  report(detail: D, line: number, data: Record<string, string | number>): FileFindingAction;
  edit(index: number, length: number, insert: string): void;
}

export interface YamlLimits {
  /** Collections nested deeper than this reject the file. */
  depth: number;
  /** Aliases that make the document this many times as large as written, and over 10,000 nodes, reject the file. */
  aliasExpansion: number;
}

/** A document with aliases still expands this far before its ratio counts. */
const EXPANSION_FLOOR = 10_000;

const YAML_TAG = 'tag:yaml.org,2002:';
/** The tags of the YAML 1.2 core schema and the YAML 1.1 types. Each makes data, never an object of a language. */
const SCHEMA_TAGS = new Set(['str', 'int', 'float', 'bool', 'null', 'map', 'seq', 'binary', 'timestamp', 'set', 'omap', 'pairs', 'merge', 'value'].map(t => YAML_TAG + t));

type AnyNode = unknown;

/** The children of a collection: a sequence's items, a mapping's keys and values. */
function children(node: AnyNode): AnyNode[] {
  if (isSeq(node)) return node.items;
  if (isMap(node)) return node.items.flatMap(p => [p.key, p.value]);
  if (isPair(node)) return [node.key, node.value];
  return [];
}

/** The deepest nesting of collections, without recursion. */
function depthOf(root: AnyNode): number {
  let max = 0;
  const stack: Array<[AnyNode, number]> = [[root, 0]];
  while (stack.length) {
    const [node, d] = stack.pop() as [AnyNode, number];
    const deeper = isMap(node) || isSeq(node) ? d + 1 : d;
    if (deeper > max) max = deeper;
    for (const c of children(node)) if (c !== null && c !== undefined) stack.push([c, deeper]);
  }
  return max;
}

/** Nodes as written, and as a reader that follows every alias sees them. */
function sizes(root: AnyNode, resolve: (alias: AnyNode) => AnyNode): { written: number; expanded: number } {
  let written = 0;
  const memo = new Map<AnyNode, number>();
  const busy = new Set<AnyNode>();
  const expand = (node: AnyNode): number => {
    if (node === null || node === undefined) return 0;
    if (isAlias(node)) {
      const target = resolve(node);
      if (target === undefined || busy.has(target)) return 1;
      return expand(target);
    }
    const known = memo.get(node);
    if (known !== undefined) return known;
    busy.add(node);
    let n = 1;
    for (const c of children(node)) n += expand(c);
    busy.delete(node);
    memo.set(node, n);
    return n;
  };
  const count = (node: AnyNode): void => {
    const stack = [node];
    while (stack.length) {
      const n = stack.pop();
      if (n === null || n === undefined) continue;
      written++;
      stack.push(...children(n));
    }
  };
  count(root);
  return { written, expanded: expand(root) };
}

/** Every tag token in a CST document, at any depth. */
function tagTokens(token: unknown, out: Array<{ offset: number; source: string }>): void {
  if (!token || typeof token !== 'object') return;
  const t = token as Record<string, unknown>;
  if (t.type === 'tag' && typeof t.offset === 'number' && typeof t.source === 'string') {
    out.push({ offset: t.offset, source: t.source });
    return;
  }
  for (const key of ['start', 'sep', 'props', 'end', 'items']) {
    const list = t[key];
    if (Array.isArray(list)) for (const x of list) tagTokens(x, out);
  }
  for (const key of ['key', 'value']) tagTokens(t[key], out);
}

/** The span that removes the pair at `i` of a mapping, with its separator, so the mapping around it still reads. */
function pairSpan(text: string, items: unknown[], i: number, flow: boolean): [number, number] | undefined {
  const pair = items[i];
  if (!isPair(pair) || !isScalar(pair.key) || !pair.key.range) return undefined;
  const keyStart = (p: unknown) => (isPair(p) && p.key && (p.key as { range?: number[] }).range ? (p.key as { range: number[] }).range[0] : undefined);
  const end = (p: unknown, nodeEnd: boolean): number | undefined => {
    if (!isPair(p)) return undefined;
    const v = p.value as { range?: number[] } | null;
    if (v?.range) return nodeEnd ? v.range[2] : v.range[1];
    const k = (p.key as { range?: number[] }).range;
    if (!k) return undefined;
    if (!nodeEnd) return k[1];
    const nl = text.indexOf('\n', k[1]);
    return nl < 0 ? text.length : nl + 1;
  };
  const start = pair.key.range[0];
  const next = keyStart(items[i + 1]);
  if (next !== undefined) return [start, next];
  const thisEnd = end(pair, !flow);
  if (thisEnd === undefined) return undefined;
  if (i > 0) {
    const prevEnd = end(items[i - 1], !flow);
    return prevEnd === undefined ? undefined : [prevEnd, thisEnd];
  }
  return [start, thisEnd];
}

/**
 * The YAML rules, over the whole text, since YAML has to be parsed whole. Edits are by index into the text. A
 * document that does not parse stops the rules there, since the file is rejected.
 */
export function yamlRules(text: string, limits: YamlLimits, hooks: YamlHooks): void {
  const lines = new LineCounter();
  const lineOf = (index: number) => lines.linePos(index).line;
  let docs: ReturnType<typeof parseAllDocuments>;
  try {
    docs = parseAllDocuments(text, { uniqueKeys: false, lineCounter: lines, prettyErrors: false });
  } catch (e) {
    // The parser recurses, so a file nested deeply enough runs it out of stack.
    if (e instanceof RangeError) hooks.report(D.Depth, 1, {});
    else hooks.report(D.Malformed, 1, { reason: e instanceof Error ? e.message : String(e) });
    return;
  }
  const list = Array.isArray(docs) ? docs : [];
  for (const doc of list) {
    const error = doc.errors[0];
    if (!error) continue;
    // The composer catches running out of stack itself, and reports it as an error of the document.
    if (/Maximum call stack size exceeded/.test(error.message)) hooks.report(D.Depth, lineOf(error.pos[0]), {});
    else hooks.report(D.Malformed, lineOf(error.pos[0]), { reason: error.message.split('\n')[0] });
    return;
  }
  const cst = [...new Parser().parse(text)].filter(t => t.type === 'document');
  list.forEach((doc, k) => {
    if (depthOf(doc.contents) > limits.depth) {
      hooks.report(D.Depth, 1, {});
      return;
    }
    // Keys a mapping repeats, and __proto__ keys.
    const maps: unknown[] = [];
    const stack: unknown[] = [doc.contents];
    while (stack.length) {
      const n = stack.pop();
      if (isMap(n)) maps.push(n);
      for (const c of children(n)) if (c !== null && c !== undefined) stack.push(c);
    }
    for (const m of maps) {
      if (!isMap(m)) continue;
      const seen = new Set<string>();
      m.items.forEach((pair, i) => {
        if (!isScalar(pair.key)) return;
        const key = String(pair.key.value);
        const at = pair.key.range?.[0] ?? 0;
        // A repeated << is a common way to merge two mappings, and loaders that merge accept it.
        if (seen.has(key) && key !== '<<') hooks.report(D.DuplicateKey, lineOf(at), { key });
        seen.add(key);
        if (key !== '__proto__') return;
        if (hooks.report(D.PrototypeKey, lineOf(at), { key }) !== 'strip') return;
        const span = pairSpan(text, m.items, i, m.flow === true);
        if (span) hooks.edit(span[0], span[1] - span[0], '');
      });
    }
    // Tags outside the schemas, resolved through the document's own %TAG directives.
    const tokens: Array<{ offset: number; source: string }> = [];
    tagTokens(cst[k], tokens);
    for (const t of tokens) {
      const name = doc.directives?.tagName(t.source, () => undefined) ?? (t.source.startsWith('!!') ? YAML_TAG + t.source.slice(2) : t.source);
      if (name === '!' || SCHEMA_TAGS.has(name)) continue;
      if (hooks.report(D.Tag, lineOf(t.offset), { tag: name }) !== 'strip') continue;
      let length = t.source.length;
      while (text[t.offset + length] === ' ' || text[t.offset + length] === '\t') length++;
      hooks.edit(t.offset, length, '');
    }
    // Aliases that blow the document up. Aliases chained deeper than the stack goes count as that too.
    let counted: { written: number; expanded: number };
    try {
      counted = sizes(doc.contents, a => (isAlias(a) ? a.resolve(doc) : undefined));
    } catch (e) {
      if (!(e instanceof RangeError)) throw e;
      counted = { written: 1, expanded: Number.POSITIVE_INFINITY };
    }
    const { written, expanded } = counted;
    if (expanded > EXPANSION_FLOOR && expanded > written * limits.aliasExpansion)
      hooks.report(D.AliasExpansion, 1, { written, expanded: Number.isFinite(expanded) ? expanded : 'more than can be counted' });
  });
}
