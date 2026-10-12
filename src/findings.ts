import { FileCategory as C, FileDetail as D, type FileActionOverride, type FileFinding, type FileFindingAction } from './types';

interface Spec {
  action: FileFindingAction;
  /** May contain <a|b> choices, which take the first alternative whose {key} values are all set and not empty. */
  description: string;
  weight: number;
}

const specs = new Map<string, Spec>();
function def(c: C, d: D, action: FileFindingAction, weight: number, description: string): void {
  specs.set(`${c}/${d}`, { action, weight, description });
}

// TYPE
def(C.Type, D.NoPackage, 'reject', 0, 'No package of the defuse family reads this file (<{sniffed}|unknown type>)');
def(C.Type, D.Polyglot, 'strip', 50, 'The file is also <{type}|another format>, so it opens as that format too');
// LIMIT
def(C.Limit, D.FileSize, 'reject', 0, 'The upload exceeds the file size limit');
def(C.Limit, D.NestingDepth, 'reject', 0, 'A file in the upload sits deeper than the nesting depth limit allows');
def(C.Limit, D.FileCount, 'reject', 0, 'The upload holds more files than the file count limit allows');
def(C.Limit, D.DecodedSize, 'reject', 0, 'The files inside the upload decode to more bytes than the decoded size limit allows');
def(C.Limit, D.Time, 'reject', 0, 'The upload exceeds the time limit');
// TEXT
def(C.Text, D.Encoding, 'strip', 10, 'The text holds bytes that are not valid <{encoding}|in its encoding>');
def(C.Text, D.UnnamedEncoding, 'info', 0, 'The text is not UTF-8 and names no encoding, so it was read as 8-bit text');
def(C.Text, D.ControlCharacter, 'strip', 10, 'The text holds a control character<, {codePoint}|>');
def(C.Text, D.BidiControl, 'strip', 30, 'The text holds a bidirectional control character<, {codePoint}|>, which can make it show in another order than it reads');
def(C.Text, D.Formula, 'strip', 50, 'A cell starts with <{first}|a character> that a spreadsheet takes as the start of a formula');
def(C.Text, D.UnclosedQuote, 'reject', 0, 'A quoted cell never closes, so the rest of the file reads as one cell');
def(C.Text, D.TerminalEscape, 'strip', 30, 'The text holds a terminal escape sequence<, {sequence}|>, which a terminal runs instead of showing');
def(C.Text, D.Markup, 'strip', 50, 'The text holds <a {tag} tag|a tag> that runs script when a browser shows the file as HTML');
def(C.Text, D.ScriptUrl, 'info', 0, 'The text holds a <{scheme}:|javascript: or vbscript:> URL, which does nothing until markup or a link uses it');
def(C.Text, D.JavaScript, 'info', 30, 'The file is JavaScript, which runs wherever it is loaded as a script');
// LINK
def(C.Link, D.ScriptUrl, 'strip', 50, 'A link uses a <{scheme}:|javascript: or vbscript:> URL');
def(C.Link, D.DataUrl, 'strip', 60, 'A link carries embedded data');
// JSON
def(C.Json, D.Malformed, 'reject', 0, 'The file is not valid JSON<: {reason}|>');
def(C.Json, D.DuplicateKey, 'strip', 40, 'An object names <the key {key}|a key> more than once, and JSON readers disagree on which value wins');
def(C.Json, D.PrototypeKey, 'strip', 60, 'An object has <a {key}|a __proto__> member, which code that merges objects turns into a change to every object');
def(C.Json, D.HtmlBreakout, 'strip', 20, 'A string holds an angle bracket, an ampersand or a line or paragraph separator, which can end a script or page the JSON is placed in');
def(C.Json, D.LoneSurrogate, 'strip', 20, 'A string escapes half of a surrogate pair, which readers decode differently');
def(C.Json, D.BigNumber, 'info', 0, 'An integer is too large for JavaScript to hold exactly<: {value}|>');
def(C.Json, D.Depth, 'reject', 0, 'The JSON nests deeper than the depth limit allows');
// SOURCEMAP
def(C.SourceMap, D.ScriptUrl, 'strip', 50, "The source map names a <{scheme}:|javascript: or data:> URL, which a browser's developer tools load");
def(C.SourceMap, D.SourcesContent, 'info', 0, 'The source map carries the source code of the files it maps');
// YAML
def(C.Yaml, D.Malformed, 'reject', 0, 'The file is not valid YAML<: {reason}|>');
def(C.Yaml, D.Tag, 'strip', 70, 'A value has <the tag {tag}|a tag> outside the YAML schemas, which some loaders turn into an object or code');
def(C.Yaml, D.AliasExpansion, 'reject', 0, 'Aliases expand the YAML to many times its size, which exhausts a reader that follows them');
def(C.Yaml, D.DuplicateKey, 'reject', 0, 'A mapping names <the key {key}|a key> more than once, which YAML does not allow');
def(C.Yaml, D.PrototypeKey, 'strip', 60, 'A mapping has <a {key}|a __proto__> key, which code that merges objects turns into a change to every object');
def(C.Yaml, D.Depth, 'reject', 0, 'The YAML nests deeper than the depth limit allows');
// PROCESSING
def(C.Processing, D.VerificationFailed, 'reject', 0, 'The defused output did not pass its own check, so nothing was written<: {reasons}|>');

function ownSpec(category: C, detail: D): Spec {
  const s = specs.get(`${category}/${detail}`);
  if (!s) throw new Error(`No finding spec for ${category}/${detail}`);
  return s;
}

/** Every kind of finding file-defuse makes itself, with its default action and weight. */
export function allFindingSpecs(): Array<{ category: C; detail: D } & Spec> {
  return [...specs.entries()].map(([k, s]) => {
    const [category, detail] = k.split('/') as [C, D];
    return { category, detail, ...s };
  });
}

export class FindingFactory {
  constructor(private readonly overrides: FileActionOverride[] = []) {}

  actionFor(category: C, detail: D): FileFindingAction {
    const exact = this.overrides.find(o => o.category === category && o.detail === detail);
    if (exact) return exact.action;
    const byCategory = this.overrides.find(o => o.category === category && o.detail === undefined);
    if (byCategory) return byCategory.action;
    return ownSpec(category, detail).action;
  }

  /** A finding of the kind, with its description filled from `data`, or `description` when given. */
  make(category: C, detail: D, data?: Record<string, string | number>, description?: string): FileFinding {
    const spec = ownSpec(category, detail);
    const filled = spec.description.replace(/<([^<>]+)>/g, (m, body: string) => {
      for (const alt of body.split('|')) {
        let missing = false;
        const text = alt.replace(/\{([a-zA-Z]+)\}/g, (_, key: string) => {
          const v = data?.[key];
          if (v === undefined || v === '') missing = true;
          return String(v ?? '');
        });
        if (!missing) return text;
      }
      return m;
    });
    const f: FileFinding = { category, detail, description: description ?? filled, action: this.actionFor(category, detail), weight: spec.weight };
    if (data !== undefined && Object.keys(data).length) f.data = data;
    return f;
  }
}
