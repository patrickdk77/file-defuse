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
// LINK
def(C.Link, D.ScriptUrl, 'strip', 50, 'A link uses a <{scheme}:|javascript: or vbscript:> URL');
def(C.Link, D.DataUrl, 'strip', 60, 'A link carries embedded data');
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
