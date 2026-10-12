import { FileCategory as C, FileDetail as D, type FileFindingAction } from './types';

/** What the JSON rules report and change. Without hooks the scanner only checks the grammar, as detection does. */
export interface JsonHooks {
  report(category: C, detail: D, line: number, data: Record<string, string | number>): FileFindingAction;
  edit(at: number, length: number, insert: string): void;
}

/** libmagic's is_json stops at this depth, and so does detection. */
export const JSON_DEPTH = 500;

const OBJECT = 0;
const ARRAY = 1;

// What comes next outside a token.
const VALUE = 0;
const AFTER_TOP = 1;
const KEY_OR_CLOSE = 2;
const KEY = 3;
const COLON = 4;
const COMMA_OR_CLOSE = 5;
const VALUE_OR_CLOSE = 6;

// Tokens.
const NONE = 0;
const STRING = 1;
const NUMBER = 2;
const LITERAL = 3;

// Number states. ZERO, INT, FRAC and EXP may end the number.
const N_SIGN = 0;
const N_ZERO = 1;
const N_INT = 2;
const N_DOT = 3;
const N_FRAC = 4;
const N_E = 5;
const N_ESIGN = 6;
const N_EXP = 7;

/** The largest integer JavaScript holds exactly, as digits. */
const SAFE = '9007199254740991';

/** The escapes the rewrite writes for characters that can end a script element or a page. */
const BREAKOUT = new Map<number, string>([
  [0x3c, '\\u003c'],
  [0x3e, '\\u003e'],
  [0x26, '\\u0026'],
  [0x2028, '\\u2028'],
  [0x2029, '\\u2029'],
]);

const ws = (c: number) => c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;
const hexValue = (c: number) => (c >= 0x30 && c <= 0x39 ? c - 0x30 : c >= 0x41 && c <= 0x46 ? c - 0x37 : c >= 0x61 && c <= 0x66 ? c - 0x57 : -1);
const SIMPLE_ESCAPE = new Map<number, string>([
  [0x22, '"'],
  [0x5c, '\\'],
  [0x2f, '/'],
  [0x62, '\b'],
  [0x66, '\f'],
  [0x6e, '\n'],
  [0x72, '\r'],
  [0x74, '\t'],
]);

/** A JSON string written so that every reader takes it as `value`, and no character in it can end a script element. */
export function jsonString(value: string): string {
  return JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, ch => BREAKOUT.get(ch.charCodeAt(0)) ?? ch);
}

interface Container {
  kind: number;
  start: number;
  /** Object: the members so far, by where each key starts and where its value ends. */
  keyStarts: number[];
  valueEnds: number[];
  keys: Map<string, number>;
  remove?: Set<number>;
  key: string;
  /** Array: the index of the next element. */
  index: number;
}

/** Marks a member of an object for removal when the object closes. */
function removeLater(c: Container, index: number): void {
  if (!c.remove) c.remove = new Set();
  c.remove.add(index);
}

interface StringToken {
  start: number;
  /** A key, or a value the source map rules read. Only these are decoded. */
  decode: boolean;
  value: string;
  escape: boolean;
  unicode: number;
  unicodeValue: number;
  escapeAt: number;
  breakout?: FileFindingAction;
  /** A high surrogate escape that waits for its low half. */
  high?: { at: number; end: number };
  surrogate?: FileFindingAction;
}

/** What the top-level object of a source map holds, for the source map rules. */
interface SourceMapParts {
  version?: string;
  mappings: boolean;
  urls: Array<{ start: number; end: number; value: string; line: number }>;
  /** The line of the first source given in full, or 0 when there is none. */
  content: number;
}

/**
 * A strict JSON reader over code points, for RFC 8259 text and, with `ndjson`, one value per line. It needs no
 * recursion, since its containers sit on an array, and it keeps only the keys of the objects still open.
 */
export class JsonScanner {
  private readonly stack: Container[] = [];
  private expect = VALUE;
  private token = NONE;
  private str?: StringToken;
  private numState = N_SIGN;
  private numText = '';
  private literal = '';
  private literalIndex = 0;
  private line = 1;
  private newline = false;
  private openObjects = 0;
  private objectStart = Number.POSITIVE_INFINITY;
  private sm?: SourceMapParts;
  /** Set once the grammar fails or the depth limit passes. Nothing more is read. */
  failed?: string;
  /** Whether an object or an array was seen, which detection requires, as libmagic does. */
  container = false;
  /** Top-level values read to their end. */
  values = 0;

  constructor(
    private readonly depthLimit: number,
    private readonly ndjson: boolean,
    private readonly hooks?: JsonHooks,
  ) {}

  /** The lowest offset an edit may still come for: the outermost open object, whose members may yet be removed. */
  get holding(): number {
    const high = this.str?.high?.at ?? Number.POSITIVE_INFINITY;
    return Math.min(this.objectStart, high);
  }

  /** True when the input so far is whole JSON: every value closed, at least one of them. */
  get complete(): boolean {
    return !this.failed && this.token === NONE && this.stack.length === 0 && this.values > 0;
  }

  private fail(reason: string, detail: D = D.Malformed): void {
    if (this.failed) return;
    this.failed = reason;
    this.hooks?.report(C.Json, detail, this.line, detail === D.Malformed ? { reason } : {});
  }

  /** The JSON pointer of the value being read. */
  private pointer(): string {
    return this.stack.map(c => `/${c.kind === OBJECT ? c.key.replace(/~/g, '~0').replace(/\//g, '~1') : String(c.index)}`).join('');
  }

  push(cp: number, at: number, length: number): void {
    if (this.failed) return;
    for (;;) {
      if (this.token === STRING) {
        this.stringChar(cp, at, length);
        break;
      }
      if (this.token === NUMBER) {
        if (this.numberChar(cp)) break;
        this.endNumber(at);
        if (this.failed) return;
        continue;
      }
      if (this.token === LITERAL) {
        if (cp !== this.literal.charCodeAt(this.literalIndex)) {
          this.fail(`unexpected text where ${this.literal} was`);
          return;
        }
        if (++this.literalIndex === this.literal.length) {
          this.token = NONE;
          this.valueDone(at + length);
        }
        break;
      }
      this.structural(cp, at, length);
      break;
    }
    if (cp === 0x0a) {
      this.line++;
      this.newline = true;
    }
  }

  end(at: number): void {
    if (this.failed) return;
    if (this.token === NUMBER) {
      if (this.numState === N_ZERO || this.numState === N_INT || this.numState === N_FRAC || this.numState === N_EXP) this.endNumber(at);
      else this.fail('the file ends inside a number');
    } else if (this.token === STRING) this.fail('the file ends inside a string');
    else if (this.token === LITERAL) this.fail(`the file ends inside ${this.literal}`);
    if (this.failed) return;
    if (this.stack.length) this.fail(`the file ends inside ${this.stack[this.stack.length - 1].kind === OBJECT ? 'an object' : 'an array'}`);
    else if (this.values === 0) this.fail('the file holds no value');
  }

  private structural(cp: number, at: number, length: number): void {
    if (ws(cp)) return;
    const top = this.stack[this.stack.length - 1];
    switch (this.expect) {
      case AFTER_TOP:
        if (!(this.ndjson && this.newline)) {
          this.fail(this.ndjson ? 'two values on one line' : 'more than one value at the top level');
          return;
        }
        this.expect = VALUE;
        this.value(cp, at, length);
        return;
      case VALUE:
        this.value(cp, at, length);
        return;
      case VALUE_OR_CLOSE:
        if (cp === 0x5d) this.close(ARRAY, at, length);
        else this.value(cp, at, length);
        return;
      case KEY_OR_CLOSE:
      case KEY:
        if (cp === 0x7d && this.expect === KEY_OR_CLOSE) this.close(OBJECT, at, length);
        else if (cp === 0x22) this.startString(at, true);
        else this.fail(this.expect === KEY ? 'a comma before no key' : 'an object key that is not a string');
        return;
      case COLON:
        if (cp === 0x3a) this.expect = VALUE;
        else this.fail('a key without a colon after it');
        return;
      case COMMA_OR_CLOSE:
        if (cp === 0x2c) {
          if (top.kind === OBJECT) this.expect = KEY;
          else {
            top.index++;
            this.expect = VALUE;
          }
        } else if (cp === 0x7d && top.kind === OBJECT) this.close(OBJECT, at, length);
        else if (cp === 0x5d && top.kind === ARRAY) this.close(ARRAY, at, length);
        else this.fail(top.kind === OBJECT ? 'a missing comma or closing brace' : 'a missing comma or closing bracket');
        return;
      default:
        throw new Error(`JSON scanner in unknown state ${this.expect}`);
    }
  }

  private value(cp: number, at: number, _length: number): void {
    if (cp === 0x7b || cp === 0x5b) {
      if (this.stack.length + 1 > this.depthLimit) {
        this.fail('nesting past the depth limit', D.Depth);
        return;
      }
      this.container = true;
      const c: Container = { kind: cp === 0x7b ? OBJECT : ARRAY, start: at, keyStarts: [], valueEnds: [], keys: new Map(), key: '', index: 0 };
      if (c.kind === OBJECT) {
        if (this.openObjects++ === 0) this.objectStart = at;
        if (this.stack.length === 0 && this.hooks) this.sm = { mappings: false, urls: [], content: 0 };
      }
      this.stack.push(c);
      this.expect = c.kind === OBJECT ? KEY_OR_CLOSE : VALUE_OR_CLOSE;
      return;
    }
    if (cp === 0x22) {
      this.startString(at, false);
      return;
    }
    if (cp === 0x2d || (cp >= 0x30 && cp <= 0x39)) {
      this.token = NUMBER;
      this.numText = '';
      this.numState = N_SIGN;
      if (!this.numberChar(cp)) this.fail('a malformed number');
      return;
    }
    const word = cp === 0x74 ? 'true' : cp === 0x66 ? 'false' : cp === 0x6e ? 'null' : '';
    if (!word) {
      this.fail(cp === 0x7d || cp === 0x5d ? 'a closing bracket where a value was' : 'text that is not a JSON value');
      return;
    }
    this.token = LITERAL;
    this.literal = word;
    this.literalIndex = 1;
  }

  /** Where a source map string goes, when the string is one the source map rules read. */
  private sourceMapRole(): 'url' | 'content' | undefined {
    if (!this.sm) return undefined;
    const d = this.stack.length;
    const top = this.stack[0];
    if (d === 1 && top.kind === OBJECT && (top.key === 'sourceRoot' || top.key === 'file')) return 'url';
    if (d === 2 && top.kind === OBJECT && this.stack[1].kind === ARRAY) {
      if (top.key === 'sources') return 'url';
      if (top.key === 'sourcesContent') return 'content';
    }
    return undefined;
  }

  private startString(at: number, key: boolean): void {
    this.token = STRING;
    const role = key ? undefined : this.sourceMapRole();
    if (role === 'content' && this.sm && !this.sm.content) this.sm.content = this.line;
    this.str = { start: at, decode: key || role === 'url', value: '', escape: false, unicode: -1, unicodeValue: 0, escapeAt: 0 };
    if (key) this.expect = COLON;
  }

  /** Reports a surrogate escape with no partner, and with `strip` replaces its six characters with \ufffd. */
  private loneEscape(s: StringToken, at: number, end: number): void {
    if (!this.hooks) return;
    s.surrogate ??= this.hooks.report(C.Json, D.LoneSurrogate, this.line, { path: this.pointer() });
    if (s.surrogate === 'strip') this.hooks.edit(at, end - at, '\\ufffd');
  }

  private stringChar(cp: number, at: number, length: number): void {
    const s = this.str;
    if (!s) throw new Error('JSON scanner lost its string');
    if (s.unicode >= 0) {
      const h = hexValue(cp);
      if (h < 0) {
        this.fail('a \\u escape without four hex digits');
        return;
      }
      s.unicodeValue = (s.unicodeValue << 4) | h;
      if (++s.unicode < 4) return;
      s.unicode = -1;
      const v = s.unicodeValue;
      const end = at + length;
      if (v >= 0xd800 && v <= 0xdbff) {
        if (s.high) this.loneEscape(s, s.high.at, s.high.end);
        s.high = { at: s.escapeAt, end };
      } else if (v >= 0xdc00 && v <= 0xdfff) {
        if (s.high && s.high.end === s.escapeAt) s.high = undefined;
        else {
          if (s.high) this.loneEscape(s, s.high.at, s.high.end);
          s.high = undefined;
          this.loneEscape(s, s.escapeAt, end);
        }
      } else if (s.high) {
        this.loneEscape(s, s.high.at, s.high.end);
        s.high = undefined;
      }
      if (s.decode) s.value += String.fromCharCode(v);
      return;
    }
    if (s.escape) {
      s.escape = false;
      if (cp === 0x75) {
        s.unicode = 0;
        s.unicodeValue = 0;
        return;
      }
      const ch = SIMPLE_ESCAPE.get(cp);
      if (ch === undefined) {
        this.fail('an escape JSON does not have');
        return;
      }
      this.settleHigh(s);
      if (s.decode) s.value += ch;
      return;
    }
    if (cp === 0x5c) {
      s.escape = true;
      s.escapeAt = at;
      return;
    }
    this.settleHigh(s);
    if (cp === 0x22) {
      this.token = NONE;
      this.str = undefined;
      this.stringDone(s, at + length);
      return;
    }
    if (cp < 0x20) {
      this.fail('a control character in a string');
      return;
    }
    const esc = BREAKOUT.get(cp);
    if (esc && this.hooks) {
      s.breakout ??= this.hooks.report(C.Json, D.HtmlBreakout, this.line, { path: this.pointer() });
      if (s.breakout === 'strip') this.hooks.edit(at, length, esc);
    }
    if (s.decode) s.value += String.fromCodePoint(cp);
  }

  /** A high surrogate escape followed by anything but a low one stands alone. */
  private settleHigh(s: StringToken): void {
    if (!s.high) return;
    this.loneEscape(s, s.high.at, s.high.end);
    s.high = undefined;
  }

  private stringDone(s: StringToken, end: number): void {
    const top = this.stack[this.stack.length - 1];
    if (this.expect === COLON && top?.kind === OBJECT) {
      this.keyDone(top, s.value, s.start);
      return;
    }
    if (s.decode && this.sm) this.sm.urls.push({ start: s.start, end, value: s.value, line: this.line });
    this.valueDone(end);
  }

  private keyDone(c: Container, key: string, start: number): void {
    const index = c.keyStarts.length;
    c.keyStarts.push(start);
    c.valueEnds.push(start);
    c.key = key;
    if (this.stack.length === 1 && this.sm && key === 'mappings') this.sm.mappings = true;
    if (!this.hooks) return;
    const earlier = c.keys.get(key);
    c.keys.set(key, index);
    if (earlier !== undefined) {
      if (this.hooks.report(C.Json, D.DuplicateKey, this.line, { key, path: this.pointer() }) === 'strip') removeLater(c, earlier);
    }
    const parent = this.stack[this.stack.length - 2];
    const proto = key === '__proto__' ? '__proto__' : key === 'prototype' && parent?.kind === OBJECT && parent.key === 'constructor' ? 'constructor.prototype' : '';
    if (proto && this.hooks.report(C.Json, D.PrototypeKey, this.line, { key: proto, path: this.pointer() }) === 'strip') removeLater(c, index);
  }

  private valueDone(end: number): void {
    const top = this.stack[this.stack.length - 1];
    if (!top) {
      this.expect = AFTER_TOP;
      this.values++;
      this.newline = false;
      return;
    }
    if (top.kind === OBJECT) top.valueEnds[top.valueEnds.length - 1] = end;
    this.expect = COMMA_OR_CLOSE;
  }

  private close(kind: number, at: number, length: number): void {
    const c = this.stack.pop();
    if (!c || c.kind !== kind) throw new Error('JSON scanner closed the wrong container');
    if (kind === OBJECT) {
      if (c.remove) this.removeMembers(c);
      if (--this.openObjects === 0) this.objectStart = Number.POSITIVE_INFINITY;
      if (this.stack.length === 0 && this.sm) {
        this.sourceMap(this.sm);
        this.sm = undefined;
      }
    }
    this.valueDone(at + length);
  }

  /** Removes members in runs, so each removal takes its own comma and no two overlap. */
  private removeMembers(c: Container): void {
    const remove = c.remove;
    if (!remove || !this.hooks) return;
    const n = c.keyStarts.length;
    for (let i = 0; i < n; i++) {
      if (!remove.has(i)) continue;
      let j = i;
      while (j + 1 < n && remove.has(j + 1)) j++;
      if (j + 1 < n) this.hooks.edit(c.keyStarts[i], c.keyStarts[j + 1] - c.keyStarts[i], '');
      else if (i > 0) this.hooks.edit(c.valueEnds[i - 1], c.valueEnds[j] - c.valueEnds[i - 1], '');
      else this.hooks.edit(c.keyStarts[i], c.valueEnds[j] - c.keyStarts[i], '');
      i = j;
    }
  }

  /** At the end of a top-level object: a source map's script URLs and source code. */
  private sourceMap(sm: SourceMapParts): void {
    if (!this.hooks || sm.version !== '3' || !sm.mappings) return;
    for (const u of sm.urls) {
      const scheme = urlScheme(u.value);
      if (scheme !== 'javascript' && scheme !== 'vbscript' && scheme !== 'data') continue;
      if (this.hooks.report(C.SourceMap, D.ScriptUrl, u.line, { scheme }) !== 'strip') continue;
      const rest = u.value.slice(u.value.indexOf(':') + 1);
      this.hooks.edit(u.start, u.end - u.start, jsonString(`#${rest}`));
    }
    if (sm.content) this.hooks.report(C.SourceMap, D.SourcesContent, sm.content, {});
  }

  private numberChar(cp: number): boolean {
    const digit = cp >= 0x30 && cp <= 0x39;
    let next = -1;
    switch (this.numState) {
      case N_SIGN:
        next = cp === 0x2d && this.numText === '' ? N_SIGN : cp === 0x30 ? N_ZERO : digit ? N_INT : -1;
        break;
      case N_ZERO:
        next = cp === 0x2e ? N_DOT : cp === 0x65 || cp === 0x45 ? N_E : -1;
        break;
      case N_INT:
        next = digit ? N_INT : cp === 0x2e ? N_DOT : cp === 0x65 || cp === 0x45 ? N_E : -1;
        break;
      case N_DOT:
      case N_FRAC:
        next = digit ? N_FRAC : this.numState === N_FRAC && (cp === 0x65 || cp === 0x45) ? N_E : -1;
        break;
      case N_E:
        next = cp === 0x2b || cp === 0x2d ? N_ESIGN : digit ? N_EXP : -1;
        break;
      case N_ESIGN:
      case N_EXP:
        next = digit ? N_EXP : -1;
        break;
      default:
        next = -1;
    }
    if (next < 0) return false;
    this.numState = next;
    if (this.numText.length < 64) this.numText += String.fromCharCode(cp);
    return true;
  }

  private endNumber(end: number): void {
    const s = this.numState;
    if (s !== N_ZERO && s !== N_INT && s !== N_FRAC && s !== N_EXP) {
      this.fail('a malformed number');
      return;
    }
    this.token = NONE;
    const text = this.numText;
    if (this.sm && this.stack.length === 1 && this.stack[0].kind === OBJECT && this.stack[0].key === 'version') this.sm.version = text;
    if (this.hooks && s === N_INT) {
      const digits = text.replace(/^-/, '');
      if (digits.length > SAFE.length || (digits.length === SAFE.length && digits > SAFE)) {
        this.hooks.report(C.Json, D.BigNumber, this.line, { value: text.length < 64 ? text : `${text}...`, path: this.pointer() });
      }
    }
    this.valueDone(end);
  }
}

/** The scheme of a URL as a browser's URL parser reads it: after leading controls and spaces, without tabs and line breaks. */
export function urlScheme(url: string): string | undefined {
  let i = 0;
  while (i < url.length && url.charCodeAt(i) <= 0x20) i++;
  let scheme = '';
  for (; i < url.length; i++) {
    const c = url[i];
    if (c === '\t' || c === '\n' || c === '\r') continue;
    if (c === ':') return scheme ? scheme.toLowerCase() : undefined;
    if (!(scheme === '' ? /[A-Za-z]/ : /[A-Za-z0-9+.-]/).test(c)) return undefined;
    scheme += c;
  }
  return undefined;
}

/**
 * Whether text is JSON, the way libmagic's is_json decides it: it parses as JSON to a depth of 500, and holds an
 * object or an array. A head cut short counts when what it holds parses so far. Two or more values, each on its own
 * line, make newline-delimited JSON.
 */
export function jsonKind(text: string, complete: boolean): 'json' | 'ndjson' | undefined {
  const scan = new JsonScanner(JSON_DEPTH, true);
  for (const ch of text) {
    scan.push(ch.codePointAt(0) ?? 0, 0, 0);
    if (scan.failed) return undefined;
  }
  if (complete) scan.end(0);
  if (scan.failed || !scan.container) return undefined;
  return scan.values > 1 ? 'ndjson' : 'json';
}
