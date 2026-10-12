import type { TextSubtype } from './detect';
import { bomOf, type TextEncoding } from './detect-text';
import { FindingFactory } from './findings';
import { DEFAULT_MEMORY_THRESHOLD, Spill } from './spill';
import { type ByteSink, type ByteSource, FileCategory as C, type ContainedFilePlugin, FileDetail as D, type DefuseFinding, type FileActionOverride, type FileFinding, FileRisk } from './types';

/** Options for text files, the `text` section. */
export interface TextOptions {
  /** Changes the action of the text rules' findings: TEXT, LINK and PROCESSING. */
  actionOverrides?: FileActionOverride[];
  scoreWeights?: Array<{ category: string; detail?: string; weight: number }>;
  scoreBands?: { low: number; medium: number; high: number; critical: number };
  limits?: {
    /** Milliseconds for one text file, its rewrite and the check of the rewrite. Not enforced unless set. */
    timeMs?: number;
  };
  /** Directory for the rewrite's temporary file. */
  tempDir?: string;
  /** Bytes of the rewrite kept in memory before it goes to a temporary file. Default 8 MiB. */
  memoryThreshold?: number;
}

const CHUNK = 65536;
/** Past this many findings of one kind, one more counts the rest, as the other packages do. */
const MAX_PER_KIND = 200;
const DEFAULT_BANDS = { low: 1, medium: 25, high: 50, critical: 80 };
/** A line of Markdown longer than this is read in pieces, keeping this much of each piece for the next. */
const MAX_LINE = 1 << 20;
const LINE_CARRY = 4096;

const BIDI = new Set([0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069]);
const allowed = (c: number) => c === 0x09 || c === 0x0a || c === 0x0c || c === 0x0d;
const control = (c: number) => (c < 0x20 || (c >= 0x7f && c <= 0x9f)) && !allowed(c);
const hex = (c: number) => `U+${c.toString(16).toUpperCase().padStart(4, '0')}`;

/** An error that stops the whole tree for time, which every package of the family passes up. */
const lateError = () => Object.assign(new Error('Time limit exceeded'), { code: 'DEFUSE_LIMIT', limit: 'time' });

/** A change to the input's bytes: `length` bytes at `at` give way to `insert`. */
interface Edit {
  at: number;
  length: number;
  insert: string;
}

/** The bytes of a short string in the file's own encoding. */
function encode(s: string, encoding: TextEncoding): Buffer {
  switch (encoding) {
    case 'utf-16le':
      return Buffer.from(s, 'utf16le');
    case 'utf-16be':
      return Buffer.from(s, 'utf16le').swap16();
    case 'utf-32le':
    case 'utf-32be': {
      const cps = [...s].map(c => c.codePointAt(0) ?? 0);
      const b = Buffer.alloc(cps.length * 4);
      cps.forEach((cp, i) => {
        if (encoding === 'utf-32le') b.writeUInt32LE(cp, i * 4);
        else b.writeUInt32BE(cp, i * 4);
      });
      return b;
    }
    case '8-bit':
      return Buffer.from(s, 'latin1');
    default:
      return Buffer.from(s, 'utf8');
  }
}

/** What the decoder makes of a sequence: a character, bytes that do not decode, or an 8-bit byte that is not UTF-8. */
const OK = 0;
const ERROR = 1;
const ESCAPE = 2;
type Emit = (cp: number, offset: number, length: number, kind: number) => void;

/**
 * Decodes in pieces. UTF-8 follows the WHATWG decoder, and a sequence that does not decode is one error. Without a
 * byte order mark such a byte is an 8-bit byte instead, passed on as U+DC80 plus its value so no rule takes it for a
 * character. UTF-16 and UTF-32 need a byte order mark, and a unit that is no character is an error.
 */
class Decoder {
  private needed = 0;
  private seen = 0;
  private cp = 0;
  private lower = 0x80;
  private upper = 0xbf;
  private start = 0;
  private pending: number[] = [];
  private pendingAt = 0;
  private high = -1;
  private highAt = 0;

  constructor(
    private readonly encoding: TextEncoding,
    private readonly bom: boolean,
    private readonly emit: Emit,
  ) {}

  /** The offset of the first byte the decoder holds without having passed it on, which an edit may yet name. */
  get holding(): number {
    if (this.needed) return this.start;
    if (this.high >= 0) return this.highAt;
    if (this.pending.length) return this.pendingAt;
    return Number.POSITIVE_INFINITY;
  }

  push(b: Uint8Array, at: number): void {
    if (this.encoding === 'utf-8' || this.encoding === '8-bit') {
      for (let i = 0; i < b.length; i++) this.utf8(b[i], at + i);
      return;
    }
    const unit = this.encoding === 'utf-16le' || this.encoding === 'utf-16be' ? 2 : 4;
    for (let i = 0; i < b.length; i++) {
      if (!this.pending.length) this.pendingAt = at + i;
      this.pending.push(b[i]);
      if (this.pending.length === unit) {
        const p = this.pending;
        this.pending = [];
        if (unit === 2) this.utf16(this.encoding === 'utf-16le' ? p[0] | (p[1] << 8) : (p[0] << 8) | p[1], this.pendingAt);
        else {
          const v = (this.encoding === 'utf-32le' ? p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24) : (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
          if (v > 0x10ffff || (v >= 0xd800 && v <= 0xdfff)) this.emit(0xfffd, this.pendingAt, 4, ERROR);
          else this.emit(v, this.pendingAt, 4, OK);
        }
      }
    }
  }

  end(): void {
    if (this.encoding === 'utf-8' || this.encoding === '8-bit') {
      if (this.needed) this.bad(this.start, this.seen + 1);
      return;
    }
    if (this.high >= 0) this.emit(0xfffd, this.highAt, 2, ERROR);
    this.high = -1;
    if (this.pending.length) this.emit(0xfffd, this.pendingAt, this.pending.length, ERROR);
    this.pending = [];
  }

  /** Bytes that do not decode: one error with a byte order mark, or each byte passed on as an 8-bit byte without one. */
  private bad(at: number, length: number): void {
    if (this.bom) this.emit(0xfffd, at, length, ERROR);
    else for (let k = 0; k < length; k++) this.emit(0xdc00, at + k, 1, ESCAPE);
  }

  private utf8(byte: number, at: number): void {
    if (this.needed === 0) {
      this.start = at;
      if (byte <= 0x7f) this.emit(byte, at, 1, OK);
      else if (byte >= 0xc2 && byte <= 0xdf) {
        this.needed = 1;
        this.cp = byte & 0x1f;
      } else if (byte >= 0xe0 && byte <= 0xef) {
        if (byte === 0xe0) this.lower = 0xa0;
        if (byte === 0xed) this.upper = 0x9f;
        this.needed = 2;
        this.cp = byte & 0xf;
      } else if (byte >= 0xf0 && byte <= 0xf4) {
        if (byte === 0xf0) this.lower = 0x90;
        if (byte === 0xf4) this.upper = 0x8f;
        this.needed = 3;
        this.cp = byte & 0x7;
      } else this.bad(at, 1);
      return;
    }
    if (byte < this.lower || byte > this.upper) {
      const [start, seen] = [this.start, this.seen];
      this.reset();
      this.bad(start, seen + 1);
      this.utf8(byte, at);
      return;
    }
    this.lower = 0x80;
    this.upper = 0xbf;
    this.cp = (this.cp << 6) | (byte & 0x3f);
    if (++this.seen === this.needed) {
      const [cp, start] = [this.cp, this.start];
      this.reset();
      this.emit(cp, start, at + 1 - start, OK);
    }
  }

  private reset(): void {
    this.needed = 0;
    this.seen = 0;
    this.cp = 0;
    this.lower = 0x80;
    this.upper = 0xbf;
  }

  private utf16(u: number, at: number): void {
    if (this.high >= 0) {
      const [h, hAt] = [this.high, this.highAt];
      this.high = -1;
      if (u >= 0xdc00 && u <= 0xdfff) {
        this.emit(0x10000 + ((h - 0xd800) << 10) + (u - 0xdc00), hAt, 4, OK);
        return;
      }
      this.emit(0xfffd, hAt, 2, ERROR);
    }
    if (u >= 0xd800 && u <= 0xdbff) {
      this.high = u;
      this.highAt = at;
    } else if (u >= 0xdc00 && u <= 0xdfff) this.emit(0xfffd, at, 2, ERROR);
    else this.emit(u, at, 2, OK);
  }
}

// States of the delimited-text reader, pdf-defuse's own.
const FIELD_START = 0;
const UNQUOTED = 3;
const QUOTED_START = 4;
const QUOTED_START_QUOTE = 5;
const QUOTED = 6;
const QUOTED_QUOTE = 7;
const AFTER_QUOTED = 8;
const SIGNED = 9;
const SIGNED_IN_QUOTES = 10;
const SIGNED_QUOTE = 11;
const QUOTE = 0x22;
const LF = 0x0a;
const CR = 0x0d;
const TAB = 0x09;
/** A cell that starts with a sign is left alone when it is a plain number, as in pdf-defuse. */
const SIGNED_NUMBER = /^[+-](?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/;
const NUMBER_CHAR = /[0-9.eE+-]/;
const SHOW = new Map<number, string>([
  [TAB, 'a tab'],
  [CR, 'a carriage return'],
]);

/**
 * pdf-defuse's reader for CSV and TSV, over characters: a cell that starts with =, +, -, @, tab or carriage return is
 * a formula to a spreadsheet, except a plain number or a lone sign. Quoting follows RFC 4180, and a stray quote is text.
 */
class Delimited {
  private state = FIELD_START;
  private signed: number[] = [];
  /** Where the cell that waits on `signed` starts, for its edit. */
  signedAt = -1;
  private row = 1;
  private cell = 1;
  private lastCR = false;

  constructor(
    private readonly delimiter: number,
    private readonly formula: (at: number, row: number, cell: number, first: number) => void,
  ) {}

  private separator(c: number): void {
    if (c === this.delimiter) this.cell++;
    else if (c === CR || (c === LF && !this.lastCR)) {
      this.row++;
      this.cell = 1;
    }
  }

  private startCell(c: number, at: number, quoted: boolean): number {
    if (c === 0x2b || c === 0x2d) {
      this.signed = [c];
      this.signedAt = at;
      return quoted ? SIGNED_IN_QUOTES : SIGNED;
    }
    if (c === 0x3d || c === 0x40 || c === TAB || c === CR) this.formula(at, this.row, this.cell, c);
    return quoted ? QUOTED : UNQUOTED;
  }

  private release(formula: boolean): void {
    if (formula) this.formula(this.signedAt, this.row, this.cell, this.signed[0]);
    this.signed = [];
    this.signedAt = -1;
  }

  private plainNumber(): boolean {
    return this.signed.length === 1 || SIGNED_NUMBER.test(String.fromCharCode(...this.signed));
  }

  push(c: number, at: number): void {
    for (;;) {
      const quotedSigned = this.state === SIGNED_IN_QUOTES;
      switch (this.state) {
        case FIELD_START:
          if (c === this.delimiter || c === CR || c === LF) this.separator(c);
          else if (c === QUOTE) this.state = QUOTED_START;
          else this.state = this.startCell(c, at, false);
          break;
        case UNQUOTED:
        case AFTER_QUOTED:
          if (c === this.delimiter || c === CR || c === LF) {
            this.separator(c);
            this.state = FIELD_START;
          }
          break;
        case QUOTED_START:
          if (c === QUOTE) this.state = QUOTED_START_QUOTE;
          else this.state = this.startCell(c, at, true);
          break;
        case QUOTED_START_QUOTE:
          if (c === QUOTE) this.state = QUOTED;
          else {
            this.state = AFTER_QUOTED;
            continue;
          }
          break;
        case QUOTED:
          if (c === QUOTE) this.state = QUOTED_QUOTE;
          break;
        case QUOTED_QUOTE:
          if (c === QUOTE) this.state = QUOTED;
          else {
            this.state = AFTER_QUOTED;
            continue;
          }
          break;
        case SIGNED:
        case SIGNED_IN_QUOTES:
          if (quotedSigned ? c === QUOTE : c === this.delimiter || c === CR || c === LF) {
            if (quotedSigned) {
              this.state = SIGNED_QUOTE;
              break;
            }
            this.release(!this.plainNumber());
            this.state = UNQUOTED;
            continue;
          }
          if (c < 0x80 && NUMBER_CHAR.test(String.fromCharCode(c)) && this.signed.length < 64) {
            this.signed.push(c);
            break;
          }
          this.release(true);
          this.state = quotedSigned ? QUOTED : UNQUOTED;
          continue;
        case SIGNED_QUOTE:
          if (c === QUOTE) {
            // An escaped quote inside the cell: not a number.
            this.release(true);
            this.state = QUOTED;
            break;
          }
          this.release(!this.plainNumber());
          this.state = AFTER_QUOTED;
          continue;
        default:
          throw new Error(`Delimited-text reader in unknown state ${this.state}`);
      }
      break;
    }
    this.lastCR = c === CR;
  }

  /** At the end of the file. True when a quoted cell is still open. */
  end(): boolean {
    if (this.state === SIGNED || this.state === SIGNED_QUOTE) this.release(!this.plainNumber());
    return this.state === QUOTED_START || this.state === QUOTED || this.state === SIGNED_IN_QUOTES;
  }

  get rowNumber(): number {
    return this.row;
  }
}

/** The scheme a link destination starts with, as a browser reads it, and the index just past its colon. */
function schemeAt(line: string, from: number): { scheme: string; end: number } | undefined {
  let i = from;
  if (line[i] === '<') i++;
  let scheme = '';
  let started = false;
  while (i < line.length && scheme.length < 64) {
    let ch = line[i];
    let next = i + 1;
    if (ch === '\\' && i + 1 < line.length && /[!-/:-@[-`{-~]/.test(line[i + 1])) {
      ch = line[i + 1];
      next = i + 2;
    } else if (ch === '&') {
      const m = /^&(?:#[xX]([0-9a-fA-F]{1,6})|#([0-9]{1,7})|(colon|Tab|NewLine));/.exec(line.slice(i, i + 12));
      if (m) {
        const cp = m[1] ? Number.parseInt(m[1], 16) : m[2] ? Number.parseInt(m[2], 10) : m[3] === 'colon' ? 0x3a : m[3] === 'Tab' ? 9 : 10;
        ch = cp > 0x10ffff ? '\ufffd' : String.fromCodePoint(cp);
        next = i + m[0].length;
      }
    } else if (ch === ' ' || ch === '>' || ch === ')' || ch === '"' || ch === "'") {
      // The destination, or a bare one at least, ends here. Spaces a reference decodes to do not end it.
      if (!(ch === ' ' && line[from] === '<')) break;
    }
    i = next;
    const code = ch.codePointAt(0) ?? 0;
    // Browsers drop tab and line breaks anywhere in a URL, and controls and spaces before it.
    if (code === 0x09 || code === 0x0a || code === 0x0d) continue;
    if (!started && code <= 0x20) continue;
    started = true;
    if (ch === ':') return scheme ? { scheme: scheme.toLowerCase(), end: i } : undefined;
    if (!/[A-Za-z0-9+.-]/.test(ch) || (scheme === '' && !/[A-Za-z]/.test(ch))) return undefined;
    scheme += ch;
  }
  return undefined;
}

const UNSAFE = new Map<string, D>([
  ['javascript', D.ScriptUrl],
  ['vbscript', D.ScriptUrl],
  ['data', D.DataUrl],
]);

/**
 * Finds Markdown link destinations that use javascript:, vbscript: or data: URLs: inline links and images, reference
 * definitions and autolinks, outside fenced code blocks and code spans. It reads line by line. Raw HTML is not read.
 */
class Markdown {
  private text = '';
  private offs: number[] = [];
  private lineNumber = 1;
  private atLineStart = true;
  private fence?: { char: string; length: number };
  /** A destination may start the next line, after a "](" or a reference label that ends this one. */
  private pendingDest = false;

  constructor(private readonly link: (detail: D, scheme: string, at: number, end: number, line: number) => void) {}

  /** The offset of the first character still held, which an edit may yet name. */
  get holding(): number {
    return this.offs.length ? this.offs[0] : Number.POSITIVE_INFINITY;
  }

  push(cp: number, at: number, length: number): void {
    const s = String.fromCodePoint(cp);
    this.text += s;
    for (const _ of s) this.offs.push(at);
    if (s.length === 2) this.offs.push(at);
    if (cp === LF) {
      this.offs.push(at + length);
      this.line(this.text.length, true);
    } else if (this.text.length > MAX_LINE) {
      this.offs.push(at + length);
      this.line(this.text.length - LINE_CARRY, false);
    }
  }

  end(endOffset: number): void {
    if (!this.text.length) return;
    this.offs.push(endOffset);
    this.line(this.text.length, true);
  }

  /** Reads the held text, reporting links that start before `upTo`, and drops what it has read. */
  private line(upTo: number, whole: boolean): void {
    const text = this.text;
    const offs = this.offs;
    const afterOf = (i: number) => offs[i];
    const report = (start: number, end: number, scheme: string) => {
      const detail = UNSAFE.get(scheme);
      if (detail && start < upTo) this.link(detail, scheme, offs[start], afterOf(end), this.lineNumber);
    };
    const lineStart = this.atLineStart;
    const body = text.replace(/\r?\n$/, '');
    let skip = false;
    if (lineStart) {
      const f = /^ {0,3}(`{3,}|~{3,})(.*)$/.exec(body);
      if (this.fence) {
        if (f && f[1][0] === this.fence.char && f[1].length >= this.fence.length && f[2].trim() === '') this.fence = undefined;
        skip = true;
      } else if (f && !(f[1][0] === '`' && f[2].includes('`'))) {
        this.fence = { char: f[1][0], length: f[1].length };
        skip = true;
      }
    } else if (this.fence) skip = true;
    if (!skip) {
      // Code spans: backtick runs of one length pair up within the line.
      const spans: Array<[number, number]> = [];
      const runs = [...body.matchAll(/`+/g)];
      for (let k = 0; k < runs.length; k++) {
        const open = runs[k];
        const close = runs.slice(k + 1).findIndex(x => x[0].length === open[0].length);
        if (close < 0) continue;
        const shut = runs[k + 1 + close];
        spans.push([open.index ?? 0, (shut.index ?? 0) + shut[0].length]);
        k += 1 + close;
      }
      const inCode = (i: number) => spans.some(([a, b]) => i >= a && i < b);
      const destination = (from: number) => {
        let i = from;
        while (i < body.length && (body[i] === ' ' || body[i] === '\t')) i++;
        if (i >= body.length) {
          this.pendingDest = true;
          return;
        }
        const found = schemeAt(body, i);
        if (found) report(body[i] === '<' ? i + 1 : i, found.end, found.scheme);
      };
      if (this.pendingDest && lineStart) {
        this.pendingDest = false;
        destination(0);
      }
      const ref = lineStart ? /^ {0,3}\[(?:[^\]\\]|\\.){1,999}\]:/.exec(body) : null;
      if (ref) destination(ref[0].length);
      for (let i = body.indexOf(']('); i >= 0; i = body.indexOf('](', i + 2)) if (!inCode(i)) destination(i + 2);
      for (const m of body.matchAll(/<([A-Za-z][A-Za-z0-9+.-]{1,31}):/g)) {
        const i = m.index ?? 0;
        if (!inCode(i)) report(i + 1, i + 1 + m[1].length + 1, m[1].toLowerCase());
      }
    }
    if (whole) {
      this.text = '';
      this.offs = [];
      this.lineNumber++;
      this.atLineStart = true;
    } else {
      this.text = text.slice(upTo);
      this.offs = offs.slice(upTo, offs.length - 1);
      this.atLineStart = false;
    }
  }
}

/** One pass over a text file: its findings, and with `edits` the changes the rewrite makes. */
class Scan {
  readonly findings: FileFinding[] = [];
  private readonly counts = new Map<string, number>();
  readonly edits: Edit[] = [];
  private line = 1;
  private lastCR = false;
  private firstEscape = -1;
  private readonly csv: Delimited[] = [];
  private readonly md?: Markdown;
  private readonly decoder: Decoder;
  private offset = 0;

  constructor(
    private readonly factory: FindingFactory,
    private readonly encoding: TextEncoding,
    bom: boolean,
    subtypes: TextSubtype[],
    private readonly rewrite: boolean,
  ) {
    this.decoder = new Decoder(encoding, bom, (cp, at, length, kind) => this.char(cp, at, length, kind));
    for (const [t, d] of [
      ['csv', 0x2c],
      ['tsv', TAB],
    ] as const) {
      if (!subtypes.includes(t)) continue;
      this.csv.push(
        new Delimited(d, (at, row, cell, first) => {
          const show = SHOW.get(first) ?? String.fromCharCode(first);
          if (this.report(C.Text, D.Formula, `row ${row}, cell ${cell}`, { row, cell, first: show }).action === 'strip') this.edit(at, 0, "'");
        }),
      );
    }
    if (subtypes.includes('md')) {
      this.md = new Markdown((detail, scheme, at, end, line) => {
        if (this.report(C.Link, detail, `line ${line}`, { scheme }).action === 'strip') this.edit(at, end - at, '#');
      });
    }
  }

  private report(category: C, detail: D, location: string, data?: Record<string, string | number>): FileFinding {
    const key = `${category}/${detail}`;
    const n = (this.counts.get(key) ?? 0) + 1;
    this.counts.set(key, n);
    const f = this.factory.make(category, detail, data);
    f.location = location;
    if (n <= MAX_PER_KIND) this.findings.push(f);
    return f;
  }

  private edit(at: number, length: number, insert: string): void {
    if (this.rewrite) this.edits.push({ at, length, insert });
  }

  /** The lowest offset an edit may still come for. */
  get watermark(): number {
    let w = Math.min(this.offset, this.decoder.holding);
    for (const d of this.csv) if (d.signedAt >= 0) w = Math.min(w, d.signedAt);
    if (this.md) w = Math.min(w, this.md.holding);
    return w;
  }

  push(b: Uint8Array, at: number): void {
    this.decoder.push(b, at);
    this.offset = at + b.length;
  }

  private char(cp: number, at: number, length: number, kind: number): void {
    const line = this.line;
    if (cp === LF) {
      if (!this.lastCR) this.line++;
    } else if (cp === CR) this.line++;
    this.lastCR = cp === CR;
    if (kind === ERROR) {
      if (this.report(C.Text, D.Encoding, `offset ${at}`, { offset: at, bytes: length, encoding: this.encoding.toUpperCase() }).action === 'strip') this.edit(at, length, '\ufffd');
    } else if (kind === ESCAPE && this.firstEscape < 0) this.firstEscape = at;
    if (kind !== ESCAPE && control(cp)) {
      if (this.report(C.Text, D.ControlCharacter, `line ${line}`, { codePoint: hex(cp) }).action === 'strip') {
        this.edit(at, length, '');
        return;
      }
    }
    if (BIDI.has(cp)) {
      if (this.report(C.Text, D.BidiControl, `line ${line}`, { codePoint: hex(cp) }).action === 'strip') {
        this.edit(at, length, '');
        return;
      }
    }
    for (const d of this.csv) d.push(cp, at);
    this.md?.push(cp, at, length);
  }

  end(): void {
    this.decoder.end();
    for (const d of this.csv) {
      if (d.end()) this.report(C.Text, D.UnclosedQuote, `row ${d.rowNumber}`);
    }
    this.md?.end(this.offset);
    if (this.firstEscape >= 0) this.report(C.Text, D.UnnamedEncoding, `offset ${this.firstEscape}`, { offset: this.firstEscape });
    for (const [key, n] of this.counts) {
      if (n <= MAX_PER_KIND) continue;
      const [category, detail] = key.split('/') as [C, D];
      const f = this.factory.make(category, detail, { count: n - MAX_PER_KIND });
      f.location = 'additional occurrences';
      this.findings.push(f);
    }
  }
}

/** Applies sorted edits to the input as it copies it to the sink. */
class Writer {
  private pos = 0;
  constructor(
    private readonly source: ByteSource,
    private readonly sink: ByteSink,
    private readonly encoding: TextEncoding,
  ) {}

  private async copy(to: number): Promise<void> {
    while (this.pos < to) {
      const n = Math.min(CHUNK, to - this.pos);
      await this.sink.write(await this.source.read(this.pos, n));
      this.pos += n;
    }
  }

  /** Writes everything before `upTo`, with the edits that start before it. */
  async flush(edits: Edit[], upTo: number): Promise<Edit[]> {
    edits.sort((a, b) => a.at - b.at || a.length - b.length);
    let k = 0;
    for (; k < edits.length && edits[k].at < upTo; k++) {
      const e = edits[k];
      // An edit inside one already made, such as a control character inside a link's scheme, is part of it.
      if (e.at < this.pos) continue;
      await this.copy(e.at);
      if (e.insert) await this.sink.write(encode(e.insert, this.encoding));
      this.pos = e.at + e.length;
    }
    await this.copy(Math.max(this.pos, upTo));
    return edits.slice(k);
  }
}

/** Highest weight in full and a quarter of each other kind's, as the family scores, capped at 100. */
function score(findings: DefuseFinding[], bands = DEFAULT_BANDS): { score: number; risk: FileRisk } {
  const byKind = new Map<string, number>();
  for (const f of findings) byKind.set(`${f.category}/${f.detail}`, Math.max(byKind.get(`${f.category}/${f.detail}`) ?? 0, f.weight ?? 0));
  const w = [...byKind.values()].sort((a, b) => b - a);
  const s = Math.min(100, Math.round(w.length ? w[0] + w.slice(1).reduce((t, x) => t + x / 4, 0) : 0));
  const risk = s >= bands.critical ? FileRisk.Critical : s >= bands.high ? FileRisk.High : s >= bands.medium ? FileRisk.Medium : s >= bands.low ? FileRisk.Low : FileRisk.None;
  return { score: s, risk };
}

export interface TextInspection {
  status: 'clean' | 'strippable' | 'rejected';
  score: number | null;
  risk: FileRisk;
  findings: DefuseFinding[];
}

export interface TextDisarm {
  status: 'clean' | 'defused' | 'rejected';
  before: TextInspection;
  after?: TextInspection;
  removed: DefuseFinding[];
}

/** The text rules, for one tree of files. */
export class TextReader {
  readonly factory: FindingFactory;

  constructor(private readonly options: TextOptions) {
    this.factory = new FindingFactory(options.actionOverrides);
  }

  /** The weight of a finding under the section's scoreWeights. */
  weightOf(f: DefuseFinding): number {
    const w = this.options.scoreWeights ?? [];
    const exact = w.find(x => x.category === f.category && x.detail === f.detail);
    if (exact) return exact.weight;
    const cat = w.find(x => x.category === f.category && x.detail === undefined);
    if (cat) return cat.weight;
    return f.weight ?? 0;
  }

  private deadline(deadline?: number): number | undefined {
    const own = this.options.limits?.timeMs;
    const mine = own === undefined ? undefined : Date.now() + own;
    return deadline === undefined ? mine : mine === undefined ? deadline : Math.min(deadline, mine);
  }

  /** One pass: the findings, and with a sink the rewrite. */
  private async pass(source: ByteSource, subtypes: TextSubtype[], deadline: number | undefined, sink?: ByteSink): Promise<FileFinding[]> {
    const size = await source.size();
    const head = await source.read(0, Math.min(4, size));
    const bom = bomOf(head);
    const encoding: TextEncoding = bom?.encoding ?? 'utf-8';
    const start = bom?.bom ?? 0;
    const scan = new Scan(this.factory, encoding, bom !== undefined, subtypes, sink !== undefined);
    const writer = sink && new Writer(source, sink, encoding);
    let pending: Edit[] = [];
    for (let pos = start; pos < size; pos += CHUNK) {
      if (deadline !== undefined && Date.now() > deadline) throw lateError();
      const b = await source.read(pos, Math.min(CHUNK, size - pos));
      scan.push(b, pos);
      if (writer) {
        pending.push(...scan.edits.splice(0));
        pending = await writer.flush(pending, scan.watermark);
      }
    }
    scan.end();
    if (writer) await writer.flush([...pending, ...scan.edits.splice(0)], size);
    for (const f of scan.findings) f.weight = this.weightOf(f);
    return scan.findings;
  }

  private verdict(findings: DefuseFinding[]): TextInspection {
    // A quoted cell that never closes leaves the rest of the file unread as cells, so, as when a package stops a run,
    // there is no score.
    if (findings.some(f => f.detail === D.UnclosedQuote && f.action === 'reject')) return { status: 'rejected', score: null, risk: FileRisk.Unknown, findings };
    const status = findings.some(f => f.action === 'reject') ? 'rejected' : findings.some(f => f.action === 'strip') ? 'strippable' : 'clean';
    const s = score(findings, this.options.scoreBands);
    return { status, score: s.score, risk: s.risk, findings };
  }

  async inspect(source: ByteSource, subtypes: TextSubtype[], deadline?: number): Promise<TextInspection> {
    return this.verdict(await this.pass(source, subtypes, this.deadline(deadline)));
  }

  /**
   * Inspects the file, writes the rewrite to a temporary copy, checks the copy, and only then copies it to `sink`.
   * A copy that still holds anything to remove is not written, and the file is rejected with
   * PROCESSING/VERIFICATION_FAILED.
   */
  async disarm(source: ByteSource, sink: ByteSink, subtypes: TextSubtype[], deadline?: number): Promise<TextDisarm> {
    const until = this.deadline(deadline);
    const before = this.verdict(await this.pass(source, subtypes, until));
    if (before.status === 'rejected') return { status: 'rejected', before, removed: [] };
    const spill = new Spill(this.options.memoryThreshold ?? DEFAULT_MEMORY_THRESHOLD, this.options.tempDir);
    try {
      await this.pass(source, subtypes, until, spill);
      const after = this.verdict(await this.pass(spill.source(), subtypes, until));
      const left = after.findings.filter(f => f.action !== 'info');
      if (left.length) {
        const reasons = [...new Set(left.map(f => `${f.category}/${f.detail}`))].join(', ');
        const failed = this.factory.make(C.Processing, D.VerificationFailed, { reasons });
        failed.weight = this.weightOf(failed);
        before.findings.push(failed);
        return { status: 'rejected', before: { ...before, status: 'rejected' }, removed: [] };
      }
      try {
        await spill.copyTo(sink, () => {
          if (until !== undefined && Date.now() > until) throw lateError();
        });
      } catch (e) {
        try {
          await sink.abort?.(e);
        } catch {
          // The copy's error is the one to report.
        }
        throw e;
      }
      await sink.close();
      const removed = before.findings.filter(f => f.action === 'strip');
      return { status: removed.length ? 'defused' : 'clean', before, after, removed };
    } finally {
      await spill.dispose();
    }
  }
}

/** The text rules as a contained file plugin, for the router. The router only hands it files detection calls text. */
export function textPlugin(reader: TextReader, subtypesOf: (name?: string, declaredType?: string) => TextSubtype[]): ContainedFilePlugin {
  return {
    kind: 'file',
    name: 'text',
    accepts: () => true,
    async process(file, sink, context) {
      const r = await reader.disarm(file.source, sink, subtypesOf(file.name, file.declaredType), context.deadline);
      if (r.status === 'rejected') return { result: 'removed', findings: r.before.findings };
      return { result: r.status === 'clean' ? 'passed' : 'scrubbed', findings: r.before.findings, outputFindings: r.after?.findings };
    },
  };
}
