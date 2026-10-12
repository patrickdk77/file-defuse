import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import type { ByteSource, DefuseFinding } from '../../src';

/** The package root. This file runs from build-test/test/helpers. */
export const root = path.join(__dirname, '..', '..', '..');
export const cli = path.join(root, 'dist', 'cli.js');
export const fixtures = path.join(root, 'test', 'fixtures');
export const fixture = (name: string) => fs.readFileSync(path.join(fixtures, name));

/** Runs the command-line tool. */
export const runCli = (args: string[], opts: { input?: Buffer; env?: NodeJS.ProcessEnv; cwd?: string } = {}) =>
  spawnSync(process.execPath, [cli, ...args], { input: opts.input, env: { ...process.env, ...opts.env }, cwd: opts.cwd, maxBuffer: 64 * 1024 * 1024 });

/** A finding as the manifest writes it. */
export const line = (f: DefuseFinding) => `${f.action} ${f.category}/${f.detail}${f.attachment === undefined ? '' : ` in ${f.attachment}`}`;

export const kinds = (findings: DefuseFinding[]) => findings.map(f => `${f.category}/${f.detail}`);

const B = (s: string) => Buffer.from(s, 'latin1');

export interface DocParts {
  attachments?: Array<{ name: string; bytes: Buffer; type?: string }>;
  js?: boolean;
  info?: boolean;
}

/** A one-page PDF with attached files stored deflated, an open action that runs a script, and an Info dictionary. */
export function makePdf(parts: DocParts = {}): Buffer {
  const objects: Array<string | { dict: string; data: Buffer }> = [];
  const add = (body: string | { dict: string; data: Buffer }) => objects.push(body);
  const files = parts.attachments ?? [];
  const names = files.map((a, i) => `(${a.name}) ${6 + 2 * i} 0 R`).join(' ');
  add(`<< /Type /Catalog /Pages 2 0 R${files.length ? ` /Names << /EmbeddedFiles << /Names [${names}] >> >>` : ''}${parts.js ? ' /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >>' : ''} >>`);
  add('<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
  add('<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>');
  add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  add({ dict: '<< >>', data: B('BT /F1 24 Tf 72 720 Td (Hello) Tj ET') });
  for (const a of files) {
    add(`<< /Type /Filespec /F (${a.name}) /UF (${a.name}) /EF << /F ${objects.length + 2} 0 R >> >>`);
    add({ dict: `<< /Type /EmbeddedFile${a.type ? ` /Subtype /${a.type.replace('/', '#2F')}` : ''} /Filter /FlateDecode >>`, data: zlib.deflateSync(a.bytes) });
  }
  const info = parts.info ? add('<< /Title (Report) /Author (Someone) >>') : undefined;
  const out: Buffer[] = [B('%PDF-1.7\n')];
  let offset = out[0].length;
  const offsets: number[] = [];
  objects.forEach((body, i) => {
    const bytes =
      typeof body === 'string'
        ? B(`${i + 1} 0 obj\n${body}\nendobj\n`)
        : Buffer.concat([B(`${i + 1} 0 obj\n${body.dict.replace(/>>$/, `/Length ${body.data.length} >>`)}\nstream\n`), body.data, B('\nendstream\nendobj\n')]);
    offsets.push(offset);
    out.push(bytes);
    offset += bytes.length;
  });
  let xref = `xref\n0 ${objects.length + 1}\n0000000000 65535 f\r\n`;
  for (const o of offsets) xref += `${String(o).padStart(10, '0')} 00000 n\r\n`;
  out.push(B(`${xref}trailer\n<< /Size ${objects.length + 1} /Root 1 0 R${info ? ` /Info ${info} 0 R` : ''} >>\nstartxref\n${offset}\n%%EOF\n`));
  return Buffer.concat(out);
}

/** A PDF inside a PDF, `levels` deep, with `inner` at the bottom. */
export function nest(levels: number, inner: Buffer): Buffer {
  let doc = inner;
  for (let n = levels; n >= 1; n--) doc = makePdf({ attachments: [{ name: `level${n}.pdf`, bytes: doc }] });
  return doc;
}

/** A source over bytes that waits `ms` before each read, and records whether it was closed. */
export function slowSource(bytes: Buffer, ms: number): ByteSource & { closed: number } {
  const s = {
    closed: 0,
    size: async () => bytes.length,
    read: async (offset: number, length: number) => {
      await new Promise(r => setTimeout(r, ms));
      return bytes.subarray(offset, offset + length);
    },
    close: async () => {
      s.closed++;
    },
  };
  return s;
}

export const rejection = (p: Promise<unknown>) =>
  p.then(
    () => undefined,
    (e: unknown) => e,
  );

export const formatsDir = path.join(fixtures, 'formats');

/** Writes bits least significant first, as deflate packs them. `code` writes a Huffman code most significant bit first. */
class Bits {
  readonly bytes: number[] = [];
  private cur = 0;
  bits = 0;
  put(value: number, count: number): void {
    for (let i = 0; i < count; i++) {
      this.cur |= ((value >> i) & 1) << (this.bits & 7);
      this.bits++;
      if ((this.bits & 7) === 0) {
        this.bytes.push(this.cur);
        this.cur = 0;
      }
    }
  }
  code(value: number, count: number): void {
    for (let i = count - 1; i >= 0; i--) this.put((value >> i) & 1, 1);
  }
  /** The bytes so far, the last one partial. */
  get head(): number[] {
    return (this.bits & 7) === 0 ? this.bytes : [...this.bytes, this.cur];
  }
}

/**
 * Raw deflate data that inflates to 1 + 258 * `repeats` zero bytes. It is one dynamic block whose code for a match of
 * 258 bytes is one bit long and whose one distance code is one bit long, so each match costs two zero bits and the
 * data is mostly zero bytes: about one byte per kilobyte of output.
 */
export function deflateBomb(repeats: number): Buffer {
  const b = new Bits();
  b.put(1, 1); // the final block
  b.put(2, 2); // dynamic Huffman codes
  b.put(29, 5); // 286 literal and length codes
  b.put(0, 5); // 1 distance code
  b.put(14, 4); // 18 code length codes
  const order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1];
  const lengths = new Map([
    [18, 1],
    [2, 2],
    [1, 2],
  ]);
  for (const sym of order) b.put(lengths.get(sym) ?? 0, 3);
  // The code length codes: 18 is 0, 1 is 10, 2 is 11.
  b.code(0b11, 2); // literal 0 has length 2
  b.code(0, 1);
  b.put(127, 7); // 138 zero lengths
  b.code(0, 1);
  b.put(106, 7); // 117 zero lengths
  b.code(0b11, 2); // end of block has length 2
  b.code(0, 1);
  b.put(17, 7); // 28 zero lengths
  b.code(0b10, 2); // length symbol 285, a match of 258, has length 1
  b.code(0b10, 2); // distance code 0, a distance of 1, has length 1
  // The literal codes: 285 is 0, literal 0 is 10, end of block is 11.
  b.code(0b10, 2);
  const start = b.bits;
  const end = start + 2 * repeats;
  const out = Buffer.alloc(Math.ceil((end + 2) / 8));
  Buffer.from(b.head).copy(out);
  for (const k of [end, end + 1]) out[k >> 3] |= 1 << (k & 7);
  return out;
}

/** A ZIP archive of entries stored as given, each with the method and the uncompressed size its headers declare. */
export function zipOf(entries: Array<{ name: string; data: Buffer; method?: number; size?: number }>): Buffer {
  const local: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const n = Buffer.from(e.name, 'utf8');
    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0);
    head.writeUInt16LE(20, 4);
    head.writeUInt16LE(e.method ?? 0, 8);
    head.writeUInt32LE(e.data.length, 18);
    head.writeUInt32LE(e.size ?? e.data.length, 22);
    head.writeUInt16LE(n.length, 26);
    const record = Buffer.alloc(46);
    record.writeUInt32LE(0x02014b50, 0);
    record.writeUInt16LE(20, 4);
    record.writeUInt16LE(20, 6);
    record.writeUInt16LE(e.method ?? 0, 10);
    record.writeUInt32LE(e.data.length, 20);
    record.writeUInt32LE(e.size ?? e.data.length, 24);
    record.writeUInt16LE(n.length, 28);
    record.writeUInt32LE(offset, 42);
    local.push(head, n, e.data);
    central.push(record, n);
    offset += 30 + n.length + e.data.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, cd, end]);
}

/** The content of one entry of a ZIP archive, read through its central directory, or undefined when it has none. */
export function entryOf(zip: Uint8Array, name: string): Buffer | undefined {
  const b = Buffer.from(zip);
  const end = b.lastIndexOf(Buffer.from([0x50, 0x4b, 5, 6]));
  let p = b.readUInt32LE(end + 16);
  for (let i = 0; i < b.readUInt16LE(end + 10); i++) {
    const method = b.readUInt16LE(p + 10);
    const size = b.readUInt32LE(p + 20);
    const nameLength = b.readUInt16LE(p + 28);
    const entry = b.toString('utf8', p + 46, p + 46 + nameLength);
    const local = b.readUInt32LE(p + 42);
    if (entry === name) {
      const start = local + 30 + b.readUInt16LE(local + 26) + b.readUInt16LE(local + 28);
      const data = b.subarray(start, start + size);
      return method === 8 ? zlib.inflateRawSync(data) : data;
    }
    p += 46 + nameLength + b.readUInt16LE(p + 30) + b.readUInt16LE(p + 32);
  }
  return undefined;
}
