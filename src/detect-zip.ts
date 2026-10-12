import * as zlib from 'node:zlib';
import type { ByteSource } from './types';

/** ZIP readers look for the end record in the last 22 bytes plus the longest comment. */
export const ZIP_WINDOW = 22 + 0xffff;
/**
 * Bounds on what detection reads of a ZIP archive: the bytes of the central directory, the entries it walks, and the
 * inflated start of an entry whose text it reads. Nothing is allocated from a size the archive declares.
 */
const MAX_DIRECTORY = 16 * 1024 * 1024;
const MAX_ENTRIES = 65536;
export const ENTRY_TEXT = 8192;

export interface ZipEntry {
  name: string;
  method: number;
  flags: number;
  compressedSize: number;
  size: number;
  /** Where the local header sits in the file. */
  local: number;
}

export interface ZipDirectory {
  /** Where the end record sits. */
  end: number;
  entries: ZipEntry[];
}

const u16 = (b: Uint8Array, at: number) => b[at] | (b[at + 1] << 8);
const u32 = (b: Uint8Array, at: number) => (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;
const u64 = (b: Uint8Array, at: number) => u32(b, at) + u32(b, at + 4) * 2 ** 32;
const SIG = (b: Uint8Array, at: number, sig: number) => at >= 0 && at + 4 <= b.length && u32(b, at) === sig;

async function sigAt(source: ByteSource, size: number, at: number, sig: number): Promise<boolean> {
  if (at < 0 || at + 4 > size) return false;
  return SIG(await source.read(at, 4), 0, sig);
}

/**
 * The central directory a ZIP reader would find: the last end record in the window whose directory offset leads to a
 * central directory, taken as written or relative to where the directory must sit when data was prepended. ZIP64
 * values replace the end record's when it defers to them.
 */
export async function findDirectory(source: ByteSource, size: number): Promise<ZipDirectory | undefined> {
  if (size < 22) return undefined;
  const tailStart = Math.max(0, size - ZIP_WINDOW);
  const tail = await source.read(tailStart, size - tailStart);
  for (let i = tail.length - 22; i >= 0; i--) {
    if (!SIG(tail, i, 0x06054b50)) continue;
    const end = tailStart + i;
    let count = u16(tail, i + 10);
    let cdSize = u32(tail, i + 12);
    let cdOffset = u32(tail, i + 16);
    if (count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
      // The ZIP64 locator sits right before the end record and points at the ZIP64 end record.
      if (end < 20) continue;
      const loc = await source.read(end - 20, 20);
      if (!SIG(loc, 0, 0x07064b50)) continue;
      const at = u64(loc, 8);
      if (!Number.isSafeInteger(at) || at + 56 > size) continue;
      const rec = await source.read(at, 56);
      if (!SIG(rec, 0, 0x06064b50)) continue;
      count = u64(rec, 32);
      cdSize = u64(rec, 40);
      cdOffset = u64(rec, 48);
    }
    let cd = -1;
    if (await sigAt(source, size, cdOffset, 0x02014b50)) cd = cdOffset;
    else if (await sigAt(source, size, end - cdSize, 0x02014b50)) cd = end - cdSize;
    else if (count === 0 && cdSize === 0) cd = end;
    if (cd < 0) continue;
    const base = cd - cdOffset;
    const raw = await source.read(cd, Math.min(cdSize, MAX_DIRECTORY, size - cd));
    const entries: ZipEntry[] = [];
    for (let p = 0; p + 46 <= raw.length && SIG(raw, p, 0x02014b50) && entries.length < MAX_ENTRIES; ) {
      const nameLength = u16(raw, p + 28);
      const extraLength = u16(raw, p + 30);
      const next = p + 46 + nameLength + extraLength + u16(raw, p + 32);
      if (p + 46 + nameLength > raw.length) break;
      const name = Buffer.from(raw.subarray(p + 46, p + 46 + nameLength)).toString((u16(raw, p + 8) & 0x800) !== 0 ? 'utf8' : 'latin1');
      let compressedSize = u32(raw, p + 20);
      let entrySize = u32(raw, p + 24);
      let local = u32(raw, p + 42);
      // A field at its maximum takes its value from the ZIP64 extra field, in the order the format fixes.
      const extra = raw.subarray(p + 46 + nameLength, Math.min(raw.length, p + 46 + nameLength + extraLength));
      for (let x = 0; x + 4 <= extra.length; x += 4 + u16(extra, x + 2)) {
        if (u16(extra, x) !== 0x0001) continue;
        let at = x + 4;
        const take = () => {
          const v = at + 8 <= extra.length ? u64(extra, at) : undefined;
          at += 8;
          return v;
        };
        if (entrySize === 0xffffffff) entrySize = take() ?? entrySize;
        if (compressedSize === 0xffffffff) compressedSize = take() ?? compressedSize;
        if (local === 0xffffffff) local = take() ?? local;
        break;
      }
      entries.push({ name, method: u16(raw, p + 10), flags: u16(raw, p + 8), compressedSize, size: entrySize, local: base + local });
      p = next;
    }
    return { end, entries };
  }
  return undefined;
}

/** The key two names collide on in office-defuse: percent-decoded, NFC and lowercase, without a directory's slash. */
export function nameKey(name: string): string {
  let n = name;
  try {
    n = decodeURIComponent(n);
  } catch {
    // Not valid percent-encoding, so it stays as written.
  }
  return n.normalize('NFC').toLowerCase().replace(/\/$/, '');
}

/**
 * The start of an entry's content, at most `limit` bytes of it, or undefined when it is encrypted or does not read.
 * Deflate data is inflated from a prefix of its compressed bytes, halved until its output fits the limit, so an entry
 * that inflates to gigabytes costs no more than one that inflates to `limit` bytes.
 */
export async function readEntry(source: ByteSource, size: number, e: ZipEntry, limit = ENTRY_TEXT): Promise<Buffer | undefined> {
  if ((e.flags & 1) !== 0 || (e.method !== 0 && e.method !== 8)) return undefined;
  if (!Number.isSafeInteger(e.local) || e.local < 0 || e.local + 30 > size) return undefined;
  const head = await source.read(e.local, 30);
  if (!SIG(head, 0, 0x04034b50)) return undefined;
  const start = e.local + 30 + u16(head, 26) + u16(head, 28);
  if (start > size) return undefined;
  // Deflate data never inflates to less than about its own size, so this much input covers the limit.
  const length = Math.max(0, Math.min(e.compressedSize, size - start, e.method === 0 ? limit : limit + 1024));
  const data = Buffer.from(await source.read(start, length));
  if (e.method === 0) return data;
  for (let n = data.length; n > 0; n = Math.floor(n / 2)) {
    try {
      return zlib.inflateRawSync(data.subarray(0, n), { finishFlush: zlib.constants.Z_SYNC_FLUSH, maxOutputLength: limit });
    } catch (err) {
      // More output than the limit: a shorter prefix gives a shorter start. Anything else does not inflate.
      if ((err as { code?: string }).code !== 'ERR_BUFFER_TOO_LARGE') return undefined;
    }
  }
  return undefined;
}
