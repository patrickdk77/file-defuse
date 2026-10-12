import type { ByteSource } from './types';

/** What the root storage of a compound file holds, as office-defuse reads it to name the format. */
export interface CfbRoot {
  clsid: string;
  children: Array<{ name: string; kind: 'storage' | 'stream' }>;
}

const END = 0xfffffffe;
/** Bounds on what detection reads of a compound file's directory. */
const MAX_DIRECTORY_SECTORS = 1024;
const MAX_FAT_SECTORS = 16384;

const u16 = (b: Uint8Array, at: number) => b[at] | (b[at + 1] << 8);
const u32 = (b: Uint8Array, at: number) => (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;

/** A class id as office-defuse writes one, such as 00021201-0000-0000-00C0-000000000046. */
function guid(b: Uint8Array, at: number): string {
  const h = (i: number) => b[at + i].toString(16).padStart(2, '0');
  const r = (...is: number[]) => is.map(h).join('');
  return `${r(3, 2, 1, 0)}-${r(5, 4)}-${r(7, 6)}-${r(8, 9)}-${r(10, 11, 12, 13, 14, 15)}`.toUpperCase();
}

/**
 * Reads the root storage of a compound file (MS-CFB): the header, the FAT sectors the directory chain needs, and the
 * directory, walking the root's tree of children. Undefined when any of it does not read, so the caller can leave the
 * verdict to office-defuse's own reader.
 */
export async function readCfbRoot(source: ByteSource, size: number): Promise<CfbRoot | undefined> {
  if (size < 512) return undefined;
  const header = await source.read(0, 512);
  const shift = u16(header, 30);
  if (shift !== 9 && shift !== 12) return undefined;
  const sector = 1 << shift;
  const perSector = sector / 4;
  const fatCount = u32(header, 44);
  const firstDir = u32(header, 48);
  if (fatCount > MAX_FAT_SECTORS) return undefined;
  const offsetOf = (s: number) => (s + 1) * sector;
  // The FAT sectors' numbers: the first 109 in the header, the rest along the DIFAT chain.
  const fatSectors: number[] = [];
  for (let i = 0; i < 109 && fatSectors.length < fatCount; i++) fatSectors.push(u32(header, 76 + 4 * i));
  let difat = u32(header, 68);
  const seen = new Set<number>();
  while (fatSectors.length < fatCount && difat < END) {
    if (seen.has(difat) || offsetOf(difat) + sector > size) return undefined;
    seen.add(difat);
    const b = await source.read(offsetOf(difat), sector);
    for (let i = 0; i < perSector - 1 && fatSectors.length < fatCount; i++) fatSectors.push(u32(b, 4 * i));
    difat = u32(b, sector - 4);
  }
  const fatCache = new Map<number, Uint8Array>();
  const next = async (s: number): Promise<number | undefined> => {
    const index = Math.floor(s / perSector);
    if (index >= fatSectors.length) return undefined;
    let b = fatCache.get(index);
    if (!b) {
      const at = offsetOf(fatSectors[index]);
      if (fatSectors[index] >= END || at + sector > size) return undefined;
      b = await source.read(at, sector);
      fatCache.set(index, b);
    }
    return u32(b, 4 * (s % perSector));
  };
  // The directory's sectors, along its FAT chain.
  const dir: Uint8Array[] = [];
  const visited = new Set<number>();
  for (let s = firstDir; s !== END; ) {
    if (visited.has(s) || dir.length >= MAX_DIRECTORY_SECTORS || offsetOf(s) + sector > size) return undefined;
    visited.add(s);
    dir.push(await source.read(offsetOf(s), sector));
    const n = await next(s);
    if (n === undefined) return undefined;
    s = n;
  }
  const entryCount = (dir.length * sector) / 128;
  const entry = (id: number) => {
    const b = dir[Math.floor((id * 128) / sector)];
    return b.subarray((id * 128) % sector, ((id * 128) % sector) + 128);
  };
  if (entryCount === 0 || entry(0)[66] !== 5) return undefined;
  const root = entry(0);
  const children: CfbRoot['children'] = [];
  // The root's children form a tree through their left and right siblings.
  const stack = [u32(root, 76)];
  const walked = new Set<number>();
  while (stack.length) {
    const id = stack.pop() as number;
    if (id >= 0xfffffffa) continue;
    if (id >= entryCount || walked.has(id)) return undefined;
    walked.add(id);
    const e = entry(id);
    const nameLength = Math.min(64, u16(e, 64));
    const name = Buffer.from(e.subarray(0, Math.max(0, nameLength - 2))).toString('utf16le');
    if (e[66] === 1 || e[66] === 2) children.push({ name, kind: e[66] === 1 ? 'storage' : 'stream' });
    stack.push(u32(e, 68), u32(e, 72));
  }
  return { clsid: guid(root, 80), children };
}

const PUBLISHER_CLSIDS = new Set(['00021200-0000-0000-00C0-000000000046', '00021201-0000-0000-00C0-000000000046']);
export const OUTLOOK_TEMPLATE_CLSID = '0006F046-0000-0000-C000-000000000046';
export const MSI_CLSID = '000C1084-0000-0000-C000-000000000046';

export type CfbKind = 'encrypted' | 'word' | 'excel' | 'powerpoint' | 'visio' | 'outlook' | 'publisher' | 'project';

/** The formats the root names, by office-defuse's own rules, ignoring case as MS-CFB does. */
export function cfbKinds(root: CfbRoot): CfbKind[] {
  const names = new Map(root.children.map(c => [c.name.toUpperCase(), c]));
  const stream = (n: string) => names.get(n)?.kind === 'stream';
  const out: CfbKind[] = [];
  if (stream('ENCRYPTIONINFO') && stream('ENCRYPTEDPACKAGE')) out.push('encrypted');
  if (stream('WORDDOCUMENT')) out.push('word');
  if (stream('WORKBOOK') || stream('BOOK')) out.push('excel');
  if (stream('POWERPOINT DOCUMENT')) out.push('powerpoint');
  if (stream('VISIODOCUMENT')) out.push('visio');
  if (stream('__PROPERTIES_VERSION1.0')) out.push('outlook');
  if (names.get('QUILL')?.kind === 'storage' || (PUBLISHER_CLSIDS.has(root.clsid) && stream('CONTENTS'))) out.push('publisher');
  if ([...names.keys()].some(n => /^PROPS\d*$/.test(n)) && root.children.some(c => c.kind === 'storage' && /^ {3}\d+$/.test(c.name))) out.push('project');
  // Word 2007 writes a Word document beside an encrypted package, for readers that cannot decrypt it.
  return out.filter(x => !(x === 'word' && out.includes('encrypted')));
}
