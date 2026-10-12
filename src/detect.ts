import { detectArchiveSource } from '@patrickdk77/archive-defuse';
import { detectImageSource } from '@patrickdk77/img-defuse';
import { detectOfficeSource } from '@patrickdk77/office-defuse';
import { bufferSource, detectPdfSource } from '@patrickdk77/pdf-defuse';
import { detectXmlSource } from '@patrickdk77/xml-defuse';
import { bomOf, type TextEncoding, textEncoding } from './detect-text';
import type { ByteSource } from './types';

/** The family of packages that reads a format: the options section and package for it. */
export type FileFamily = 'pdf' | 'office' | 'image' | 'xml' | 'archive' | 'text';

/** A text subtype, which a name or a declared type chooses and which adds rules of its own. */
export type TextSubtype = 'csv' | 'tsv' | 'md' | 'txt';

/** What a file claims to be. Neither decides a family: a claim chooses among the formats the content matches. */
export interface DetectHints {
  /** The file's name, such as an upload's file name, an attachment's name or a ZIP entry's name. */
  name?: string;
  /** The MIME type the uploader or the container declares. */
  declaredType?: string;
}

/** One format the content matches, and where its signature sits. */
export interface FileSignature {
  mimeType: string;
  /** The usual file extension, without the dot. */
  extension: string;
  /** The family whose package reads the format. Absent for a format no package of the family reads. */
  family?: FileFamily;
  /** Where the signature sits: 0 for the start, the header's offset for a PDF, the end record's for a ZIP archive. */
  offset: number;
  /** Set when the match rests on a heuristic instead of a signature, saying what it rests on. */
  heuristic?: string;
}

export interface FileDetection {
  /** The MIME type of the format the file is handled as, or application/octet-stream when nothing matched. */
  mimeType: string;
  /** The usual file extension of that format, without the dot, or '' when nothing matched. */
  extension: string;
  /** The family whose package reads the file. Absent when no package of the family reads it. */
  family?: FileFamily;
  /** Every format the content matches, the one at the start first. More than one makes the file a polyglot. */
  signatures: FileSignature[];
  /** For a polyglot, what chose the format it is handled as: its name, its declared type, or the first signature. */
  chosenBy?: 'name' | 'declaredType' | 'firstSignature';
  /** Set when the format rests on a heuristic, saying what it rests on. */
  heuristic?: string;
  /** The encoding of text and markup. '8-bit' is text that is not UTF-8 and names no encoding. */
  encoding?: string;
  /** For text, the subtypes the name and the declared type give. Each adds rules, and none removes one. */
  textTypes?: TextSubtype[];
  /** The type the router gives the package as `sniffedType`: the container format, such as application/zip for a .docx. */
  sniffedType?: string;
}

const ZIP = 'application/zip';
const CFB = 'application/x-ole-storage';
const MARKUP = 'markup';

/**
 * Each package's own detect function, in the order they are asked. A package names only the formats it reads, by the
 * code its inspection uses. office-defuse comes before archive-defuse, which reads every ZIP but cannot know an Office
 * package from any other.
 */
const PACKAGES: ReadonlyArray<{ family: FileFamily; detect: typeof detectPdfSource }> = [
  { family: 'office', detect: detectOfficeSource },
  { family: 'pdf', detect: detectPdfSource },
  { family: 'image', detect: detectImageSource },
  { family: 'xml', detect: detectXmlSource },
  { family: 'archive', detect: detectArchiveSource },
];

/** Extensions of the formats office-defuse reads in a ZIP archive, for what a claim names. */
const OFFICE_ZIP_EXT = [
  ...'docx docm dotx dotm xlsx xlsm xltx xltm xlam xlsb pptx pptm potx potm ppsx ppsm ppam sldx sldm vsdx vsdm vstx vstm vssx vssm'.split(' '),
  ...'xps oxps odt ott ods ots odp otp odg otg odf odm odb'.split(' '),
];

const starts = (b: Uint8Array, at: number, bytes: number[]) => bytes.every((x, i) => b[at + i] === x);
const latin1 = (b: Uint8Array) => Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString('latin1');
const u32le = (b: Uint8Array, at: number) => (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;

/** How many bytes from the start detection reads once and hands every package. Text is judged on them too. */
export const HEAD_BYTES = 65536;

/**
 * Formats at the start of a file that no package of the family reads, named so a report can say what the file is.
 * They have no family.
 */
async function otherFormat(source: ByteSource, size: number, head: Uint8Array): Promise<Omit<FileSignature, 'offset'> | undefined> {
  const s = latin1(head.subarray(0, 64));
  if (s.startsWith('Rar!\x1a\x07\x00') || s.startsWith('Rar!\x1a\x07\x01\x00')) return { mimeType: 'application/vnd.rar', extension: 'rar' };
  if (s.startsWith('\x7fELF')) return { mimeType: 'application/x-executable', extension: 'elf' };
  if (s.startsWith('MZ') && head.length >= 64) {
    const pe = u32le(head, 0x3c);
    if (pe + 4 <= size && latin1(pe + 4 <= head.length ? head.subarray(pe, pe + 4) : await source.read(pe, 4)) === 'PE\0\0') return { mimeType: 'application/x-msdownload', extension: 'exe' };
    if (head.subarray(0, 64).includes(0)) return { mimeType: 'application/x-dosexec', extension: 'exe' };
  }
  if (s.startsWith('%!PS') || starts(head, 0, [0xc5, 0xd0, 0xd3, 0xc6])) return { mimeType: 'application/postscript', extension: 'ps' };
  // SYLK, which Excel opens and runs the formulas of, starts with its ID record.
  if (s.startsWith('ID;P')) return { mimeType: 'application/x-sylk', extension: 'slk' };
  // A compound file office-defuse does not name, such as an installer or an OLE object's own storage.
  if (starts(head, 0, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return { mimeType: CFB, extension: 'cfb' };
  return undefined;
}

/** A file name's extension, lowercased. Windows drops trailing dots and spaces, so "page.html." has the extension html. */
export function extensionOf(name?: string): string | undefined {
  // A loop and lastIndexOf, since /[. ]+$/ backtracks: a name of 40,000 dots took seconds to match.
  const n = name ?? '';
  let end = n.length;
  while (end > 0 && (n[end - 1] === '.' || n[end - 1] === ' ')) end--;
  const dot = n.lastIndexOf('.', end - 1);
  const ext = dot < 0 ? '' : n.slice(dot + 1, end);
  return ext && !/[/\\]/.test(ext) ? ext.toLowerCase() : undefined;
}

/** What a claim names, by extension: the container key a signature carries. */
const CLAIM_EXT = new Map<string, string>([
  ['pdf', 'application/pdf'],
  ['rtf', 'application/rtf'],
  ['png', 'image/png'],
  ['apng', 'image/png'],
  ['jpg', 'image/jpeg'],
  ['jpeg', 'image/jpeg'],
  ['jpe', 'image/jpeg'],
  ['jfif', 'image/jpeg'],
  ['gif', 'image/gif'],
  ['webp', 'image/webp'],
  ['tif', 'image/tiff'],
  ['tiff', 'image/tiff'],
  ['bmp', 'image/bmp'],
  ['dib', 'image/bmp'],
  ['ico', 'image/vnd.microsoft.icon'],
  ['cur', 'image/x-win-bitmap'],
  ['jp2', 'image/jp2'],
  ['j2k', 'image/j2c'],
  ['j2c', 'image/j2c'],
  ['jpc', 'image/j2c'],
  ['jxl', 'image/jxl'],
  ['emf', 'image/emf'],
  ['wmf', 'image/wmf'],
  ['psd', 'image/vnd.adobe.photoshop'],
  ['psb', 'image/vnd.adobe.photoshop'],
  ['gz', 'application/gzip'],
  ['tgz', 'application/gzip'],
  ['bz2', 'application/x-bzip2'],
  ['tbz', 'application/x-bzip2'],
  ['tbz2', 'application/x-bzip2'],
  ['zst', 'application/zstd'],
  ['tzst', 'application/zstd'],
  ['tar', 'application/x-tar'],
  ['cab', 'application/vnd.ms-cab-compressed'],
  ['7z', 'application/x-7z-compressed'],
  ['xz', 'application/x-xz'],
  ['txz', 'application/x-xz'],
  ['lzma', 'application/x-lzma'],
  ['rar', 'application/vnd.rar'],
  ['exe', 'application/x-msdownload'],
  ['dll', 'application/x-msdownload'],
  ['ps', 'application/postscript'],
  ['eps', 'application/postscript'],
  ['slk', 'application/x-sylk'],
]);
for (const ext of ['zip', 'zipx', 'epub', 'jar', ...OFFICE_ZIP_EXT]) CLAIM_EXT.set(ext, ZIP);
for (const ext of ['doc', 'dot', 'xls', 'xlt', 'xla', 'ppt', 'pps', 'pot', 'vsd', 'vss', 'vst', 'msg', 'oft', 'pub', 'mpp', 'msi', 'cfb']) CLAIM_EXT.set(ext, CFB);
for (const ext of ['xml', 'html', 'htm', 'xhtml', 'xht', 'svg', 'xsl', 'xslt', 'mht', 'mhtml', 'eml', 'hta', 'shtml', 'shtm', 'fodt', 'fods', 'fodp', 'fodg']) CLAIM_EXT.set(ext, MARKUP);

/** What a claim names, by declared type. */
function claimOfType(declared: string): string | undefined {
  const m = declared.toLowerCase().split(';')[0].trim();
  if (m === 'application/pdf' || m === 'application/x-pdf') return 'application/pdf';
  if (m === 'application/rtf' || m === 'text/rtf') return 'application/rtf';
  if (m === 'image/jpg' || m === 'image/pjpeg') return 'image/jpeg';
  if (m === 'image/x-png') return 'image/png';
  if (m === 'image/x-icon') return 'image/vnd.microsoft.icon';
  if (
    m === ZIP ||
    m === 'application/x-zip-compressed' ||
    m === 'application/x-zip' ||
    m === 'application/x-zipx' ||
    m.includes('openxmlformats') ||
    m.includes('opendocument') ||
    m.includes('macroenabled') ||
    m === 'application/epub+zip' ||
    m === 'application/java-archive' ||
    m === 'application/vnd.ms-xpsdocument' ||
    m === 'application/oxps'
  )
    return ZIP;
  if (
    m === CFB ||
    m === 'application/msword' ||
    m === 'application/vnd.ms-excel' ||
    m === 'application/vnd.ms-powerpoint' ||
    m === 'application/vnd.visio' ||
    m === 'application/vnd.ms-outlook' ||
    m === 'application/x-mspublisher' ||
    m === 'application/vnd.ms-project' ||
    m === 'application/x-msi'
  )
    return CFB;
  if (
    m === 'text/html' ||
    m === 'application/xml' ||
    m === 'text/xml' ||
    m === 'image/svg+xml' ||
    m === 'application/xhtml+xml' ||
    m === 'application/xslt+xml' ||
    m === 'multipart/related' ||
    m === 'message/rfc822' ||
    m === 'application/hta' ||
    m === 'text/x-server-parsed-html'
  )
    return MARKUP;
  if (m === 'application/x-gzip') return 'application/gzip';
  if (m === 'application/x-bzip' || m === 'application/x-bzip2') return 'application/x-bzip2';
  if (m === 'application/x-zstd') return 'application/zstd';
  if (m === 'application/x-rar-compressed') return 'application/vnd.rar';
  return m.startsWith('image/') || m.startsWith('application/') ? m : undefined;
}

const TEXT_EXT = new Map<string, TextSubtype>([
  ['csv', 'csv'],
  ['tsv', 'tsv'],
  ['tab', 'tsv'],
  ['md', 'md'],
  ['markdown', 'md'],
  ['mdown', 'md'],
  ['mkd', 'md'],
  ['txt', 'txt'],
  ['text', 'txt'],
]);
const TEXT_TYPE = new Map<string, TextSubtype>([
  ['text/csv', 'csv'],
  ['application/csv', 'csv'],
  ['text/tab-separated-values', 'tsv'],
  ['text/markdown', 'md'],
  ['text/x-markdown', 'md'],
  ['text/plain', 'txt'],
]);

/** The text subtypes a claim gives: the name's first, then the declared type's. */
export function textTypesOf(hints: DetectHints): TextSubtype[] {
  const out: TextSubtype[] = [];
  const ext = extensionOf(hints.name);
  const a = ext === undefined ? undefined : TEXT_EXT.get(ext);
  const t = hints.declaredType?.toLowerCase().split(';')[0].trim();
  const b = t === undefined ? undefined : TEXT_TYPE.get(t);
  for (const x of [a, b]) if (x && !out.includes(x)) out.push(x);
  return out.length ? out : ['txt'];
}

const TEXT_MIME: Record<TextSubtype, string> = { csv: 'text/csv', tsv: 'text/tab-separated-values', md: 'text/markdown', txt: 'text/plain' };

/** A signature found, with the key a claim matches it by. */
type Found = FileSignature & { container: string };

/** The key a claim matches a format by: the container for the formats in a ZIP archive, a compound file or markup. */
function containerOf(family: FileFamily | undefined, mimeType: string, extension: string): string {
  if (family === 'xml') return MARKUP;
  if (family === 'pdf') return 'application/pdf';
  return CLAIM_EXT.get(extension) ?? mimeType;
}

/** The type a package is given as `sniffedType`: the container format, such as application/zip for a .docx. */
function sniffedTypeOf(f: Found): string {
  if (f.container === MARKUP) return f.family === 'office' ? 'application/xml' : f.mimeType;
  return f.container;
}

/** A detection, with what the router needs besides: the formats that lost to the one chosen. */
export interface Detected extends FileDetection {
  /** The signatures of the formats the file is not handled as, for the router's polyglot findings. */
  others: FileSignature[];
  /** The container key of the chosen format, which the output's signatures are checked against. */
  container?: string;
}

/** A source over the same bytes that answers reads within the head from the head, so every package shares one read. */
function headed(source: ByteSource, head: Uint8Array): ByteSource {
  return {
    size: () => source.size(),
    read: async (offset, length) => (offset + length <= head.length ? head.subarray(offset, offset + length) : source.read(offset, length)),
  };
}

/**
 * Detects a file's format by asking each package of the family, with the first 64 KiB read once. Each package names
 * only the formats it reads, and where in the file the format starts. When the content matches more than one format,
 * the name's extension, then the declared type, chooses among them, and without a claim that names one of them the
 * format at the start wins. A few formats no package reads are named at the start of a file too. Text, which no
 * package claims, is the last guess, and its subtype comes from the claim.
 */
export async function detectSource(source: ByteSource, size: number, hints: DetectHints = {}, deadline?: number): Promise<Detected> {
  const head = size > 0 ? await source.read(0, Math.min(size, HEAD_BYTES)) : new Uint8Array(0);
  const shared = headed(source, head);
  const found: Found[] = [];
  for (const p of PACKAGES) {
    const d = await p.detect(shared, { name: hints.name, declaredType: hints.declaredType, deadline });
    if (!d) continue;
    const sig: Found = { mimeType: d.mimeType, extension: d.extension, family: p.family, offset: d.offset, container: containerOf(p.family, d.mimeType, d.extension) };
    if (d.heuristic) sig.heuristic = d.heuristic;
    found.push(sig);
  }
  // archive-defuse reads every ZIP, so its ZIP gives way to the Office package office-defuse names in the same bytes.
  const officeZip = found.find(f => f.family === 'office' && f.container === ZIP);
  const kept = officeZip ? found.filter(f => !(f.family === 'archive' && f.container === ZIP && f.offset === officeZip.offset)) : found;
  if (!kept.some(f => f.offset === 0)) {
    const other = await otherFormat(source, size, head);
    if (other) kept.push({ ...other, offset: 0, container: CLAIM_EXT.get(other.extension) ?? other.mimeType });
  }
  // The format at the start first, and among formats at one offset, the order the packages are asked in.
  kept.sort((a, b) => a.offset - b.offset);
  if (!kept.length) {
    const encoding = textEncoding(head, head.length === size);
    if (encoding === undefined) return { mimeType: 'application/octet-stream', extension: '', signatures: [], others: [] };
    const textTypes = textTypesOf(hints);
    const d: Detected = { mimeType: TEXT_MIME[textTypes[0]], extension: textTypes[0], family: 'text', signatures: [], others: [], encoding, textTypes, sniffedType: TEXT_MIME[textTypes[0]] };
    if (encoding === '8-bit') d.heuristic = 'bytes that are not UTF-8 and hold no control character, read as text in an 8-bit encoding the file does not name';
    return d;
  }
  // A claim chooses among the formats the content matches, and the one at the start wins otherwise.
  let chosen = kept[0];
  let chosenBy: FileDetection['chosenBy'];
  if (kept.length > 1) {
    const ext = extensionOf(hints.name);
    const byName = ext === undefined ? undefined : CLAIM_EXT.get(ext);
    const byType = hints.declaredType ? claimOfType(hints.declaredType) : undefined;
    const named = kept.find(x => x.container === byName);
    const typed = kept.find(x => x.container === byType);
    if (named) [chosen, chosenBy] = [named, 'name'];
    else if (typed) [chosen, chosenBy] = [typed, 'declaredType'];
    else chosenBy = 'firstSignature';
  }
  const strip = ({ container: _, ...sig }: Found): FileSignature => sig;
  const d: Detected = {
    mimeType: chosen.mimeType,
    extension: chosen.extension,
    signatures: kept.map(strip),
    others: kept.filter(x => x !== chosen).map(strip),
    container: chosen.container,
    sniffedType: sniffedTypeOf(chosen),
  };
  if (chosen.family) d.family = chosen.family;
  if (chosenBy) d.chosenBy = chosenBy;
  if (chosen.heuristic) d.heuristic = chosen.heuristic;
  return d;
}

/** The detection the public functions return: the router's, without what only the router uses. */
function publicDetection(d: Detected): FileDetection {
  const { others: _o, container: _c, ...rest } = d;
  return rest;
}

/** Detects the format of the bytes of any file. See detectFileSource. */
export async function detectFile(bytes: Uint8Array, hints: DetectHints = {}): Promise<FileDetection> {
  return publicDetection(await detectSource(bufferSource(bytes), bytes.length, hints));
}

/**
 * Detects the format of any file, the way file-defuse routes it: the MIME type, the usual extension, the family whose
 * package reads it, and every format found. The source is closed when the detection ends.
 */
export async function detectFileSource(source: ByteSource, hints: DetectHints = {}): Promise<FileDetection> {
  try {
    return publicDetection(await detectSource(source, await source.size(), hints));
  } finally {
    try {
      await source.close?.();
    } catch {
      // The detection stands.
    }
  }
}

export type { TextEncoding };
/** Whether `bom` bytes start the text, for the text rules. */
export { bomOf };
