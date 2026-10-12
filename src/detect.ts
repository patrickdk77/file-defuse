import { bufferSource } from '@patrickdk77/pdf-defuse';
import { cfbKinds, MSI_CLSID, OUTLOOK_TEMPLATE_CLSID, readCfbRoot } from './detect-cfb';
import { bomOf, isFlatHead, looseText, markupEncoding, sniffMarkup, type TextEncoding, textEncoding } from './detect-text';
import { findDirectory, nameKey, readEntry, type ZipDirectory } from './detect-zip';
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

/** A format and the key a claim matches it by. */
interface Format {
  mimeType: string;
  extension: string;
  family?: FileFamily;
  /** What a claim names and what the package is given as sniffedType, such as application/zip for every ZIP format. */
  container: string;
}

const fmt = (mimeType: string, extension: string, family: FileFamily | undefined, container = mimeType): Format => ({ mimeType, extension, family, container });

const ZIP = 'application/zip';
const CFB = 'application/x-ole-storage';
const MARKUP = 'markup';

const PDF = fmt('application/pdf', 'pdf', 'pdf');
const RTF = fmt('application/rtf', 'rtf', 'office');

/** OOXML formats by the content type of the main part, lowercased, as office-defuse names them. */
const OOXML = new Map<string, [string, string]>([
  ['application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml', ['docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']],
  ['application/vnd.ms-word.document.macroenabled.main+xml', ['docm', 'application/vnd.ms-word.document.macroEnabled.12']],
  ['application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml', ['dotx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.template']],
  ['application/vnd.ms-word.template.macroenabledtemplate.main+xml', ['dotm', 'application/vnd.ms-word.template.macroEnabled.12']],
  ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml', ['xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']],
  ['application/vnd.ms-excel.sheet.macroenabled.main+xml', ['xlsm', 'application/vnd.ms-excel.sheet.macroEnabled.12']],
  ['application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml', ['xltx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.template']],
  ['application/vnd.ms-excel.template.macroenabled.main+xml', ['xltm', 'application/vnd.ms-excel.template.macroEnabled.12']],
  ['application/vnd.ms-excel.addin.macroenabled.main+xml', ['xlam', 'application/vnd.ms-excel.addin.macroEnabled.12']],
  ['application/vnd.ms-excel.sheet.binary.macroenabled.main', ['xlsb', 'application/vnd.ms-excel.sheet.binary.macroEnabled.12']],
  ['application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml', ['pptx', 'application/vnd.openxmlformats-officedocument.presentationml.presentation']],
  ['application/vnd.ms-powerpoint.presentation.macroenabled.main+xml', ['pptm', 'application/vnd.ms-powerpoint.presentation.macroEnabled.12']],
  ['application/vnd.openxmlformats-officedocument.presentationml.template.main+xml', ['potx', 'application/vnd.openxmlformats-officedocument.presentationml.template']],
  ['application/vnd.ms-powerpoint.template.macroenabled.main+xml', ['potm', 'application/vnd.ms-powerpoint.template.macroEnabled.12']],
  ['application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml', ['ppsx', 'application/vnd.openxmlformats-officedocument.presentationml.slideshow']],
  ['application/vnd.ms-powerpoint.slideshow.macroenabled.main+xml', ['ppsm', 'application/vnd.ms-powerpoint.slideshow.macroEnabled.12']],
  ['application/vnd.ms-powerpoint.addin.macroenabled.main+xml', ['ppam', 'application/vnd.ms-powerpoint.addin.macroEnabled.12']],
  ['application/vnd.openxmlformats-officedocument.presentationml.slide+xml', ['sldx', 'application/vnd.openxmlformats-officedocument.presentationml.slide']],
  ['application/vnd.ms-powerpoint.slide.macroenabled.main+xml', ['sldm', 'application/vnd.ms-powerpoint.slide.macroEnabled.12']],
  ['application/vnd.ms-visio.drawing.main+xml', ['vsdx', 'application/vnd.ms-visio.drawing']],
  ['application/vnd.ms-visio.drawing.macroenabled.main+xml', ['vsdm', 'application/vnd.ms-visio.drawing.macroEnabled.12']],
  ['application/vnd.ms-visio.template.main+xml', ['vstx', 'application/vnd.ms-visio.template']],
  ['application/vnd.ms-visio.template.macroenabled.main+xml', ['vstm', 'application/vnd.ms-visio.template.macroEnabled.12']],
  ['application/vnd.ms-visio.stencil.main+xml', ['vssx', 'application/vnd.ms-visio.stencil']],
  ['application/vnd.ms-visio.stencil.macroenabled.main+xml', ['vssm', 'application/vnd.ms-visio.stencil.macroEnabled.12']],
]);
const XPS_SEQUENCE = 'application/vnd.ms-package.xps-fixeddocumentsequence+xml';
const OXPS_RELATIONSHIP = 'http://schemas.openxps.org/oxps/v1.0/fixedrepresentation';

/** OpenDocument formats by media type, as office-defuse names them. */
const ODF = new Map<string, string>([
  ['text', 'odt'],
  ['text-template', 'ott'],
  ['spreadsheet', 'ods'],
  ['spreadsheet-template', 'ots'],
  ['presentation', 'odp'],
  ['presentation-template', 'otp'],
  ['graphics', 'odg'],
  ['graphics-template', 'otg'],
  ['formula', 'odf'],
  ['text-master', 'odm'],
  ['base', 'odb'],
]);
const odfFormat = (mediaType: string): Format | undefined => {
  const kind = /^application\/vnd\.oasis\.opendocument\.(.+)$/.exec(mediaType)?.[1];
  const ext = kind === undefined ? undefined : ODF.get(kind);
  return ext ? fmt(mediaType, ext, 'office', ZIP) : undefined;
};
/** Flat OpenDocument formats by media type. */
const FLAT_ODF = new Map([
  ['application/vnd.oasis.opendocument.text', 'fodt'],
  ['application/vnd.oasis.opendocument.spreadsheet', 'fods'],
  ['application/vnd.oasis.opendocument.presentation', 'fodp'],
  ['application/vnd.oasis.opendocument.graphics', 'fodg'],
]);

/** ZIP compression methods only WinZip's .zipx writes: LZMA, zstd, XZ, JPEG, WavPack and PPMd. */
const ZIPX_METHODS = new Set([14, 93, 95, 96, 97, 98]);

const starts = (b: Uint8Array, at: number, bytes: number[]) => bytes.every((x, i) => b[at + i] === x);
const latin1 = (b: Uint8Array) => Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString('latin1');
const u32le = (b: Uint8Array, at: number) => (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;

/** How many bytes from the start detection reads. Text is judged on them, and markup on the first 16 KiB of them. */
export const HEAD_BYTES = 65536;
/** PDF readers take a header anywhere in the first 1024 bytes. */
const PDF_WINDOW = 1024;

/** The format a ZIP archive is, by its central directory: an Office or OpenDocument package, XPS, or an archive. */
async function zipFormat(source: ByteSource, size: number, dir: ZipDirectory | undefined): Promise<Format & { heuristic?: string }> {
  if (!dir) {
    // No end record leads to a central directory, so the first local header's name is all there is to go on.
    const head = await source.read(0, Math.min(size, 30 + 64));
    const n = head.length >= 30 ? head[26] | (head[27] << 8) : 0;
    const first = latin1(head.subarray(30, 30 + n));
    const heuristic = 'no end record leads to a central directory, so the name of the first entry decides';
    if (first === '[Content_Types].xml' || first === 'mimetype') return { ...fmt(ZIP, 'zip', 'office', ZIP), heuristic };
    return { ...fmt(ZIP, 'zip', 'archive'), heuristic };
  }
  const byKey = new Map(dir.entries.map(e => [nameKey(e.name), e]));
  const types = byKey.get('[content_types].xml');
  const mimetype = dir.entries.find(e => e.name === 'mimetype');
  const manifest = byKey.get('meta-inf/manifest.xml');
  // Both markers make office-defuse refuse the package as ambiguous.
  if (types && (mimetype || manifest)) return fmt(ZIP, 'zip', 'office', ZIP);
  if (types) {
    const xml = await readEntry(source, size, types);
    if (!xml) return fmt(ZIP, 'zip', 'office', ZIP);
    const named = [...xml.toString('utf8').matchAll(/ContentType\s*=\s*(?:"([^"]*)"|'([^']*)')/gi)].map(m => (m[1] ?? m[2]).trim().toLowerCase());
    const main = [...new Set(named.filter(t => OOXML.has(t)))];
    if (main.length === 1) {
      const [ext, mime] = OOXML.get(main[0]) as [string, string];
      return fmt(mime, ext, 'office', ZIP);
    }
    if (main.length === 0 && named.includes(XPS_SEQUENCE)) {
      const rels = byKey.get('_rels/.rels');
      const text = rels ? ((await readEntry(source, size, rels))?.toString('utf8') ?? '') : '';
      return text.includes(OXPS_RELATIONSHIP) ? fmt('application/oxps', 'oxps', 'office', ZIP) : fmt('application/vnd.ms-xpsdocument', 'xps', 'office', ZIP);
    }
    // Any Open Packaging Conventions package goes to office-defuse, which judges one that names no Office main part.
    return fmt(ZIP, 'zip', 'office', ZIP);
  }
  if (mimetype || manifest) {
    let mediaType: string | undefined;
    if (mimetype) mediaType = (await readEntry(source, size, mimetype, 256))?.toString('latin1');
    else if (manifest) {
      const xml = (await readEntry(source, size, manifest))?.toString('utf8') ?? '';
      for (const tag of xml.match(/<[^>]*file-entry\b[^>]*>/g) ?? []) {
        if (!/full-path\s*=\s*["']\/["']/.test(tag)) continue;
        mediaType = /media-type\s*=\s*["']([^"']*)["']/.exec(tag)?.[1];
        break;
      }
    }
    const type = mediaType?.trim() ?? '';
    // EPUB has a mimetype entry too, and is an archive of web pages.
    if (type === 'application/epub+zip') return fmt('application/epub+zip', 'epub', 'archive', ZIP);
    // Any other marked package goes to office-defuse, which judges one of a type it does not read, such as StarOffice's.
    return odfFormat(type) ?? fmt(ZIP, 'zip', 'office', ZIP);
  }
  if (dir.entries.some(e => ZIPX_METHODS.has(e.method))) return { ...fmt('application/x-zipx', 'zipx', 'archive', ZIP), heuristic: 'a compression method only WinZip writes' };
  return fmt(ZIP, 'zip', 'archive');
}

/** The format a compound file is, by the streams and storages of its root, as office-defuse names it. */
async function cfbFormat(source: ByteSource, size: number): Promise<Format> {
  const root = await readCfbRoot(source, size);
  // A compound file that does not read goes to office-defuse, whose reader gives the reason.
  if (!root) return fmt(CFB, 'cfb', 'office', CFB);
  const kinds = cfbKinds(root);
  if (kinds.length > 1) return fmt(CFB, 'cfb', 'office', CFB);
  switch (kinds[0]) {
    case 'encrypted':
      return fmt(CFB, '', 'office', CFB);
    case 'word':
      return fmt('application/msword', 'doc', 'office', CFB);
    case 'excel':
      return fmt('application/vnd.ms-excel', 'xls', 'office', CFB);
    case 'powerpoint':
      return fmt('application/vnd.ms-powerpoint', 'ppt', 'office', CFB);
    case 'visio':
      return fmt('application/vnd.visio', 'vsd', 'office', CFB);
    case 'outlook':
      return root.clsid === OUTLOOK_TEMPLATE_CLSID ? fmt('application/vnd.ms-outlook', 'oft', 'office', CFB) : fmt('application/vnd.ms-outlook', 'msg', 'office', CFB);
    case 'publisher':
      return fmt('application/x-mspublisher', 'pub', 'office', CFB);
    case 'project':
      return fmt('application/vnd.ms-project', 'mpp', 'office', CFB);
    default:
      // A compound file of another kind, such as an installer or an OLE object's own storage.
      return root.clsid === MSI_CLSID ? fmt('application/x-msi', 'msi', undefined, CFB) : fmt(CFB, 'cfb', undefined, CFB);
  }
}

/** True when the 512 bytes are a tar header, by the checksum of the header, counted unsigned or, as old writers did, signed. */
export function isTarHeader(block: Uint8Array): boolean {
  if (block.length < 512) return false;
  let i = 148;
  while (i < 156 && block[i] === 0x20) i++;
  let stored = 0;
  let digits = 0;
  for (; i < 156 && block[i] >= 0x30 && block[i] <= 0x37; i++, digits++) stored = stored * 8 + (block[i] - 0x30);
  if (digits === 0) return false;
  for (; i < 156; i++) if (block[i] !== 0x20 && block[i] !== 0) return false;
  let unsigned = 0;
  let signed = 0;
  for (let k = 0; k < 512; k++) {
    const b = k >= 148 && k < 156 ? 0x20 : block[k];
    unsigned += b;
    signed += b > 127 ? b - 256 : b;
  }
  return unsigned !== 8 * 0x20 && (stored === unsigned || stored === signed);
}

/**
 * The lzma-alone header (.lzma), which has no magic, by the test archive-defuse and liblzma's .lzma decoder use when
 * they guess: properties with lc + lp at most 4, a dictionary of 2^n or 2^n + 2^(n-1) bytes, a size that is unknown or
 * below 256 GiB, and a first byte of 0 in the range coder data.
 */
function isLzmaAlone(b: Uint8Array): boolean {
  if (b.length < 14) return false;
  const props = b[0];
  if (props >= 9 * 5 * 5 || (props % 9) + (Math.floor(props / 9) % 5) > 4) return false;
  const dict = u32le(b, 1);
  if (dict !== 0xffffffff && dict !== 0) {
    const high = 2 ** Math.floor(Math.log2(dict));
    if (dict !== high && dict !== high + high / 2) return false;
  }
  const low = u32le(b, 5);
  const high = u32le(b, 9);
  if (!(low === 0xffffffff && high === 0xffffffff) && high >= 1 << 6) return false;
  return b[13] === 0;
}

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(b: Uint8Array): number {
  let c = 0xffffffff;
  for (const x of b) c = CRC_TABLE[(c ^ x) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** How far into a file a 7z signature header is looked for, as self-extracting archives put a program first. */
const SEVENZIP_SEARCH = 1024 * 1024;

/**
 * Where a 7z signature header sits after other data, as archive-defuse looks for one: the signature, version 0 and
 * a start header whose CRC matches, within the first MiB. Undefined when there is none.
 */
async function sevenZipAfter(source: ByteSource, size: number): Promise<number | undefined> {
  const b = await source.read(0, Math.min(size, SEVENZIP_SEARCH));
  const limit = b.length - 32;
  for (let at = b.indexOf(0x37, 1); at >= 0 && at <= limit; at = b.indexOf(0x37, at + 1)) {
    if (!starts(b, at, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) || b[at + 6] !== 0) continue;
    if (crc32(b.subarray(at + 12, at + 32)) === u32le(b, at + 8)) return at;
  }
  return undefined;
}

/** The format the start of the file names, by a signature at offset 0, or undefined. */
async function atStart(source: ByteSource, size: number, head: Uint8Array): Promise<(Format & { heuristic?: string; encoding?: string }) | undefined> {
  const s = latin1(head.subarray(0, 64));
  if (s.startsWith('%PDF-')) return PDF;
  if (s.startsWith('PK\x03\x04') || s.startsWith('PK\x05\x06') || s.startsWith('PK\x07\x08')) return zipFormat(source, size, await findDirectory(source, size));
  if (starts(head, 0, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return cfbFormat(source, size);
  // Word reads any file that starts with {\rt as RTF.
  if (s.startsWith('{\\rt')) return RTF;
  // Images, with img-defuse's own signatures.
  if (starts(head, 0, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return fmt('image/png', 'png', 'image');
  if (starts(head, 0, [0xff, 0xd8, 0xff])) return fmt('image/jpeg', 'jpg', 'image');
  if (s.startsWith('GIF87a') || s.startsWith('GIF89a')) return fmt('image/gif', 'gif', 'image');
  if (s.startsWith('RIFF') && s.slice(8, 12) === 'WEBP') return fmt('image/webp', 'webp', 'image');
  if (s.startsWith('II*\0') || s.startsWith('MM\0*') || s.startsWith('II+\0') || s.startsWith('MM\0+')) return fmt('image/tiff', 'tif', 'image');
  if (s.startsWith('BM') && head.length >= 18 && [12, 40, 52, 56, 64, 108, 124].includes(u32le(head, 14))) return fmt('image/bmp', 'bmp', 'image');
  if (head.length >= 6 && starts(head, 0, [0, 0]) && (head[2] === 1 || head[2] === 2) && head[3] === 0 && (head[4] | (head[5] << 8)) > 0) {
    return head[2] === 1 ? fmt('image/vnd.microsoft.icon', 'ico', 'image') : fmt('image/x-win-bitmap', 'cur', 'image');
  }
  if (starts(head, 0, [0, 0, 0, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a, 0x87, 0x0a])) return fmt('image/jp2', 'jp2', 'image');
  if (starts(head, 0, [0xff, 0x4f, 0xff, 0x51])) return fmt('image/j2c', 'j2c', 'image');
  if (starts(head, 0, [0xff, 0x0a]) || starts(head, 0, [0, 0, 0, 0x0c, 0x4a, 0x58, 0x4c, 0x20, 0x0d, 0x0a, 0x87, 0x0a])) return fmt('image/jxl', 'jxl', 'image');
  if (head.length >= 44 && starts(head, 0, [1, 0, 0, 0]) && s.slice(40, 44) === ' EMF') return fmt('image/emf', 'emf', 'image');
  if (starts(head, 0, [0xd7, 0xcd, 0xc6, 0x9a]) || ((head[0] === 1 || head[0] === 2) && starts(head, 1, [0, 9, 0, 0]) && (head[5] === 3 || head[5] === 1))) {
    return fmt('image/wmf', 'wmf', 'image');
  }
  // Version 2 is the large document format, PSB.
  if (s.startsWith('8BPS')) return head[4] === 0 && head[5] === 2 ? fmt('image/vnd.adobe.photoshop', 'psb', 'image') : fmt('image/vnd.adobe.photoshop', 'psd', 'image');
  // Compression and archives.
  if (head[0] === 0x1f && head[1] === 0x8b) return fmt('application/gzip', 'gz', 'archive');
  // bzip2 needs a block or the end of the stream right after its header.
  if (s.startsWith('BZh') && head[3] >= 0x31 && head[3] <= 0x39 && (starts(head, 4, [0x31, 0x41, 0x59, 0x26, 0x53, 0x59]) || starts(head, 4, [0x17, 0x72, 0x45, 0x38, 0x50, 0x90]))) {
    return fmt('application/x-bzip2', 'bz2', 'archive');
  }
  // A zstd frame, or a skippable frame (0x184D2A50 to 0x184D2A5F), which a zstd stream may start with.
  if (starts(head, 0, [0x28, 0xb5, 0x2f, 0xfd]) || ((head[0] & 0xf0) === 0x50 && starts(head, 1, [0x2a, 0x4d, 0x18]))) return fmt('application/zstd', 'zst', 'archive');
  if (s.startsWith('MSCF\0\0\0\0')) return fmt('application/vnd.ms-cab-compressed', 'cab', 'archive');
  if (starts(head, 0, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return fmt('application/x-7z-compressed', '7z', 'archive');
  if (starts(head, 0, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])) return fmt('application/x-xz', 'xz', 'archive');
  // POSIX ustar and GNU tar put their magic at 257. An old tar header has none, so its checksum is the test.
  const magic = latin1(head.subarray(257, 265));
  if (magic === 'ustar\x0000' || magic === 'ustar  \0') return fmt('application/x-tar', 'tar', 'archive');
  if (isTarHeader(head.subarray(0, 512))) return { ...fmt('application/x-tar', 'tar', 'archive'), heuristic: 'the header checksum of an old tar header, which has no magic' };
  // Formats no package of the family reads, named so a report can say what the file is.
  if (s.startsWith('Rar!\x1a\x07\x00') || s.startsWith('Rar!\x1a\x07\x01\x00')) return fmt('application/vnd.rar', 'rar', undefined);
  if (s.startsWith('\x7fELF')) return fmt('application/x-executable', 'elf', undefined);
  if (s.startsWith('MZ') && head.length >= 64) {
    const pe = u32le(head, 0x3c);
    if (pe + 4 <= size && latin1(pe + 4 <= head.length ? head.subarray(pe, pe + 4) : await source.read(pe, 4)) === 'PE\0\0') return fmt('application/x-msdownload', 'exe', undefined);
    if (head.subarray(0, 64).includes(0)) return fmt('application/x-dosexec', 'exe', undefined);
  }
  if (s.startsWith('%!PS') || starts(head, 0, [0xc5, 0xd0, 0xd3, 0xc6])) return fmt('application/postscript', 'ps', undefined);
  // SYLK, which Excel opens and runs the formulas of, starts with its ID record.
  if (s.startsWith('ID;P')) return fmt('application/x-sylk', 'slk', undefined);
  return markup(head);
}

/** HTML, XML, SVG, XSLT, MHT, HTA and SHTML for xml-defuse, and flat OpenDocument and Flat OPC for office-defuse. */
function markup(head: Uint8Array): (Format & { heuristic?: string; encoding?: string }) | undefined {
  const enc = markupEncoding(head);
  if (enc.encoding === 'ebcdic') return { ...fmt('application/xml', 'xml', 'xml', MARKUP), encoding: 'ebcdic', heuristic: 'an XML declaration in EBCDIC' };
  const text = looseText(head.subarray(enc.bom, 16384), enc.encoding);
  const m = sniffMarkup(text);
  if (!m) return undefined;
  const encoding = enc.encoding === '8-bit' ? undefined : enc.encoding;
  const out = (f: Format) => ({ ...f, encoding });
  if (m.kind === 'mht') {
    if (m.mediaType?.startsWith('multipart/related')) return out(fmt('multipart/related', 'mht', 'xml', MARKUP));
    // A page saved as one MIME body is MHT too. Other multipart bodies and messages are mail.
    if (m.mediaType && !m.mediaType.startsWith('multipart/') && m.mediaType !== 'message/rfc822') return out(fmt('message/rfc822', 'mht', 'xml', MARKUP));
    return out(fmt('message/rfc822', 'eml', 'xml', MARKUP));
  }
  if (m.kind === 'html') {
    if (/<hta:application[\s>/]/i.test(text)) return out(fmt('application/hta', 'hta', 'xml', MARKUP));
    if (/<!--#(include|exec|echo|config|flastmod|fsize|printenv|set|if|elif|else|endif)\b/i.test(text)) return out(fmt('text/x-server-parsed-html', 'shtml', 'xml', MARKUP));
    return out(fmt('text/html', 'html', 'xml', MARKUP));
  }
  if (isFlatHead(text)) {
    const mime = /office:mimetype\s*=\s*["']([^"']+)["']/.exec(text)?.[1];
    if (m.root?.endsWith(':package') || m.root === 'package') return out(fmt('application/xml', 'xml', 'office', MARKUP));
    const ext = mime ? FLAT_ODF.get(mime) : undefined;
    return out(ext && mime ? fmt(mime, ext, 'office', MARKUP) : fmt('application/xml', 'xml', 'office', MARKUP));
  }
  const local = m.root?.slice(m.root.indexOf(':') + 1);
  if (local === 'svg') return out(fmt('image/svg+xml', 'svg', 'xml', MARKUP));
  if ((local === 'stylesheet' || local === 'transform') && text.includes('http://www.w3.org/1999/XSL/Transform')) return out(fmt('application/xslt+xml', 'xsl', 'xml', MARKUP));
  if (local === 'html' && /xmlns\s*=\s*["']http:\/\/www\.w3\.org\/1999\/xhtml["']/.test(m.attributes ?? '')) return out(fmt('application/xhtml+xml', 'xhtml', 'xml', MARKUP));
  return out(fmt('application/xml', 'xml', 'xml', MARKUP));
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
  ['pdf', PDF.container],
  ['rtf', RTF.container],
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
for (const ext of ['zip', 'zipx', 'epub', 'jar', 'xps', 'oxps', ...[...OOXML.values()].map(([e]) => e), ...ODF.values()]) CLAIM_EXT.set(ext, ZIP);
for (const ext of ['doc', 'dot', 'xls', 'xlt', 'xla', 'ppt', 'pps', 'pot', 'vsd', 'vss', 'vst', 'msg', 'oft', 'pub', 'mpp', 'msi']) CLAIM_EXT.set(ext, CFB);
for (const ext of ['xml', 'html', 'htm', 'xhtml', 'xht', 'svg', 'xsl', 'xslt', 'mht', 'mhtml', 'eml', 'hta', 'shtml', 'shtm', 'fodt', 'fods', 'fodp', 'fodg']) CLAIM_EXT.set(ext, MARKUP);

/** What a claim names, by declared type. */
function claimOfType(declared: string): string | undefined {
  const m = declared.toLowerCase().split(';')[0].trim();
  if (m === 'application/pdf' || m === 'application/x-pdf') return PDF.container;
  if (m === 'application/rtf' || m === 'text/rtf') return RTF.container;
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

/** A signature found, with the format it names. */
type Found = FileSignature & { format: Format };

const signatureOf = (f: Format & { heuristic?: string }, offset: number): Found => {
  const s: Found = { mimeType: f.mimeType, extension: f.extension, offset, format: f };
  if (f.family) s.family = f.family;
  if (f.heuristic) s.heuristic = f.heuristic;
  return s;
};

/** A detection, with what the router needs besides: the formats that lost to the one chosen. */
export interface Detected extends FileDetection {
  /** The signatures of the formats the file is not handled as, for the router's polyglot findings. */
  others: FileSignature[];
  /** The container key of the chosen format, which the output's signatures are checked against. */
  container?: string;
  /** A family to try when the chosen one's package does not take the file, such as xml for flat XML office-defuse refuses. */
  fallback?: FileFamily;
}

/**
 * Detects a file's format from its content. Every format the content matches is listed with its offset. One at the
 * start of the file, or a PDF header in its first 1024 bytes, or a ZIP end record in its last 65,557 bytes, is a
 * signature. When the content matches more than one format, the name's extension, then the declared type, chooses
 * among them, and without a claim that names one of them the signature at the start wins. Text, which has no
 * signature, is the last guess, and its subtype comes from the claim.
 */
export async function detectSource(source: ByteSource, size: number, hints: DetectHints = {}): Promise<Detected> {
  const head = size > 0 ? await source.read(0, Math.min(size, HEAD_BYTES)) : new Uint8Array(0);
  const found: Found[] = [];
  const start = await atStart(source, size, head);
  if (start) found.push(signatureOf(start, 0));
  // PDF readers take the header anywhere in the first 1024 bytes.
  if (start?.container !== PDF.container) {
    const at = latin1(head.subarray(0, PDF_WINDOW)).indexOf('%PDF-');
    if (at >= 0) found.push(signatureOf(PDF, at));
  }
  // ZIP readers find the end record from the end of the file.
  if (start?.container !== ZIP) {
    const dir = await findDirectory(source, size);
    if (dir) found.push(signatureOf(await zipFormat(source, size, dir), dir.end));
  }
  // A self-extracting 7z archive puts a program first, and 7-Zip looks past it.
  if (!start || (start.family === undefined && /exe|elf/.test(start.extension))) {
    const at = await sevenZipAfter(source, size);
    if (at !== undefined) found.push(signatureOf(fmt('application/x-7z-compressed', '7z', 'archive'), at));
  }
  if (!found.length && isLzmaAlone(head)) found.push(signatureOf({ ...fmt('application/x-lzma', 'lzma', 'archive'), heuristic: 'the lzma-alone header, which has no magic' }, 0));
  if (!found.length) {
    const encoding = textEncoding(head, head.length === size);
    if (encoding === undefined) return { mimeType: 'application/octet-stream', extension: '', signatures: [], others: [] };
    const textTypes = textTypesOf(hints);
    const d: Detected = { mimeType: TEXT_MIME[textTypes[0]], extension: textTypes[0], family: 'text', signatures: [], others: [], encoding, textTypes, sniffedType: TEXT_MIME[textTypes[0]] };
    if (encoding === '8-bit') d.heuristic = 'bytes that are not UTF-8 and hold no control character, read as text in an 8-bit encoding the file does not name';
    return d;
  }
  // A claim chooses among the formats the content matches, and the signature at the start wins otherwise.
  let chosen = found[0];
  let chosenBy: FileDetection['chosenBy'];
  if (found.length > 1) {
    const ext = extensionOf(hints.name);
    const byName = ext === undefined ? undefined : CLAIM_EXT.get(ext);
    const byType = hints.declaredType ? claimOfType(hints.declaredType) : undefined;
    const named = found.find(x => x.format.container === byName);
    const typed = found.find(x => x.format.container === byType);
    if (named) [chosen, chosenBy] = [named, 'name'];
    else if (typed) [chosen, chosenBy] = [typed, 'declaredType'];
    else chosenBy = 'firstSignature';
  }
  const f = chosen.format as Format & { heuristic?: string; encoding?: string };
  const d: Detected = {
    mimeType: f.mimeType,
    extension: f.extension,
    signatures: found.map(({ format: _, ...sig }) => sig),
    others: found.filter(x => x !== chosen).map(({ format: _, ...sig }) => sig),
    container: f.container,
    sniffedType: f.container === MARKUP ? (f.family === 'office' ? 'application/xml' : f.mimeType) : f.container,
  };
  if (f.family) d.family = f.family;
  if (chosenBy) d.chosenBy = chosenBy;
  if (f.heuristic) d.heuristic = f.heuristic;
  if (f.encoding) d.encoding = f.encoding;
  if (f.family === 'office' && f.container === MARKUP) d.fallback = 'xml';
  return d;
}

/** The detection the public functions return: the router's, without what only the router uses. */
function publicDetection(d: Detected): FileDetection {
  const { others: _o, container: _c, fallback: _f, ...rest } = d;
  return rest;
}

/** Detects the format of the bytes of any file. See detectFileSource. */
export async function detectFile(bytes: Uint8Array, hints: DetectHints = {}): Promise<FileDetection> {
  return publicDetection(await detectSource(bufferSource(bytes), bytes.length, hints));
}

/**
 * Detects the format of any file, the way file-defuse routes it: the MIME type, the usual extension, the family whose
 * package reads it, and every signature found. The source is closed when the detection ends.
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
