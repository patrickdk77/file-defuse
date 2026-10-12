/** The Unicode encodings detection and the text rules read, and the 8-bit fallback for text that names none. */
export type TextEncoding = 'utf-8' | 'utf-16le' | 'utf-16be' | 'utf-32le' | 'utf-32be' | '8-bit';

/** The encoding the first bytes give: a byte order mark, and its length, or undefined when there is none. */
export function bomOf(b: Uint8Array): { encoding: TextEncoding; bom: number } | undefined {
  if (b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) return { encoding: 'utf-8', bom: 3 };
  if (b[0] === 0xff && b[1] === 0xfe && b[2] === 0 && b[3] === 0) return { encoding: 'utf-32le', bom: 4 };
  if (b[0] === 0 && b[1] === 0 && b[2] === 0xfe && b[3] === 0xff) return { encoding: 'utf-32be', bom: 4 };
  if (b[0] === 0xff && b[1] === 0xfe) return { encoding: 'utf-16le', bom: 2 };
  if (b[0] === 0xfe && b[1] === 0xff) return { encoding: 'utf-16be', bom: 2 };
  return undefined;
}

/** UTF-32 to a string, with U+FFFD for a value that is no code point. Stops at a partial unit. */
function utf32(b: Uint8Array, little: boolean): string {
  let out = '';
  for (let i = 0; i + 4 <= b.length; i += 4) {
    const v = little ? (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0 : ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
    out += v > 0x10ffff || (v >= 0xd800 && v <= 0xdfff) ? '\ufffd' : String.fromCodePoint(v);
  }
  return out;
}

/** Bytes as a string in an encoding, loosely: what does not decode becomes U+FFFD, and 8-bit text reads as Latin-1. */
export function looseText(b: Uint8Array, encoding: TextEncoding | 'ebcdic'): string {
  const buf = Buffer.from(b.buffer, b.byteOffset, b.byteLength);
  switch (encoding) {
    case 'utf-8':
      return buf.toString('utf8');
    case 'utf-16le':
      return buf.subarray(0, buf.length & ~1).toString('utf16le');
    case 'utf-16be':
      return Buffer.from(buf.subarray(0, buf.length & ~1))
        .swap16()
        .toString('utf16le');
    case 'utf-32le':
      return utf32(b, true);
    case 'utf-32be':
      return utf32(b, false);
    default:
      return buf.toString('latin1');
  }
}

/** True for a control character text may hold: tab, line feed, form feed and carriage return. */
export const allowedControl = (c: number) => c === 0x09 || c === 0x0a || c === 0x0c || c === 0x0d;
/** C0 controls, DEL and C1 controls, as code points. */
export const isControl = (c: number) => c < 0x20 || (c >= 0x7f && c <= 0x9f);

/**
 * Whether the start of a file is text, and in what encoding. A byte order mark names UTF-8, UTF-16 or UTF-32, and
 * without one the bytes must be UTF-8. Either way they must decode, and hold no NUL and no control character but tab,
 * line feed, form feed and carriage return. A sequence the cut at `complete === false` splits is not held against
 * it. Bytes that are not UTF-8 and name no encoding count as 8-bit text when they hold no C0 control but those four
 * and no DEL. That is a guess, since any 8-bit encoding fits.
 */
export function textEncoding(head: Uint8Array, complete: boolean): TextEncoding | undefined {
  const bom = bomOf(head);
  if (bom) {
    const body = head.subarray(bom.bom);
    const text = strictText(body, bom.encoding, complete);
    return text !== undefined && cleanText(text) ? bom.encoding : undefined;
  }
  const text = strictText(head, 'utf-8', complete);
  if (text !== undefined) return cleanText(text) ? 'utf-8' : undefined;
  for (const b of head) if ((b < 0x20 && !allowedControl(b)) || b === 0x7f) return undefined;
  return '8-bit';
}

function cleanText(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (isControl(c) && !allowedControl(c)) return false;
  }
  return true;
}

/** Bytes as a string in a Unicode encoding, or undefined when they do not decode. A partial unit at an open end is dropped. */
function strictText(b: Uint8Array, encoding: TextEncoding, complete: boolean): string | undefined {
  if (encoding === 'utf-8' || encoding === '8-bit') {
    try {
      return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(b, { stream: !complete });
    } catch {
      return undefined;
    }
  }
  const unit = encoding === 'utf-16le' || encoding === 'utf-16be' ? 2 : 4;
  const whole = b.length - (b.length % unit);
  if (complete && whole !== b.length) return undefined;
  const body = b.subarray(0, whole);
  if (unit === 4) return checkUtf32(body, encoding === 'utf-32le') ? looseText(body, encoding) : undefined;
  const text = looseText(body, encoding);
  // Every surrogate must be half of a pair. A high one at an open end may have its pair in the next bytes.
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = text.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) i++;
      else if (!(i === text.length - 1 && !complete)) return undefined;
    } else if (c >= 0xdc00 && c <= 0xdfff) return undefined;
  }
  return text;
}

function checkUtf32(b: Uint8Array, little: boolean): boolean {
  for (let i = 0; i + 4 <= b.length; i += 4) {
    const v = little ? (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0 : ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
    if (v > 0x10ffff || (v >= 0xd800 && v <= 0xdfff)) return false;
  }
  return true;
}
