// Crafted XFA form PDFs, written from scratch. Every name and value in them is invented.

import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

export interface XfaFormOptions {
  applicant?: string;
  /** Repeated rows. About twenty fill the first page, so more flow onto a second. */
  rows?: number;
  /** A catalog without NeedsRendering and with page content: a static XFA form, which is not pure XFA. */
  staticForm?: boolean;
  /** A template outside the XFA template namespace, which pdf.js cannot lay out. */
  bareTemplate?: boolean;
  /** Encrypt with RC4, 128-bit key, revision 3, and this user password. */
  password?: string;
}

/** The text the form draws: its heading, a caption and the first row. */
export const FORM_TEXT = ['Allotment Plot Application', 'Applicant', 'Bed row 1 heirloom squash'];

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function template(bare: boolean): string {
  const ns = bare ? '' : ' xmlns="http://www.xfa.org/schema/xfa-template/3.3/"';
  return `<template${ns}>
<subform name="plotForm" layout="tb" locale="en_US">
  <pageSet>
    <pageArea name="leaf" id="leaf">
      <contentArea x="0.5in" y="0.5in" w="7.5in" h="10in"/>
      <medium stock="letter" short="8.5in" long="11in"/>
    </pageArea>
  </pageSet>
  <subform name="top" layout="position" w="7.5in" h="1.2in">
    <draw name="heading" x="0in" y="0in" w="6in" h="0.4in">
      <value><text>${FORM_TEXT[0]}</text></value>
      <font typeface="Arial" size="16pt" weight="bold"/>
    </draw>
    <field name="applicant" x="0in" y="0.6in" w="5in" h="0.35in">
      <ui><textEdit/></ui>
      <font typeface="Arial" size="10pt"/>
      <caption reserve="1.2in"><value><text>${FORM_TEXT[1]}</text></value></caption>
      <border><edge thickness="0.5pt"/></border>
    </field>
  </subform>
  <subform name="row" layout="lr-tb" w="7.5in">
    <occur min="0" max="-1"/>
    <field name="bed" w="5in" h="0.45in"><ui><textEdit/></ui><border><edge thickness="0.5pt"/></border></field>
    <field name="size" w="2.5in" h="0.45in"><ui><textEdit/></ui><border><edge thickness="0.5pt"/></border></field>
  </subform>
</subform>
</template>`;
}

function datasets(o: XfaFormOptions): string {
  const rows: string[] = [];
  for (let i = 1; i <= (o.rows ?? 3); i++) rows.push(`<row><bed>Bed row ${i} heirloom squash</bed><size>${i * 4} sq ft</size></row>`);
  return `<xfa:datasets xmlns:xfa="http://www.xfa.org/schema/xfa-data/1.0/"><xfa:data><plotForm><top><applicant>${esc(o.applicant ?? 'Rowan Thistlewood')}</applicant></top>${rows.join('')}</plotForm></xfa:data></xfa:datasets>`;
}

// RC4 with a 128-bit key, revision 3 of the standard security handler (ISO 32000-1, 7.6.3).
const PAD = Buffer.from('28bf4e5e4e758a4164004e56fffa01082e2e00b6d0683e802f0ca9fe6453697a', 'hex');
const ID = Buffer.from('7c1d2e3f405162738495a6b7c8d9eaf1', 'hex');
const md5 = (...parts: Buffer[]) => createHash('md5').update(Buffer.concat(parts)).digest();
const padded = (pw: string) => Buffer.concat([Buffer.from(pw, 'latin1'), PAD]).subarray(0, 32);

function rc4(key: Buffer, data: Buffer): Buffer {
  const s = Array.from({ length: 256 }, (_, i) => i);
  for (let i = 0, j = 0; i < 256; i++) {
    j = (j + s[i] + key[i % key.length]) & 255;
    [s[i], s[j]] = [s[j], s[i]];
  }
  const out = Buffer.alloc(data.length);
  for (let k = 0, a = 0, b = 0; k < data.length; k++) {
    a = (a + 1) & 255;
    b = (b + s[a]) & 255;
    [s[a], s[b]] = [s[b], s[a]];
    out[k] = data[k] ^ s[(s[a] + s[b]) & 255];
  }
  return out;
}

const rounds = (key: Buffer, data: Buffer) => {
  let out = rc4(key, data);
  for (let i = 1; i <= 19; i++) out = rc4(Buffer.from(key.map(b => b ^ i)), out);
  return out;
};

function rc4Handler(user: string) {
  let ownerKey = md5(padded(`${user}-owner`));
  for (let i = 0; i < 50; i++) ownerKey = md5(ownerKey);
  const o = rounds(ownerKey, padded(user));
  const p = Buffer.alloc(4);
  p.writeInt32LE(-3904);
  let key = md5(padded(user), o, p, ID);
  for (let i = 0; i < 50; i++) key = md5(key);
  const u = Buffer.concat([rounds(key, md5(PAD, ID)), Buffer.alloc(16)]);
  const objectKey = (num: number) => md5(key, Buffer.from([num & 255, (num >> 8) & 255, (num >> 16) & 255, 0, 0])).subarray(0, 16);
  return {
    dict: `<</Filter /Standard /V 2 /R 3 /Length 128 /P -3904 /O <${o.toString('hex')}> /U <${u.toString('hex')}>>>`,
    encrypt: (num: number, data: Buffer) => rc4(objectKey(num), data),
  };
}

/** A form PDF with an XFA form and one placeholder page; a dynamic form unless `staticForm` is set. */
export function makeXfaForm(o: XfaFormOptions = {}): Buffer {
  const handler = o.password === undefined ? undefined : rc4Handler(o.password);
  const str = (num: number, s: string) => (handler ? `<${handler.encrypt(num, Buffer.from(s, 'latin1')).toString('hex')}>` : `(${s})`);
  const stm = (num: number, dict: string, data: Buffer) => {
    const d = handler ? handler.encrypt(num, data) : data;
    return Buffer.concat([Buffer.from(`<<${dict} /Length ${d.length}>>\nstream\n`, 'latin1'), d, Buffer.from('\nendstream', 'latin1')]);
  };
  const page = o.staticForm ? 'BT /F1 12 Tf 72 700 Td (Allotment Plot Application, printed page) Tj ET' : 'BT /F1 18 Tf 72 700 Td (Please wait while the form loads.) Tj ET';
  const bodies: Buffer[] = [
    Buffer.from(`<</Type /Catalog /Pages 2 0 R /AcroForm 5 0 R${o.staticForm ? '' : ' /NeedsRendering true'}>>`, 'latin1'),
    Buffer.from('<</Type /Pages /Kids [3 0 R] /Count 1>>', 'latin1'),
    Buffer.from('<</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources <</Font <</F1 4 0 R>>>> /Contents 6 0 R>>', 'latin1'),
    Buffer.from('<</Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding>>', 'latin1'),
    // pdf.js measures XFA text with the fonts in the form's default resources, so the form lists one.
    Buffer.from(
      `<</Fields [] /DR <</Font <</ArialRegular 11 0 R>>>> /XFA [${str(5, 'preamble')} 7 0 R ${str(5, 'template')} 8 0 R ${str(5, 'datasets')} 9 0 R ${str(5, 'postamble')} 10 0 R]>>`,
      'latin1',
    ),
    stm(6, '', Buffer.from(page, 'latin1')),
    stm(7, '', Buffer.from('<?xml version="1.0" encoding="UTF-8"?><xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">', 'utf8')),
    stm(8, ' /Filter /FlateDecode', deflateSync(Buffer.from(template(o.bareTemplate === true), 'utf8'))),
    stm(9, '', Buffer.from(datasets(o), 'utf8')),
    stm(10, '', Buffer.from('</xdp:xdp>', 'utf8')),
    Buffer.from('<</Type /Font /Subtype /TrueType /BaseFont /Arial /Encoding /WinAnsiEncoding /FontDescriptor 12 0 R>>', 'latin1'),
    Buffer.from(
      `<</Type /FontDescriptor /FontName /Arial /FontFamily ${str(12, 'Arial')} /Flags 32 /ItalicAngle 0 /FontBBox [-665 -325 2000 1006] /Ascent 905 /Descent -212 /CapHeight 716 /StemV 80>>`,
      'latin1',
    ),
  ];
  if (handler) bodies.push(Buffer.from(handler.dict, 'latin1'));
  const chunks: Buffer[] = [Buffer.from('%PDF-1.7\n%\xe2\xe3\xcf\xd3\n', 'latin1')];
  let offset = chunks[0].length;
  const offsets: number[] = [];
  bodies.forEach((b, i) => {
    offsets.push(offset);
    const body = Buffer.concat([Buffer.from(`${i + 1} 0 obj\n`, 'latin1'), b, Buffer.from('\nendobj\n', 'latin1')]);
    chunks.push(body);
    offset += body.length;
  });
  let xref = `xref\n0 ${bodies.length + 1}\n0000000000 65535 f \n`;
  for (const at of offsets) xref += `${String(at).padStart(10, '0')} 00000 n \n`;
  const encryption = handler ? ` /Encrypt ${bodies.length} 0 R /ID [<${ID.toString('hex')}> <${ID.toString('hex')}>]` : '';
  chunks.push(Buffer.from(`${xref}trailer\n<</Size ${bodies.length + 1} /Root 1 0 R${encryption}>>\nstartxref\n${offset}\n%%EOF\n`, 'latin1'));
  return Buffer.concat(chunks);
}

/**
 * The text a PDF draws with hex strings, which is how xfa-flatten writes it, from every stream that inflates, with the
 * whitespace taken out so that line breaks do not matter.
 */
export function drawnText(pdf: Uint8Array): string {
  const raw = Buffer.from(pdf).toString('latin1');
  let text = '';
  for (const m of raw.matchAll(/stream\r?\n/g)) {
    const start = (m.index ?? 0) + m[0].length;
    const end = raw.indexOf('endstream', start);
    if (end < 0) continue;
    let data: Buffer;
    try {
      data = inflateSync(Buffer.from(raw.slice(start, end), 'latin1'));
    } catch {
      continue;
    }
    for (const t of data.toString('latin1').matchAll(/<([0-9a-fA-F]*)>\s*Tj/g)) text += Buffer.from(t[1], 'hex').toString('latin1');
  }
  return text.replace(/\s+/g, '');
}
