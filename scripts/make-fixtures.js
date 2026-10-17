// Regenerates the test fixtures in test/fixtures. Run it with `node scripts/make-fixtures.js`. It needs no build and
// no other tool. Every file is written here from scratch, with fixed salts, keys and IVs, so a rerun on the same Node
// writes the same bytes. The outputs are committed, and the tests read them and test/fixtures/manifest.json.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const B = s => Buffer.from(s, 'latin1');
const dir = path.join(__dirname, '..', 'test', 'fixtures');

// ---------------------------------------------------------------------------------------------------------------
// Revision 6 of the PDF standard security handler, ISO 32000-2 Algorithms 2.B, 8, 9 and 10, with fixed salts and a
// fixed file key. The same code writes pdf-defuse's encrypted fixtures.

const sha = (alg, ...parts) => crypto.createHash(alg).update(Buffer.concat(parts)).digest();
function hash2B(password, salt, udata) {
  let k = sha('sha256', password, salt, udata);
  let e = Buffer.alloc(0);
  for (let round = 0; round < 64 || e[e.length - 1] > round - 32; round++) {
    const k1 = Buffer.concat(new Array(64).fill(Buffer.concat([password, k, udata])));
    const c = crypto.createCipheriv('aes-128-cbc', k.subarray(0, 16), k.subarray(16, 32));
    c.setAutoPadding(false);
    e = Buffer.concat([c.update(k1), c.final()]);
    let sum = 0;
    for (let i = 0; i < 16; i++) sum += e[i];
    k = sha(['sha256', 'sha384', 'sha512'][sum % 3], e);
  }
  return k.subarray(0, 32);
}
function aes256Raw(key, data, mode) {
  const c = crypto.createCipheriv(mode, key, mode === 'aes-256-ecb' ? null : Buffer.alloc(16));
  c.setAutoPadding(false);
  return Buffer.concat([c.update(data), c.final()]);
}
const FILE_KEY = Buffer.alloc(32, 0x5a);
const SALTS = { uv: B('uvsaltuv'), uk: B('uksaltuk'), ov: B('ovsaltov'), ok: B('oksaltok') };
const hex = b => `<${b.toString('hex')}>`;
function r6Keys(user, owner) {
  const U = Buffer.concat([hash2B(user, SALTS.uv, Buffer.alloc(0)), SALTS.uv, SALTS.uk]);
  const UE = aes256Raw(hash2B(user, SALTS.uk, Buffer.alloc(0)), FILE_KEY, 'aes-256-cbc');
  const O = Buffer.concat([hash2B(owner, SALTS.ov, U), SALTS.ov, SALTS.ok]);
  const OE = aes256Raw(hash2B(owner, SALTS.ok, U), FILE_KEY, 'aes-256-cbc');
  const perms = Buffer.concat([Buffer.from([0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), B('Tadbfxtr')]);
  const filters = '/CF << /StdCF << /AuthEvent /DocOpen /CFM /AESV3 /Length 32 >> >> /StmF /StdCF /StrF /StdCF';
  return `<< /Filter /Standard /V 5 /R 6 /Length 256 ${filters} /O ${hex(O)} /U ${hex(U)} /OE ${hex(OE)} /UE ${hex(UE)} /P -4 /Perms ${hex(aes256Raw(FILE_KEY, perms, 'aes-256-ecb'))} >>`;
}
/** AESV3 encryption of one string or stream with the file key, behind a fixed IV. */
function aesv3(data) {
  const c = crypto.createCipheriv('aes-256-cbc', FILE_KEY, Buffer.alloc(16, 0x24));
  return Buffer.concat([Buffer.alloc(16, 0x24), c.update(data), c.final()]);
}

// ---------------------------------------------------------------------------------------------------------------
// PDFs with attached files.

/**
 * A one-page PDF. Each attachment is { name, bytes }, stored deflated. `js` adds an open action that runs a script.
 * `pad` adds that many spaces to the page content. `info` adds an Info dictionary. `password` encrypts the file at
 * revision 6 with that user password.
 */
function pdf({ attachments = [], js = false, pad = 0, info = false, password } = {}) {
  const str = s => (password === undefined ? `(${s.replace(/[()\\]/g, c => `\\${c}`)})` : hex(aesv3(B(s))));
  const data = d => (password === undefined ? d : aesv3(d));
  const objects = [];
  const add = body => objects.push(body);
  const names = attachments.map((a, i) => `${str(a.name)} ${6 + 2 * i} 0 R`).join(' ');
  add(
    `<< /Type /Catalog /Pages 2 0 R${attachments.length ? ` /Names << /EmbeddedFiles << /Names [${names}] >> >>` : ''}${js ? ` /OpenAction << /S /JavaScript /JS ${str('app.launchURL("https://example.invalid/")')} >>` : ''} >>`,
  );
  add('<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>');
  add('<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>');
  add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  add({ dict: '<< >>', stream: data(B(`BT /F1 24 Tf 72 720 Td (Hello) Tj ET${' '.repeat(pad)}`)) });
  for (const a of attachments) {
    add(`<< /Type /Filespec /F ${str(a.name)} /UF ${str(a.name)} /EF << /F ${objects.length + 2} 0 R >> >>`);
    add({ dict: '<< /Type /EmbeddedFile /Filter /FlateDecode >>', stream: data(zlib.deflateSync(a.bytes)) });
  }
  const infoRef = info ? add(`<< /Title ${str('Report')} /Author ${str('Someone')} >>`) : undefined;
  const encrypt = password === undefined ? undefined : add(r6Keys(B(password), B(`${password} owner`)));
  const parts = [B('%PDF-1.7\n%\xe2\xe3\xcf\xd3\n')];
  let offset = parts[0].length;
  const offsets = [];
  objects.forEach((body, i) => {
    const bytes =
      typeof body === 'string'
        ? B(`${i + 1} 0 obj\n${body}\nendobj\n`)
        : Buffer.concat([B(`${i + 1} 0 obj\n${body.dict.replace(/>>$/, `/Length ${body.stream.length} >>`)}\nstream\n`), body.stream, B('\nendstream\nendobj\n')]);
    offsets.push(offset);
    parts.push(bytes);
    offset += bytes.length;
  });
  let xref = `xref\n0 ${objects.length + 1}\n0000000000 65535 f\r\n`;
  for (const o of offsets) xref += `${String(o).padStart(10, '0')} 00000 n\r\n`;
  const trailer = `/Size ${objects.length + 1} /Root 1 0 R${infoRef ? ` /Info ${infoRef} 0 R` : ''}${encrypt ? ` /Encrypt ${encrypt} 0 R /ID [<${'42'.repeat(16)}> <${'42'.repeat(16)}>]` : ''}`;
  parts.push(B(`${xref}trailer\n<< ${trailer} >>\nstartxref\n${offset}\n%%EOF\n`));
  return Buffer.concat(parts);
}

/** A PDF inside a PDF, `levels` deep. The innermost file is `inner`, and the file at level n is named level<n>.pdf. */
function nest(levels, inner) {
  let doc = inner;
  for (let n = levels; n >= 1; n--) doc = pdf({ attachments: [{ name: `level${n}.pdf`, bytes: doc }] });
  return doc;
}

// ---------------------------------------------------------------------------------------------------------------
// A PDF that holds itself. Its attached file is raw deflate data Z that inflates to the whole PDF, prefix P, then Z,
// then suffix S. The construction is Russ Cox's, from "Zip Files All The Way Down" (2010). It uses two
// instructions. Lit(n) copies the next n bytes of Z to the output, and Rep(d, n) repeats n bytes from d back in the
// output. Each instruction takes the same number of bytes, u.

class Bits {
  constructor() {
    this.bytes = [];
    this.cur = 0;
    this.n = 0;
  }
  /** Writes `count` bits of `value`, least significant first. */
  put(value, count) {
    for (let i = 0; i < count; i++) {
      this.cur |= ((value >> i) & 1) << this.n;
      if (++this.n === 8) {
        this.bytes.push(this.cur);
        this.cur = 0;
        this.n = 0;
      }
    }
  }
  /** Writes a Huffman code, most significant bit first. */
  code(value, count) {
    for (let i = count - 1; i >= 0; i--) this.put((value >> i) & 1, 1);
  }
  done() {
    if (this.n) throw new Error('The instruction does not end on a byte boundary');
    return Buffer.from(this.bytes);
  }
}

const LEN_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const lengthCode = n => (n === 258 ? 28 : LEN_BASE.findLastIndex((b, i) => i < 28 && n >= b));
const distCode = d => DIST_BASE.findLastIndex(b => d >= b);
/** Writes a literal or length symbol with the fixed Huffman code. */
function symbol(bits, v) {
  if (v <= 143) bits.code(0x30 + v, 8);
  else if (v <= 255) bits.code(0x190 + v - 144, 9);
  else if (v <= 279) bits.code(v - 256, 7);
  else bits.code(0xc0 + v - 280, 8);
}
const symbolBits = v => (v <= 143 ? 8 : v <= 255 ? 9 : v <= 279 ? 7 : 8);
const copyBits = (n, d) => symbolBits(257 + lengthCode(n)) + LEN_EXTRA[lengthCode(n)] + 5 + DIST_EXTRA[distCode(d)];

/** An empty block with fixed codes, which pads an instruction by 10 bits. */
function emptyFixed(bits) {
  bits.put(0, 1);
  bits.put(1, 2);
  symbol(bits, 256);
}
/** The header of a stored block of `len` bytes, which ends on a byte boundary. */
function storedHeader(bits, len) {
  bits.put(0, 3);
  if (bits.n) bits.put(0, 8 - bits.n);
  bits.put(len, 16);
  bits.put(~len & 0xffff, 16);
}
const litSize = pad => Math.ceil((10 * pad + 3) / 8) + 4;
const repSize = (copied, pad) => Math.ceil((3 + copied + 7 + 10 * pad + 3) / 8) + 4;

/** Lit(n) in exactly u bytes: empty fixed blocks, then a stored block header. */
function lit(n, u) {
  for (let pad = 0; pad <= 8; pad++) {
    if (litSize(pad) !== u) continue;
    const b = new Bits();
    for (let i = 0; i < pad; i++) emptyFixed(b);
    storedHeader(b, n);
    return b.done();
  }
  return undefined;
}

/**
 * Rep(n, n) in exactly u bytes: a fixed block that copies n bytes from n back, in chunks of at most 258, then empty
 * fixed blocks, then an empty stored block that ends on a byte boundary.
 */
function rep(n, u) {
  const fewest = Math.ceil(n / 258);
  for (let m = fewest; m <= fewest + 4; m++) {
    const chunks = Array.from({ length: m }, (_, i) => Math.floor(n / m) + (i < n % m ? 1 : 0));
    if (chunks.some(c => c < 3 || c > 258)) continue;
    const copied = chunks.reduce((s, c) => s + copyBits(c, n), 0);
    for (let pad = 0; pad <= 8; pad++) {
      if (repSize(copied, pad) !== u) continue;
      const b = new Bits();
      b.put(0, 1);
      b.put(1, 2);
      for (const c of chunks) {
        symbol(b, 257 + lengthCode(c));
        b.put(c - LEN_BASE[lengthCode(c)], LEN_EXTRA[lengthCode(c)]);
        b.code(distCode(n), 5);
        b.put(n - DIST_BASE[distCode(n)], DIST_EXTRA[distCode(n)]);
      }
      symbol(b, 256);
      for (let i = 0; i < pad; i++) emptyFixed(b);
      storedHeader(b, 0);
      return b.done();
    }
  }
  return undefined;
}

/** Raw deflate data Z that inflates to P + Z + S. No block is final, so it ends the way truncated data does. */
function quine(P, S) {
  const p = P.length;
  const s = S.length;
  for (let u = 5; u < 64; u++) {
    const ops = [lit(p + u, u), rep(p + u, u), lit(u, u), lit(4 * u, u), rep(4 * u, u), lit(0, u), lit(s + u, u), rep(s + u, u)];
    if (!ops.every(x => x && x.length === u)) continue;
    const [Lp, Rp, L1, L4, R4, L0, Ls, Rs] = ops;
    return Buffer.concat([Lp, P, Lp, Rp, L1, Rp, L1, L1, L4, Rp, L1, L1, L4, R4, L4, R4, L4, R4, L4, R4, L4, R4, L0, L0, Ls, R4, L0, L0, Ls, Rs, S, Rs]);
  }
  throw new Error('No instruction size fits');
}

/** A PDF whose one attached file, loop.pdf, is the PDF itself. */
function loopPdf() {
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(loop.pdf) 4 0 R] >> >> >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>',
    '<< /Type /Page /Parent 2 0 R >>',
    '<< /Type /Filespec /F (loop.pdf) /UF (loop.pdf) /EF << /F 5 0 R >> >>',
  ];
  // The prefix holds the length of Z, and Z's length depends on the prefix, so this runs until the two agree.
  let length = 0;
  for (let i = 0; i < 10; i++) {
    let head = '%PDF-1.7\n';
    const offsets = [];
    objects.forEach((body, n) => {
      offsets.push(head.length);
      head += `${n + 1} 0 obj\n${body}\nendobj\n`;
    });
    offsets.push(head.length);
    head += `5 0 obj\n<< /Type /EmbeddedFile /Filter /FlateDecode /Length ${length} >>\nstream\n`;
    const end = '\nendstream\nendobj\n';
    let xref = 'xref\n0 6\n0000000000 65535 f\r\n';
    for (const o of offsets) xref += `${String(o).padStart(10, '0')} 00000 n\r\n`;
    const tail = `${end}${xref}trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n${head.length + length + end.length}\n%%EOF\n`;
    const z = quine(B(head), B(tail));
    if (z.length === length) {
      const file = Buffer.concat([B(head), z, B(tail)]);
      if (!zlib.inflateRawSync(z, { finishFlush: zlib.constants.Z_SYNC_FLUSH }).equals(file)) throw new Error('loop.pdf does not hold itself');
      return file;
    }
    length = z.length;
  }
  throw new Error('The length of loop.pdf did not settle');
}

// ---------------------------------------------------------------------------------------------------------------
// Office files. ZIP entries are stored, not deflated, so their bytes do not depend on the zlib a Node version has.

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** A ZIP archive of stored entries, given as [name, bytes], with every date at 1980-01-01. */
function zip(entries) {
  const local = [];
  const central = [];
  let offset = 0;
  // An entry's third value, when given, is the method its headers name. The data is stored as given either way.
  for (const [name, data, method = 0] of entries) {
    const n = Buffer.from(name, 'utf8');
    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0);
    head.writeUInt16LE(20, 4);
    head.writeUInt16LE(method, 8);
    head.writeUInt16LE(0x21, 12);
    head.writeUInt32LE(crc32(data), 14);
    head.writeUInt32LE(data.length, 18);
    head.writeUInt32LE(data.length, 22);
    head.writeUInt16LE(n.length, 26);
    const record = Buffer.alloc(46);
    record.writeUInt32LE(0x02014b50, 0);
    record.writeUInt16LE(20, 4);
    record.writeUInt16LE(20, 6);
    record.writeUInt16LE(method, 10);
    record.writeUInt16LE(0x21, 14);
    record.writeUInt32LE(crc32(data), 16);
    record.writeUInt32LE(data.length, 20);
    record.writeUInt32LE(data.length, 24);
    record.writeUInt16LE(n.length, 28);
    record.writeUInt32LE(offset, 42);
    local.push(head, n, data);
    central.push(record, n);
    offset += head.length + n.length + data.length;
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

const PKG_REL = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
/**
 * A one-paragraph .docx. Each embed is { name, bytes, type }, a part under word/embeddings that a package
 * relationship of the document reaches, the way Word links an embedded package. Each media entry is a picture under
 * word/media that an image relationship reaches.
 */
function docx({ embeds = [], media = [] } = {}) {
  const xml = s => B(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n${s}`);
  const overrides =
    embeds.map(e => `<Override PartName="/word/embeddings/${e.name}" ContentType="${e.type}"/>`).join('') +
    media.map(m => `<Override PartName="/word/media/${m.name}" ContentType="${m.type}"/>`).join('');
  const types = `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>${overrides}</Types>`;
  const rels = `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="${PKG_REL}/officeDocument" Target="word/document.xml"/></Relationships>`;
  const docRels = `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${embeds.map((e, i) => `<Relationship Id="rId${i + 1}" Type="${PKG_REL}/package" Target="embeddings/${e.name}"/>`).join('')}${media.map((m, i) => `<Relationship Id="rIdImage${i + 1}" Type="${PKG_REL}/image" Target="media/${m.name}"/>`).join('')}</Relationships>`;
  const doc = '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>';
  return zip([
    ['[Content_Types].xml', xml(types)],
    ['_rels/.rels', xml(rels)],
    ['word/document.xml', xml(doc)],
    ['word/_rels/document.xml.rels', xml(docRels)],
    ...embeds.map(e => [`word/embeddings/${e.name}`, e.bytes]),
    ...media.map(m => [`word/media/${m.name}`, m.bytes]),
  ]);
}
const DOCX_TYPE = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';

/**
 * A compound file (MS-CFB) version 3 with 512-byte sectors, holding a tree of { name, data } streams and
 * { name, children } storages. Streams under 4096 bytes go in the mini stream. Ported from office-defuse's fixture
 * script, without its options for breaking the format.
 */
function cfb(rootChildren, rootClsid) {
  const SS = 512;
  const END = 0xfffffffe;
  const FREE = 0xffffffff;
  const NONE = 0xffffffff;
  const entries = [{ kind: 5, name: 'Root Entry', left: NONE, right: NONE, child: NONE }];
  const tree = ids => {
    if (!ids.length) return NONE;
    const mid = ids.length >> 1;
    entries[ids[mid]].left = tree(ids.slice(0, mid));
    entries[ids[mid]].right = tree(ids.slice(mid + 1));
    return ids[mid];
  };
  const build = (index, children) => {
    const ids = children.map(c => entries.push({ kind: c.children ? 1 : 2, name: c.name, data: c.data, left: NONE, right: NONE, child: NONE }) - 1);
    for (let k = 0; k < children.length; k++) if (children[k].children) build(ids[k], children[k].children);
    ids.sort((a, b) => entries[a].name.length - entries[b].name.length || (entries[a].name.toUpperCase() < entries[b].name.toUpperCase() ? -1 : 1));
    entries[index].child = tree(ids);
  };
  build(0, rootChildren);
  let mini = Buffer.alloc(0);
  const miniFat = [];
  for (const e of entries) {
    if (e.kind !== 2 || e.data.length === 0 || e.data.length >= 4096) continue;
    const n = Math.ceil(e.data.length / 64);
    e.start = mini.length / 64;
    for (let k = 1; k < n; k++) miniFat.push(e.start + k);
    miniFat.push(END);
    mini = Buffer.concat([mini, e.data, Buffer.alloc(n * 64 - e.data.length)]);
  }
  const big = entries.filter(e => e.kind === 2 && e.data.length >= 4096);
  const dirN = Math.ceil((entries.length * 128) / SS);
  const miniFatN = Math.ceil((miniFat.length * 4) / SS);
  const miniN = Math.ceil(mini.length / SS);
  const dataN = big.reduce((s, e) => s + Math.ceil(e.data.length / SS), 0);
  let fatN = 1;
  while (fatN * 128 < fatN + dirN + miniFatN + miniN + dataN) fatN++;
  if (fatN > 109) throw new Error('The compound file needs a DIFAT, which this writer does not write');
  let pos = fatN;
  const take = n => Array.from({ length: n }, () => pos++);
  const fatSectors = Array.from({ length: fatN }, (_, k) => k);
  const dirSectors = take(dirN);
  const miniFatSectors = take(miniFatN);
  const miniSectors = take(miniN);
  for (const e of big) e.sectors = take(Math.ceil(e.data.length / SS));
  const fat = new Array(fatN * 128).fill(FREE);
  for (const s of fatSectors) fat[s] = 0xfffffffd;
  const chain = list => {
    for (let k = 0; k < list.length; k++) fat[list[k]] = k + 1 < list.length ? list[k + 1] : END;
  };
  for (const c of [dirSectors, miniFatSectors, miniSectors, ...big.map(e => e.sectors)]) chain(c);
  const sectors = new Map();
  const put = (list, data) => {
    for (let k = 0; k < list.length; k++) sectors.set(list[k], Buffer.concat([data.subarray(k * SS, (k + 1) * SS), Buffer.alloc(SS)]).subarray(0, SS));
  };
  put(miniSectors, mini);
  for (const e of big) put(e.sectors, e.data);
  const words = list => {
    const b = Buffer.alloc(list.length * 4);
    for (let k = 0; k < list.length; k++) b.writeUInt32LE(list[k], k * 4);
    return b;
  };
  put(miniFatSectors, words(miniFat));
  put(fatSectors, words(fat));
  const directory = Buffer.alloc(dirN * SS);
  for (let k = entries.length; k < dirN * 4; k++) {
    directory.writeUInt32LE(NONE, k * 128 + 68);
    directory.writeUInt32LE(NONE, k * 128 + 72);
    directory.writeUInt32LE(NONE, k * 128 + 76);
  }
  entries.forEach((e, k) => {
    const d = directory.subarray(k * 128, (k + 1) * 128);
    const name = Buffer.from(e.name, 'utf16le');
    name.copy(d, 0);
    // A class id such as 000C1084-0000-0000-C000-000000000046, its first three fields little-endian.
    if (k === 0 && rootClsid) {
      const h = rootClsid.replace(/-/g, '');
      const le = (from, n) => Buffer.from(h.slice(from, from + 2 * n), 'hex').reverse();
      Buffer.concat([le(0, 4), le(8, 2), le(12, 2), Buffer.from(h.slice(16), 'hex')]).copy(d, 80);
    }
    d.writeUInt16LE(name.length + 2, 64);
    d[66] = e.kind;
    d[67] = 1;
    d.writeUInt32LE(e.left, 68);
    d.writeUInt32LE(e.right, 72);
    d.writeUInt32LE(e.child, 76);
    const [start, size] =
      e.kind === 5 ? [mini.length ? miniSectors[0] : END, mini.length] : e.kind === 1 ? [0, 0] : e.sectors ? [e.sectors[0], e.data.length] : [e.data.length ? e.start : END, e.data.length];
    d.writeUInt32LE(start, 116);
    d.writeUInt32LE(size, 120);
  });
  put(dirSectors, directory);
  const header = Buffer.alloc(SS);
  Buffer.from('d0cf11e0a1b11ae1', 'hex').copy(header, 0);
  header.writeUInt16LE(0x3e, 24);
  header.writeUInt16LE(3, 26);
  header.writeUInt16LE(0xfffe, 28);
  header.writeUInt16LE(9, 30);
  header.writeUInt16LE(6, 32);
  header.writeUInt32LE(fatN, 44);
  header.writeUInt32LE(dirSectors[0], 48);
  header.writeUInt32LE(4096, 56);
  header.writeUInt32LE(miniFatN ? miniFatSectors[0] : END, 60);
  header.writeUInt32LE(miniFatN, 64);
  header.writeUInt32LE(END, 68);
  for (let k = 0; k < 109; k++) header.writeUInt32LE(k < fatN ? fatSectors[k] : FREE, 76 + 4 * k);
  return Buffer.concat([header, ...Array.from({ length: pos }, (_, s) => sectors.get(s) ?? Buffer.alloc(SS))]);
}

/**
 * An OOXML package encrypted with Agile encryption (MS-OFFCRYPTO 2.3.4.10), AES-256-CBC and SHA-512 with fixed salts
 * and keys. Ported from office-defuse's fixture script.
 */
function agileEncrypt(pkg, password, spin = 100000) {
  const keySalt = Buffer.from(Array.from({ length: 16 }, (_, i) => i));
  const dataSalt = Buffer.from(Array.from({ length: 16 }, (_, i) => 16 + i));
  const secret = Buffer.from(Array.from({ length: 32 }, (_, i) => 32 + i));
  const verifier = Buffer.from(Array.from({ length: 16 }, (_, i) => 64 + i));
  const H = data => crypto.createHash('sha512').update(data).digest();
  const u32 = n => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n);
    return b;
  };
  const pad16 = b => Buffer.concat([b, Buffer.alloc(-b.length & 15)]);
  const cbc = (key, iv, data) => {
    const c = crypto.createCipheriv('aes-256-cbc', key, iv);
    c.setAutoPadding(false);
    return Buffer.concat([c.update(data), c.final()]);
  };
  let h = H(Buffer.concat([keySalt, Buffer.from(password, 'utf16le')]));
  for (let i = 0; i < spin; i++) h = H(Buffer.concat([u32(i), h]));
  const derive = block => H(Buffer.concat([h, Buffer.from(block, 'hex')])).subarray(0, 32);
  const encInput = cbc(derive('fea7d2763b4b9e79'), keySalt, verifier);
  const encValue = cbc(derive('d7aa0f6d3061344e'), keySalt, pad16(H(verifier)));
  const encKey = cbc(derive('146e0be7abacd0d6'), keySalt, secret);
  const size = Buffer.alloc(8);
  size.writeUInt32LE(pkg.length);
  const parts = [size];
  for (let k = 0; k < pkg.length; k += 4096) parts.push(cbc(secret, H(Buffer.concat([dataSalt, u32(k / 4096)])).subarray(0, 16), pad16(pkg.subarray(k, k + 4096))));
  const body = Buffer.concat(parts);
  // The integrity check Office writes: an HMAC key, and the HMAC of the encrypted package, each encrypted.
  const hmacKey = Buffer.from(Array.from({ length: 64 }, (_, i) => 128 + i));
  const hmacValue = crypto.createHmac('sha512', hmacKey).update(body).digest();
  const encHmacKey = cbc(secret, H(Buffer.concat([dataSalt, Buffer.from('5fb2ad010cb9e1f6', 'hex')])).subarray(0, 16), hmacKey);
  const encHmacValue = cbc(secret, H(Buffer.concat([dataSalt, Buffer.from('a0677f02b22c8433', 'hex')])).subarray(0, 16), hmacValue);
  const b64 = b => b.toString('base64');
  const xml =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption" ' +
    'xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password"><keyData saltSize="16" blockSize="16" keyBits="256" hashSize="64" ' +
    `cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="${b64(dataSalt)}"/><dataIntegrity encryptedHmacKey="${b64(encHmacKey)}" encryptedHmacValue="${b64(encHmacValue)}"/><keyEncryptors><keyEncryptor ` +
    `uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password"><p:encryptedKey spinCount="${spin}" saltSize="16" blockSize="16" keyBits="256" ` +
    `hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="${b64(keySalt)}" encryptedVerifierHashInput="${b64(encInput)}" ` +
    `encryptedVerifierHashValue="${b64(encValue)}" encryptedKeyValue="${b64(encKey)}"/></keyEncryptor></keyEncryptors></encryption>`;
  const version = Buffer.alloc(8);
  version.writeUInt16LE(4, 0);
  version.writeUInt16LE(4, 2);
  version.writeUInt32LE(0x40, 4);
  const spacesVersion = Buffer.concat([Buffer.from([0x3c, 0, 0, 0]), Buffer.from('Microsoft.Container.DataSpaces', 'utf16le'), Buffer.from([1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0])]);
  return cfb([
    { name: 'EncryptionInfo', data: Buffer.concat([version, B(xml)]) },
    { name: 'EncryptedPackage', data: body },
    { name: '\x06DataSpaces', children: [{ name: 'Version', data: spacesVersion }] },
  ]);
}

// ---------------------------------------------------------------------------------------------------------------
// Images. Their compressed data is written as stored deflate blocks, so the bytes do not depend on a zlib version.

/** zlib data that holds `data` in stored blocks. */
function zlibStored(data) {
  const parts = [Buffer.from([0x78, 0x01])];
  for (let at = 0; ; at += 65535) {
    const chunk = data.subarray(at, at + 65535);
    const last = at + 65535 >= data.length;
    const head = Buffer.alloc(5);
    head[0] = last ? 1 : 0;
    head.writeUInt16LE(chunk.length, 1);
    head.writeUInt16LE(~chunk.length & 0xffff, 3);
    parts.push(head, chunk);
    if (last) break;
  }
  let a = 1;
  let b = 0;
  for (const x of data) {
    a = (a + x) % 65521;
    b = (b + a) % 65521;
  }
  const adler = Buffer.alloc(4);
  adler.writeUInt32BE(((b << 16) | a) >>> 0);
  return Buffer.concat([...parts, adler]);
}

/** A 2x2 grayscale PNG, with a tEXt chunk when `text` is given. */
function png({ text } = {}) {
  const chunk = (type, data) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const body = Buffer.concat([B(type), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(body));
    return Buffer.concat([len, body, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(2, 0);
  ihdr.writeUInt32BE(2, 4);
  ihdr[8] = 8;
  return Buffer.concat([
    B('\x89PNG\r\n\x1a\n'),
    chunk('IHDR', ihdr),
    ...(text ? [chunk('tEXt', B(`Comment\0${text}`))] : []),
    chunk('IDAT', zlibStored(Buffer.from([0, 0x40, 0x80, 0, 0xc0, 0xff]))),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

const segment = (marker, data) => {
  const head = Buffer.from([0xff, marker, 0, 0]);
  head.writeUInt16BE(data.length + 2, 2);
  return Buffer.concat([head, data]);
};

/** EXIF data with the camera's make in IFD0 and `thumbnail`, a JPEG file, in IFD1. */
function exif(thumbnail) {
  const tiff = Buffer.alloc(64);
  tiff.write('II', 0, 'latin1');
  tiff.writeUInt16LE(42, 2);
  tiff.writeUInt32LE(8, 4);
  // IFD0 at 8: Make, ASCII, 7 bytes at 26. The next IFD is at 34.
  tiff.writeUInt16LE(1, 8);
  tiff.writeUInt16LE(0x010f, 10);
  tiff.writeUInt16LE(2, 12);
  tiff.writeUInt32LE(7, 14);
  tiff.writeUInt32LE(26, 18);
  tiff.writeUInt32LE(34, 22);
  tiff.write('Camera\0', 26, 'latin1');
  // IFD1 at 34: the thumbnail's offset and length. It ends at 64, where the thumbnail starts.
  tiff.writeUInt16LE(2, 34);
  tiff.writeUInt16LE(0x0201, 36);
  tiff.writeUInt16LE(4, 38);
  tiff.writeUInt32LE(1, 40);
  tiff.writeUInt32LE(64, 44);
  tiff.writeUInt16LE(0x0202, 48);
  tiff.writeUInt16LE(4, 50);
  tiff.writeUInt32LE(1, 52);
  tiff.writeUInt32LE(thumbnail.length, 56);
  tiff.writeUInt32LE(0, 60);
  return Buffer.concat([B('Exif\0\0'), tiff, thumbnail]);
}

/**
 * An 8x8 grayscale baseline JPEG of one flat block. Each Huffman table holds one code, for a DC difference of 0 and
 * for the end of the block. `comment` adds a COM segment and `thumbnail`, a JPEG file, an EXIF segment holding it.
 */
function jpeg({ comment, thumbnail, quantization } = {}) {
  const table = cls => Buffer.concat([Buffer.from([cls, 1]), Buffer.alloc(15), Buffer.from([0])]);
  // `quantization` replaces the start of the quantization table, which the decoder needs.
  const dqt = Buffer.alloc(64, 1);
  if (quantization) quantization.copy(dqt);
  return Buffer.concat([
    Buffer.from([0xff, 0xd8]),
    ...(thumbnail ? [segment(0xe1, exif(thumbnail))] : []),
    ...(comment ? [segment(0xfe, B(comment))] : []),
    segment(0xdb, Buffer.concat([Buffer.from([0]), dqt])),
    segment(0xc0, Buffer.from([8, 0, 8, 0, 8, 1, 1, 0x11, 0])),
    segment(0xc4, table(0x00)),
    segment(0xc4, table(0x10)),
    segment(0xda, Buffer.from([1, 1, 0, 0, 63, 0])),
    // DC code 0 for a difference of 0, then AC code 0 for the end of the block, padded with ones.
    Buffer.from([0x3f, 0xff, 0xd9]),
  ]);
}

// ---------------------------------------------------------------------------------------------------------------
// JPEG 2000 and JPEG XL. Big-endian boxes, as ISO/IEC 15444-1 Annex I and ISO/IEC 18181-2 lay them out.

const u16be = n => Buffer.from([n >> 8, n & 0xff]);
const u32be = n => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
};
const box = (type, data) => Buffer.concat([u32be(8 + data.length), B(type), data]);
const j2kMarker = (code, data) => Buffer.concat([u16be(code), u16be(data.length + 2), data]);

/**
 * A JPEG 2000 codestream of one 8x8 grayscale tile with no decomposition levels: SOC, SIZ, COD, QCD, a comment when
 * `comment` is given, one tile-part of two bytes of data, and EOC. The data is not real entropy-coded data; readers
 * that check structure do not decode it.
 */
function codestream({ comment } = {}) {
  const siz = Buffer.concat([u16be(0), u32be(8), u32be(8), u32be(0), u32be(0), u32be(8), u32be(8), u32be(0), u32be(0), u16be(1), Buffer.from([7, 1, 1])]);
  const cod = Buffer.from([0, 0, 0, 1, 0, 0, 4, 4, 0, 1]);
  const qcd = Buffer.from([0x40, 0x40]);
  const data = Buffer.from([0x80, 0x80]);
  const sot = Buffer.concat([u16be(0xff90), u16be(10), u16be(0), u32be(12 + 2 + data.length), Buffer.from([0, 1])]);
  return Buffer.concat([
    u16be(0xff4f),
    j2kMarker(0xff51, siz),
    j2kMarker(0xff52, cod),
    j2kMarker(0xff5c, qcd),
    ...(comment ? [j2kMarker(0xff64, Buffer.concat([u16be(1), B(comment)]))] : []),
    sot,
    u16be(0xff93),
    data,
    u16be(0xffd9),
  ]);
}

/** A JP2 file around the codestream. `exifData`, EXIF as exif() writes it, goes in the UUID box ExifTool reads. */
function jp2({ exifData } = {}) {
  const ihdr = Buffer.concat([u32be(8), u32be(8), u16be(1), Buffer.from([7, 7, 0, 0])]);
  const colr = Buffer.concat([Buffer.from([1, 0, 0]), u32be(17)]);
  return Buffer.concat([
    box('jP  ', Buffer.from([0x0d, 0x0a, 0x87, 0x0a])),
    box('ftyp', Buffer.concat([B('jp2 '), u32be(0), B('jp2 ')])),
    box('jp2h', Buffer.concat([box('ihdr', ihdr), box('colr', colr)])),
    ...(exifData ? [box('uuid', Buffer.concat([B('JpgTiffExif->JP2'), exifData]))] : []),
    box('jp2c', codestream()),
  ]);
}

/**
 * A bare JPEG XL codestream of an 8x8 image: the signature, a size header of 8 by 8 at a 1:1 ratio and an image
 * header with every field at its default, then a few bytes. Readers that check the headers do not decode the frames.
 */
const jxlCodestream = () => Buffer.from([0xff, 0x0a, 0x41, 0x02, 0x00, 0x00, 0x00, 0x00]);

/** A JPEG XL container: the signature box, the file type box, the codestream, and a gain map holding a bare codestream. */
function jxl() {
  const gainMap = Buffer.concat([Buffer.from([0]), u16be(0), Buffer.from([0]), u32be(0), jxlCodestream()]);
  return Buffer.concat([
    Buffer.concat([u32be(12), B('JXL '), Buffer.from([0x0d, 0x0a, 0x87, 0x0a])]),
    box('ftyp', Buffer.concat([B('jxl '), u32be(0), B('jxl ')])),
    box('jxlc', jxlCodestream()),
    box('jhgm', gainMap),
  ]);
}

// ---------------------------------------------------------------------------------------------------------------
// Office files office-defuse 0.2 reads beyond the ZIP formats: XPS, flat XML, RTF and Outlook messages.

const ODF_NS =
  'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:xlink="http://www.w3.org/1999/xlink"';
const PKG_NS = 'http://schemas.microsoft.com/office/2006/xmlPackage';
const RELS_NS = 'http://schemas.openxmlformats.org/package/2006/relationships';

/** A flat OpenDocument text document with one paragraph and `picture`, a PNG held as base64. */
function flatOdf(picture) {
  return B(
    `<?xml version="1.0" encoding="UTF-8"?>\n<office:document ${ODF_NS} office:version="1.3" office:mimetype="application/vnd.oasis.opendocument.text"><office:body><office:text><text:p>Hello</text:p><draw:frame draw:name="p"><draw:image draw:mime-type="image/png"><office:binary-data>${picture.toString('base64')}</office:binary-data></draw:image></draw:frame></office:text></office:body></office:document>`,
  );
}

/** A Flat OPC Word document with one paragraph and `picture`, a PNG part an image relationship reaches. */
function flatOpc(picture) {
  const part = (name, type, body) => `<pkg:part pkg:name="${name}" pkg:contentType="${type}">${body}</pkg:part>`;
  const rels = r => `<pkg:xmlData><Relationships xmlns="${RELS_NS}">${r}</Relationships></pkg:xmlData>`;
  return B(
    `<?xml version="1.0" standalone="yes"?>\n<?mso-application progid="Word.Document"?>\n<pkg:package xmlns:pkg="${PKG_NS}">${[
      part('/_rels/.rels', 'application/vnd.openxmlformats-package.relationships+xml', rels(`<Relationship Id="rId1" Type="${PKG_REL}/officeDocument" Target="word/document.xml"/>`)),
      part(
        '/word/document.xml',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml',
        '<pkg:xmlData><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document></pkg:xmlData>',
      ),
      part('/word/_rels/document.xml.rels', 'application/vnd.openxmlformats-package.relationships+xml', rels(`<Relationship Id="rIdImage1" Type="${PKG_REL}/image" Target="media/image1.png"/>`)),
      part('/word/media/image1.png', 'image/png', `<pkg:binaryData>${picture.toString('base64')}</pkg:binaryData>`),
    ].join('')}</pkg:package>`,
  );
}

/** An XPS package of one document with one page that paints `picture`, a PNG resource. */
function xps(picture) {
  const ns = 'http://schemas.microsoft.com/xps/2005/06';
  const types =
    '<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
    '<Default Extension="fdseq" ContentType="application/vnd.ms-package.xps-fixeddocumentsequence+xml"/>' +
    '<Default Extension="fdoc" ContentType="application/vnd.ms-package.xps-fixeddocument+xml"/>' +
    '<Default Extension="fpage" ContentType="application/vnd.ms-package.xps-fixedpage+xml"/>' +
    '<Default Extension="png" ContentType="image/png"/></Types>';
  const page =
    '<Path Data="M 0,0 L 10,0 10,10 0,10 Z"><Path.Fill><ImageBrush ImageSource="/Resources/image.png" Viewbox="0,0,1,1" Viewport="0,0,10,10" ViewboxUnits="Absolute" ViewportUnits="Absolute"/></Path.Fill></Path>';
  return zip([
    ['[Content_Types].xml', B(types)],
    ['_rels/.rels', B(`<?xml version="1.0" encoding="utf-8"?><Relationships xmlns="${RELS_NS}"><Relationship Id="R0" Type="${ns}/fixedrepresentation" Target="/FixedDocSeq.fdseq"/></Relationships>`)],
    ['FixedDocSeq.fdseq', B(`<FixedDocumentSequence xmlns="${ns}"><DocumentReference Source="/Documents/1/FixedDoc.fdoc"/></FixedDocumentSequence>`)],
    ['Documents/1/FixedDoc.fdoc', B(`<FixedDocument xmlns="${ns}"><PageContent Source="Pages/1.fpage"/></FixedDocument>`)],
    ['Documents/1/Pages/1.fpage', B(`<FixedPage xmlns="${ns}" Width="816" Height="1056" xml:lang="en-US">${page}</FixedPage>`)],
    ['Resources/image.png', picture],
  ]);
}

/** A string as MS-OLEDS writes a LengthPrefixedAnsiString: a count that includes the NUL, the text and the NUL. */
const lpAnsi = text => {
  const b = Buffer.concat([B(text), Buffer.from([0])]);
  const n = Buffer.alloc(4);
  n.writeUInt32LE(b.length);
  return Buffer.concat([n, b]);
};
const u32le = n => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return b;
};
const u16le = n => Buffer.from([n & 0xff, n >> 8]);

/** Packager's native data for `data` named `name`, as the Package class writes it (MS-OLEDS 2.3.6 and Packager's format). */
function packageNative(name, data) {
  const temp = `C:\\Temp\\${name}`;
  return Buffer.concat([u16le(2), B(`${name}\0C:\\${name}\0`), u16le(0), u16le(3), u32le(temp.length + 1), B(`${temp}\0`), u32le(data.length), data]);
}

/** An RTF document whose one object is a Packager object, an OLE 1.0 object (MS-OLEDS 2.2), holding `data` named `name`. */
function rtfObject(name, data) {
  const ole1 = Buffer.concat([u32le(0x00000501), u32le(2), lpAnsi('Package'), lpAnsi(''), lpAnsi(''), u32le(packageNative(name, data).length), packageNative(name, data)]);
  return B(`{\\rtf1\\ansi\\deff0 Hello {\\object\\objemb{\\*\\objclass Package}\\objw100\\objh100{\\*\\objdata ${ole1.toString('hex')}}}}`);
}

/** An RTF document with a DDEAUTO field, whose result stays when the field goes. */
const rtfField = () => B('{\\rtf1\\ansi\\deff0 Hello {\\field{\\*\\fldinst DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/c calc"}{\\fldrslt result}}}');

/** An Outlook property stream: `header` zero bytes, then a 16-byte entry per [tag, value] of 32-bit values. */
const props = (entries, header) => Buffer.concat([Buffer.alloc(header), ...entries.map(([tag, value]) => Buffer.concat([u32le(tag), u32le(6), u32le(value), u32le(0)]))]);

/** An Outlook message with one attachment by value: `data` named `name`, of MIME type `type`. */
function msg(name, type, data) {
  const attachment = {
    name: '__attach_version1.0_#00000000',
    children: [
      { name: '__properties_version1.0', data: props([[0x37050003, 1]], 8) },
      { name: '__substg1.0_3707001F', data: Buffer.from(name, 'utf16le') },
      { name: '__substg1.0_370E001F', data: Buffer.from(type, 'utf16le') },
      { name: '__substg1.0_37010102', data },
    ],
  };
  return cfb([
    { name: '__properties_version1.0', data: props([], 32) },
    { name: '__substg1.0_0037001F', data: Buffer.from('Inert subject', 'utf16le') },
    { name: '__nameid_version1.0', children: [] },
    attachment,
  ]);
}

// ---------------------------------------------------------------------------------------------------------------
// Text, which file-defuse reads itself.

const csvRows = [
  'name,amount,note',
  'alice,-5,plain number',
  'bob,=1+2,formula',
  'carol,"=HYPERLINK(""http://example.com"")",quoted formula',
  "dave,+cmd|' /c calc'!A0,signed formula",
  'erin,@SUM(A1),at sign',
  'frank,-2+3,signed formula',
  'grace,+1.5e3,plain number',
  'ivan,\u202eevil,bidi control',
];

const markdown = [
  '# Notes',
  '',
  'A [safe link](https://example.com).',
  '',
  '[Click](javascript:alert(1))',
  '',
  '![pixel](data:image/png;base64,AAAA)',
  '',
  '[ref]: vbscript:msgbox',
  '',
  '<javascript:alert(2)>',
  '',
  '[x](&#106;avascript:alert(3))',
  '',
  '```',
  '[code](javascript:not_a_link)',
  '```',
  '',
  'Inline `[code](javascript:no)` span.',
  '',
];

// ---------------------------------------------------------------------------------------------------------------
// Polyglots: files whose content matches two formats.

/** A JPEG with a ZIP archive appended, as `cat` writes one. */
const jpegZip = () => Buffer.concat([jpeg({ comment: 'polyglot' }), zip([['readme.txt', B('A ZIP archive after the JPEG.\n')]])]);
/** A PDF with a ZIP archive appended. */
const pdfZip = () => Buffer.concat([pdf(), zip([['readme.txt', B('A ZIP archive after the PDF.\n')]])]);
/** A PNG with a text chunk and bytes after its end, which img-defuse removes. */
const untidyPng = () => Buffer.concat([png({ text: 'made by hand' }), B('trailing bytes')]);

// ---------------------------------------------------------------------------------------------------------------
// One small sample of every format detection names, in test/fixtures/formats, with the detection each must get in
// formats.json. They hold a format's signature and the structure detection reads, not a whole file of that format.

const OFFICE_DOCUMENT = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument';
const VISIO_DOCUMENT = 'http://schemas.microsoft.com/visio/2010/relationships/document';
/** The smallest package office-defuse names: content types, the package relationship to the main part, and the part. */
const oox = (mainType, relType = OFFICE_DOCUMENT) =>
  zip([
    ['[Content_Types].xml', B(`<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/main.xml" ContentType="${mainType}"/></Types>`)],
    ['_rels/.rels', B(`<Relationships xmlns="${RELS_NS}"><Relationship Id="R1" Type="${relType}" Target="main.xml"/></Relationships>`)],
    ['main.xml', B('<?xml version="1.0"?><document/>')],
  ]);
const odfZip = media =>
  zip([
    ['mimetype', B(media)],
    ['content.xml', B('<office:document-content/>')],
  ]);
const xpsZip = open =>
  zip([
    [
      '[Content_Types].xml',
      B('<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="fdseq" ContentType="application/vnd.ms-package.xps-fixeddocumentsequence+xml"/></Types>'),
    ],
    [
      '_rels/.rels',
      B(
        `<Relationships xmlns="${RELS_NS}"><Relationship Id="R0" Type="${open ? 'http://schemas.openxps.org/oxps/v1.0' : 'http://schemas.microsoft.com/xps/2005/06'}/fixedrepresentation" Target="/a.fdseq"/></Relationships>`,
      ),
    ],
    ['a.fdseq', B('<FixedDocumentSequence/>')],
  ]);
const stream = (name, data = B('x')) => ({ name, data });
/** A tar header of one empty file, with `magic` at 257 and its checksum. */
function tarHeader(magic) {
  const h = Buffer.alloc(512);
  h.write('file.txt', 0, 'latin1');
  h.write('0000644\0', 100, 'latin1');
  h.write('0000000\0', 108, 'latin1');
  h.write('0000000\0', 116, 'latin1');
  h.write('00000000000\0', 124, 'latin1');
  h.write('00000000000\0', 136, 'latin1');
  h.write('        ', 148, 'latin1');
  h.write('0', 156, 'latin1');
  if (magic) h.write(magic, 257, 'latin1');
  let sum = 0;
  for (const b of h) sum += b;
  h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1');
  return Buffer.concat([h, Buffer.alloc(1024)]);
}
const utf16 = (s, little) => (little ? Buffer.from(s, 'utf16le') : Buffer.from(s, 'utf16le').swap16());
const utf32le = s => Buffer.concat([...s].map(c => u32le(c.codePointAt(0))));
const pe = () => {
  const b = Buffer.alloc(128);
  b.write('MZ', 0, 'latin1');
  b.writeUInt32LE(64, 0x3c);
  b.write('PE\0\0', 64, 'latin1');
  return b;
};
const XML_DECL = '<?xml version="1.0" encoding="UTF-8"?>';
/** A 7z signature header of an empty archive: the signature, version 0.4, and a start header with its CRC. */
const sevenZip = () => {
  const start = Buffer.alloc(20);
  return Buffer.concat([Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 4]), u32le(crc32(start)), start]);
};
const MT = 'multipart/related; boundary="b"';

const formats = {
  pdf: [B('%PDF-1.7\n1 0 obj\n<<>>\nendobj\n'), 'application/pdf', 'pdf', 'pdf'],
  'pdf-late': [Buffer.concat([Buffer.alloc(100, 0xff), B('%PDF-1.7\n')]), 'application/pdf', 'pdf', 'pdf'],
  docx: [oox('application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'), 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'docx', 'office'],
  docm: [oox('application/vnd.ms-word.document.macroEnabled.main+xml'), 'application/vnd.ms-word.document.macroEnabled.12', 'docm', 'office'],
  xlsx: [oox('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml'), 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'xlsx', 'office'],
  xlsb: [oox('application/vnd.ms-excel.sheet.binary.macroEnabled.main'), 'application/vnd.ms-excel.sheet.binary.macroEnabled.12', 'xlsb', 'office'],
  pptx: [oox('application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml'), 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'pptx', 'office'],
  vsdx: [oox('application/vnd.ms-visio.drawing.main+xml', VISIO_DOCUMENT), 'application/vnd.ms-visio.drawing', 'vsdx', 'office'],
  // A package of a kind office-defuse cannot name is a ZIP archive to archive-defuse.
  'opc-other': [oox('application/vnd.example.package+xml'), 'application/zip', 'zip', 'archive'],
  xps: [xpsZip(false), 'application/vnd.ms-xpsdocument', 'xps', 'office'],
  oxps: [xpsZip(true), 'application/oxps', 'oxps', 'office'],
  odt: [odfZip('application/vnd.oasis.opendocument.text'), 'application/vnd.oasis.opendocument.text', 'odt', 'office'],
  ods: [odfZip('application/vnd.oasis.opendocument.spreadsheet'), 'application/vnd.oasis.opendocument.spreadsheet', 'ods', 'office'],
  'odf-manifest': [
    zip([
      [
        'META-INF/manifest.xml',
        B(
          '<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"><manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.presentation"/></manifest:manifest>',
        ),
      ],
    ]),
    'application/vnd.oasis.opendocument.presentation',
    'odp',
    'office',
  ],
  'sun-xml': [odfZip('application/vnd.sun.xml.writer'), 'application/zip', 'zip', 'archive'],
  epub: [odfZip('application/epub+zip'), 'application/zip', 'zip', 'archive'],
  zip: [zip([['readme.txt', B('hello\n')]]), 'application/zip', 'zip', 'archive'],
  zipx: [zip([['readme.txt', B('not really LZMA'), 14]]), 'application/zip', 'zip', 'archive'],
  'zip-no-directory': [zip([['[Content_Types].xml', B('<Types/>')]]).subarray(0, 60), 'application/zip', 'zip', 'archive'],
  'encrypted-ooxml': [cfb([stream('EncryptionInfo'), stream('EncryptedPackage')]), 'application/x-ole-storage', '', 'office'],
  doc: [cfb([stream('WordDocument'), stream('1Table')]), 'application/msword', 'doc', 'office'],
  xls: [cfb([stream('Workbook')]), 'application/vnd.ms-excel', 'xls', 'office'],
  'xls-book': [cfb([stream('Book')]), 'application/vnd.ms-excel', 'xls', 'office'],
  ppt: [cfb([stream('PowerPoint Document'), stream('Current User')]), 'application/vnd.ms-powerpoint', 'ppt', 'office'],
  vsd: [cfb([stream('VisioDocument')]), 'application/vnd.visio', 'vsd', 'office'],
  msg: [cfb([stream('__properties_version1.0')]), 'application/vnd.ms-outlook', 'msg', 'office'],
  oft: [cfb([stream('__properties_version1.0')], '0006F046-0000-0000-C000-000000000046'), 'application/vnd.ms-outlook', 'oft', 'office'],
  pub: [cfb([{ name: 'Quill', children: [stream('CONTENTS')] }]), 'application/x-mspublisher', 'pub', 'office'],
  mpp: [cfb([stream('Props'), { name: '   114', children: [stream('Var2Data')] }]), 'application/vnd.ms-project', 'mpp', 'office'],
  // Compound files office-defuse cannot name, which no package reads.
  'cfb-two-formats': [cfb([stream('WordDocument'), stream('Workbook')]), 'application/x-ole-storage', 'cfb', undefined],
  'cfb-unreadable': [Buffer.concat([Buffer.from('d0cf11e0a1b11ae1', 'hex'), Buffer.alloc(600)]), 'application/x-ole-storage', 'cfb', undefined],
  msi: [cfb([stream('\u4840\u3f3f\u4577')], '000C1084-0000-0000-C000-000000000046'), 'application/x-ole-storage', 'cfb', undefined],
  'cfb-other': [cfb([stream('Equation Native')]), 'application/x-ole-storage', 'cfb', undefined],
  rtf: [B('{\\rtf1\\ansi Hello}'), 'application/rtf', 'rtf', 'office'],
  fodt: [flatOdf(png()), 'application/vnd.oasis.opendocument.text-flat-xml', 'fodt', 'office'],
  'flat-opc': [flatOpc(png()), 'application/xml', 'xml', 'office'],
  png: [png(), 'image/png', 'png', 'image'],
  jpeg: [jpeg(), 'image/jpeg', 'jpg', 'image'],
  gif: [B('GIF89a\x01\0\x01\0\0\0\0;'), 'image/gif', 'gif', 'image'],
  webp: [B('RIFF\x1a\0\0\0WEBPVP8 '), 'image/webp', 'webp', 'image'],
  tiff: [B('II*\0\x08\0\0\0'), 'image/tiff', 'tif', 'image'],
  bigtiff: [B('MM\0+\0\x08\0\0'), 'image/tiff', 'tif', 'image'],
  bmp: [Buffer.concat([B('BM'), Buffer.alloc(12), u32le(40), Buffer.alloc(36)]), 'image/bmp', 'bmp', 'image'],
  ico: [Buffer.from([0, 0, 1, 0, 1, 0, 16, 16]), 'image/vnd.microsoft.icon', 'ico', 'image'],
  cur: [Buffer.from([0, 0, 2, 0, 1, 0, 16, 16]), 'image/x-win-bitmap', 'cur', 'image'],
  jp2: [jp2(), 'image/jp2', 'jp2', 'image'],
  j2c: [codestream(), 'image/j2c', 'j2c', 'image'],
  jxl: [jxlCodestream(), 'image/jxl', 'jxl', 'image'],
  'jxl-container': [jxl(), 'image/jxl', 'jxl', 'image'],
  emf: [Buffer.concat([u32le(1), Buffer.alloc(36), B(' EMF'), Buffer.alloc(40)]), 'image/emf', 'emf', 'image'],
  wmf: [Buffer.from([0xd7, 0xcd, 0xc6, 0x9a, 0, 0, 0, 0]), 'image/wmf', 'wmf', 'image'],
  'wmf-bare': [Buffer.from([1, 0, 9, 0, 0, 3, 0, 0, 0, 0]), 'image/wmf', 'wmf', 'image'],
  psd: [B('8BPS\0\x01\0\0\0\0\0\0'), 'image/vnd.adobe.photoshop', 'psd', 'image'],
  psb: [B('8BPS\0\x02\0\0\0\0\0\0'), 'image/vnd.adobe.photoshop', 'psb', 'image'],
  xml: [B(`${XML_DECL}<root/>`), 'application/xml', 'xml', 'xml'],
  'xml-utf16le-bom': [Buffer.concat([Buffer.from([0xff, 0xfe]), utf16('<?xml version="1.0" encoding="UTF-16"?><root/>', true)]), 'application/xml', 'xml', 'xml'],
  'xml-utf16be': [utf16('<?xml version="1.0" encoding="UTF-16"?><root/>', false), 'application/xml', 'xml', 'xml'],
  // xml-defuse does not read UTF-32 without a byte order mark, and refuses XML in EBCDIC, which it claims.
  'xml-utf32le': [utf32le('<?xml version="1.0"?><root/>'), 'application/octet-stream', '', undefined],
  'xml-ebcdic': [Buffer.from([0x4c, 0x6f, 0xa7, 0x94, 0x93, 0x40]), 'application/xml', 'xml', 'xml'],
  html: [B('<html><body>Hello</body></html>'), 'text/html', 'html', 'xml'],
  'html-doctype': [B('<!DOCTYPE html><p>Hello'), 'text/html', 'html', 'xml'],
  'html-comment': [B('<!-- note --><div>Hello</div>'), 'text/html', 'html', 'xml'],
  xhtml: [B(`${XML_DECL}<html xmlns="http://www.w3.org/1999/xhtml"><body/></html>`), 'application/xhtml+xml', 'xhtml', 'xml'],
  svg: [B('<svg xmlns="http://www.w3.org/2000/svg"/>'), 'image/svg+xml', 'svg', 'xml'],
  xslt: [B(`${XML_DECL}<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"/>`), 'application/xslt+xml', 'xsl', 'xml'],
  mht: [B(`MIME-Version: 1.0\r\nContent-Type: ${MT}\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\n<p>Hi</p>\r\n--b--\r\n`), 'multipart/related', 'mht', 'xml'],
  'mht-single': [B('MIME-Version: 1.0\r\nContent-Type: text/html\r\n\r\n<p>Hi</p>\r\n'), 'multipart/related', 'mht', 'xml'],
  eml: [B('From: a@example.com\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n--b--\r\n'), 'multipart/related', 'mht', 'xml'],
  // xml-defuse reads both as HTML, and refuses the HTML Application when it reads it.
  hta: [B('<html><head><hta:application id="app"/></head></html>'), 'text/html', 'html', 'xml'],
  shtml: [B('<html><body><!--#include virtual="/footer.html" --></body></html>'), 'text/html', 'html', 'xml'],
  gzip: [zlib.gzipSync(B('hello'), { level: 0 }).fill(0, 4, 8), 'application/gzip', 'gz', 'archive'],
  bzip2: [Buffer.concat([B('BZh9'), Buffer.from([0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 0, 0, 0, 0])]), 'application/x-bzip2', 'bz2', 'archive'],
  zstd: [Buffer.from([0x28, 0xb5, 0x2f, 0xfd, 0x20, 0, 0x01, 0, 0]), 'application/zstd', 'zst', 'archive'],
  'zstd-skippable': [Buffer.concat([Buffer.from([0x50, 0x2a, 0x4d, 0x18]), u32le(2), B('hi'), Buffer.from([0x28, 0xb5, 0x2f, 0xfd, 0x20, 0, 0x01, 0, 0])]), 'application/zstd', 'zst', 'archive'],
  'tar-ustar': [tarHeader('ustar\x0000'), 'application/x-tar', 'tar', 'archive'],
  'tar-gnu': [tarHeader('ustar  \0'), 'application/x-tar', 'tar', 'archive'],
  'tar-old': [tarHeader(), 'application/x-tar', 'tar', 'archive'],
  cab: [Buffer.concat([B('MSCF\0\0\0\0'), Buffer.alloc(16), Buffer.from([3, 1])]), 'application/vnd.ms-cab-compressed', 'cab', 'archive'],
  '7z': [sevenZip(), 'application/x-7z-compressed', '7z', 'archive'],
  xz: [Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0, 0, 4]), 'application/x-xz', 'xz', 'archive'],
  lzma: [Buffer.concat([Buffer.from([0x5d]), u32le(1 << 16), Buffer.alloc(8, 0xff), Buffer.from([0, 0x41, 0x0f])]), 'application/x-lzma', 'lzma', 'archive', 'heuristic'],
  'text-utf8': [Buffer.from('Plain text, caf\u00e9.\n', 'utf8'), 'text/plain', 'txt', 'text'],
  'text-utf16-bom': [Buffer.concat([Buffer.from([0xfe, 0xff]), utf16('Plain text.\n', false)]), 'text/plain', 'txt', 'text'],
  'text-utf32-bom': [Buffer.concat([Buffer.from([0xff, 0xfe, 0, 0]), utf32le('Plain text.\n')]), 'text/plain', 'txt', 'text'],
  'text-8bit': [B('Caf\xe9 au lait\n'), 'text/plain', 'txt', 'text', 'heuristic'],
  rar: [B('Rar!\x1a\x07\x01\0'), 'application/vnd.rar', 'rar', undefined],
  elf: [B('\x7fELF\x02\x01\x01\0'), 'application/x-executable', 'elf', undefined],
  exe: [pe(), 'application/x-msdownload', 'exe', undefined],
  postscript: [B('%!PS-Adobe-3.0\n'), 'application/postscript', 'ps', undefined],
  sylk: [B('ID;PWXL;N;E\r\nC;Y1;X1;K1\r\nE\r\n'), 'application/x-sylk', 'slk', undefined],
  binary: [Buffer.from([0, 1, 2, 3, 4, 5, 6, 7]), 'application/octet-stream', '', undefined],
};

/**
 * An MS-OVBA CompressedContainer (2.4.1) with every token a literal: a flag byte of zeros before each eight bytes. A
 * full chunk of literals passes 4,096 bytes, so it is written raw. This is not office-defuse's compressor.
 */
function ovba(data) {
  const out = [Buffer.from([1])];
  for (let start = 0; start < data.length; start += 4096) {
    const chunk = data.subarray(start, start + 4096);
    if (chunk.length === 4096) {
      out.push(Buffer.from([0xff, 0x3f]), chunk);
      continue;
    }
    const body = [];
    for (let i = 0; i < chunk.length; i += 8) body.push(Buffer.from([0]), chunk.subarray(i, i + 8));
    const b = Buffer.concat(body);
    if (b.length > 4096) throw new Error('a last chunk of literals past 4,096 bytes');
    const head = Buffer.alloc(2);
    head.writeUInt16LE(0xb000 | (b.length - 1));
    out.push(head, b);
  }
  return Buffer.concat(out);
}

/**
 * A vbaProject.bin (MS-OVBA 2.2) holding `modules`, each { name, kind: 'document' | 'standard', source }: the PROJECT
 * stream, and a VBA storage with a dir stream, a compiled-code header, a performance cache, and each module's p-code
 * followed by its source.
 */
function vbaStorages(modules) {
  const record = (id, data = Buffer.alloc(0)) => {
    const head = Buffer.alloc(6);
    head.writeUInt16LE(id, 0);
    head.writeUInt32LE(data.length, 2);
    return Buffer.concat([head, data]);
  };
  const u16 = n => Buffer.from([n & 0xff, n >> 8]);
  const u32 = n => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n);
    return b;
  };
  const pcode = B('\x01\x16\x03\x00inert p-code');
  const version = Buffer.alloc(16);
  version.writeUInt16LE(0x0009, 0);
  version.writeUInt32LE(4, 2);
  version.writeUInt32LE(1, 6);
  const records = [record(0x0001, u32(1)), record(0x0002, u32(0x0409)), record(0x0014, u32(0x0409)), record(0x0003, u16(1252)), record(0x0004, B('VBAProject'))];
  records.push(record(0x0005), record(0x0040), record(0x0006), record(0x003d), record(0x0007, u32(0)), record(0x0008, u32(0)), version.subarray(0, 12), record(0x000c), record(0x003c));
  records.push(record(0x000f, u16(modules.length)), record(0x0013, u16(0xffff)));
  const streams = [];
  const project = ['ID="{6A1B2C3D-4E5F-4071-8293-A4B5C6D7E8F9}"'];
  for (const m of modules) {
    const name = B(m.name);
    const wide = Buffer.from(m.name, 'utf16le');
    records.push(record(0x0019, name), record(0x0047, wide), record(0x001a, name), record(0x0032, wide), record(0x001c), record(0x0048));
    records.push(record(0x0031, u32(pcode.length)), record(0x001e, u32(0)), record(0x002c, u16(0xffff)), record(m.kind === 'standard' ? 0x0021 : 0x0022), record(0x002b));
    streams.push({ name: m.name, data: Buffer.concat([pcode, ovba(B(`Attribute VB_Name = "${m.name}"\r\n${m.source.replace(/\n/g, '\r\n')}`))]) });
    project.push(m.kind === 'standard' ? `Module=${m.name}` : `Document=${m.name}/&H00000000`);
  }
  records.push(record(0x0010));
  project.push('Name="VBAProject"', 'HelpContextID="0"', '');
  return [
    { name: 'PROJECT', data: B(project.join('\r\n')) },
    { name: 'PROJECTwm', data: Buffer.alloc(2) },
    {
      name: 'VBA',
      children: [
        { name: 'dir', data: ovba(Buffer.concat(records)) },
        { name: '_VBA_PROJECT', data: B('\xcc\x61\xb5\x00\x00\x03\x00inert performance cache') },
        { name: '__SRP_0', data: B('inert cache') },
        ...streams,
      ],
    },
  ];
}
const vbaProject = modules => cfb(vbaStorages(modules));

/** A one-sheet .xlsm whose VBA project holds a workbook module and `code` in a code module. */
function xlsm(code) {
  const xml = s => B(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n${s}`);
  const S = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main';
  const types =
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>' +
    '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' +
    '<Override PartName="/xl/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>';
  const rels = `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="${PKG_REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>`;
  const workbookRels = `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="${PKG_REL}/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/></Relationships>`;
  const workbook = `<workbook xmlns="${S}" xmlns:r="${PKG_REL}"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>`;
  const project = vbaProject([
    { name: 'ThisWorkbook', kind: 'document', source: 'Sub Workbook_Open()\n    inertOpened = True\n    Worksheets(1).Cells(5, 2).Value = "Inert opened"\nEnd Sub\n' },
    { name: 'Inert', kind: 'standard', source: code },
  ]);
  return zip([
    ['[Content_Types].xml', xml(types)],
    ['_rels/.rels', xml(rels)],
    ['xl/workbook.xml', xml(workbook)],
    ['xl/_rels/workbook.xml.rels', xml(workbookRels)],
    ['xl/worksheets/sheet1.xml', xml(`<worksheet xmlns="${S}"><sheetData/></worksheet>`)],
    ['xl/vbaProject.bin', project],
  ]);
}
/**
 * A Forms 2.0 property block (MS-OFORMS 2.2): version 2.0, its size, the property mask, the data block with each
 * number aligned to its size from the block's start, and the extra data block with pairs and strings.
 */
function axBlock(kinds, values, wide = false) {
  let mask = 0n;
  const body = [...Buffer.alloc(wide ? 8 : 4)];
  const extra = [];
  const align = n => {
    while ((4 + body.length) % n) body.push(0);
  };
  kinds.forEach((kind, i) => {
    if (!(i in values)) return;
    mask |= 1n << BigInt(i);
    const v = values[i];
    if (kind === 'string') {
      align(4);
      const raw = B(v);
      const size = Buffer.alloc(4);
      size.writeUInt32LE((raw.length | 0x80000000) >>> 0);
      body.push(...size);
      extra.push(raw);
    } else if (kind === 'pair') {
      const pair = Buffer.alloc(8);
      pair.writeInt32LE(v[0]);
      pair.writeInt32LE(v[1], 4);
      extra.push(pair);
    } else {
      const n = { u8: 1, u16: 2, u32: 4 }[kind];
      align(n);
      for (let k = 0; k < n; k++) body.push((v >>> (8 * k)) & 0xff);
    }
  });
  align(4);
  for (const x of extra) {
    body.push(...x);
    align(4);
  }
  const m = Buffer.alloc(wide ? 8 : 4);
  if (wide) m.writeBigUInt64LE(mask);
  else m.writeUInt32LE(Number(mask));
  body.splice(0, wide ? 8 : 4, ...m);
  return Buffer.concat([Buffer.from([0, 2, body.length & 0xff, body.length >> 8]), Buffer.from(body)]);
}
const MORPH = [...'u32 u32 u32 u32 u8 u8 u8 u8 pair u16 u32 u16 u16 u16 u16 u16 u8 u8 u8 undefined u8 u8 string string u32 u32 u32 picture picture u16 undefined flag string'.split(' ')];
const TEXT_PROPS = ['string', 'u32', 'u32', 'u32', 'u8', 'u8', 'u8', 'u16'];
const CHECKBOX = '8BD21D40-EC42-11CE-9E0D-00AA006002F3';
/** A GUID as Windows writes it, in the byte order a file holds. */
function guidBytes(text) {
  const h = Buffer.from(text.replace(/-/g, ''), 'hex');
  return Buffer.concat([Buffer.from(h.subarray(0, 4)).reverse(), Buffer.from(h.subarray(4, 6)).reverse(), Buffer.from(h.subarray(6, 8)).reverse(), h.subarray(8)]);
}
/** A Forms 2.0 check box as Excel persists it in an activeX part's binary: its class id, its properties, its font. */
const checkBoxData = () =>
  Buffer.concat([guidBytes(CHECKBOX), axBlock(MORPH, { 0: 0x2c80081b, 6: 4, 8: [2000, 500], 22: '0', 23: 'Inert box' }, true), axBlock(TEXT_PROPS, { 0: 'Inert Sans', 2: 165 })]);

/** A one-sheet .xlsm with a VBA project and a Forms 2.0 check box on the sheet, whose click the sheet's module handles. */
function controlsXlsm() {
  const xml = s => B(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n${s}`);
  const S = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main';
  const types =
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>' +
    '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' +
    '<Override PartName="/xl/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/><Override PartName="/xl/activeX/activeX1.xml" ContentType="application/vnd.ms-office.activeX+xml"/><Override PartName="/xl/activeX/activeX1.bin" ContentType="application/vnd.ms-office.activeX"/></Types>';
  const rels = `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="${PKG_REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>`;
  const workbookRels = `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="${PKG_REL}/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/></Relationships>`;
  const sheetRels = `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="${PKG_REL}/control" Target="../activeX/activeX1.xml"/></Relationships>`;
  const axRels =
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/activeXControlBinary" Target="activeX1.bin"/></Relationships>';
  const ax = `<ax:ocx ax:classid="{${CHECKBOX}}" ax:persistence="persistStreamInit" r:id="rId1" xmlns:ax="http://schemas.microsoft.com/office/2006/activeX" xmlns:r="${PKG_REL}"/>`;
  const workbook = `<workbook xmlns="${S}" xmlns:r="${PKG_REL}"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>`;
  const project = vbaProject([{ name: 'Sheet1', kind: 'document', source: 'Sub InertBox_Click()\n    inertCount = inertCount + 1\n    Cells(2, 7).Value = inertCount\nEnd Sub\n' }]);
  return zip([
    ['[Content_Types].xml', xml(types)],
    ['_rels/.rels', xml(rels)],
    ['xl/workbook.xml', xml(workbook)],
    ['xl/_rels/workbook.xml.rels', xml(workbookRels)],
    ['xl/worksheets/sheet1.xml', xml(`<worksheet xmlns="${S}" xmlns:r="${PKG_REL}"><sheetData/><controls><control shapeId="1025" r:id="rId1" name="InertBox"/></controls></worksheet>`)],
    ['xl/worksheets/_rels/sheet1.xml.rels', xml(sheetRels)],
    ['xl/activeX/activeX1.xml', xml(ax)],
    ['xl/activeX/_rels/activeX1.xml.rels', xml(axRels)],
    ['xl/activeX/activeX1.bin', checkBoxData()],
    ['xl/vbaProject.bin', project],
  ]);
}

/** A BIFF8 record. */
const biff = (type, body) => Buffer.concat([Buffer.from([type & 0xff, type >> 8, body.length & 0xff, body.length >> 8]), body]);
const biffBof = dt => biff(0x0809, Buffer.from([0x00, 0x06, dt, 0x00, 0xbb, 0x0d, 0xcc, 0x07, 0, 0, 0, 0, 0, 0, 0, 0]));
/**
 * An Excel 97 workbook with an Excel 4.0 macro sheet and the built-in Auto_Open name that runs it: the globals with
 * the name and a BoundSheet8 per sheet, then each sheet's substream.
 */
function xlmXls() {
  const autoOpen = biff(0x0018, Buffer.from([0x20, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
  const bound = (pos, state, dt, name) => {
    const b = Buffer.alloc(8);
    b.writeUInt32LE(pos);
    b[4] = state;
    b[5] = dt;
    b[6] = name.length;
    return biff(0x0085, Buffer.concat([b, B(name)]));
  };
  const sheet = biffBof(0x10);
  // The macro sheet: a cell whose formula is the number 1, the shape of an XLM macro cell.
  const formula = Buffer.concat([Buffer.alloc(6), Buffer.alloc(8), Buffer.from([0, 0, 0, 0, 0, 0, 3, 0, 0x1e, 1, 0])]);
  const macro = Buffer.concat([biffBof(0x40), biff(0x0006, formula), biff(0x000a, Buffer.alloc(0))]);
  const head = Buffer.concat([biffBof(5), autoOpen]);
  const globalsLength = head.length + bound(0, 0, 0, 'Sheet1').length + bound(0, 1, 1, 'Macro1').length + 4;
  const sheetAt = globalsLength;
  const macroAt = sheetAt + sheet.length + 4;
  const book = Buffer.concat([head, bound(sheetAt, 0, 0, 'Sheet1'), bound(macroAt, 1, 1, 'Macro1'), biff(0x000a, Buffer.alloc(0)), sheet, biff(0x000a, Buffer.alloc(0)), macro]);
  return cfb([{ name: 'Workbook', data: book }], '00020820-0000-0000-C000-000000000046');
}

/** A PowerPoint 97 to 2003 add-in: its root is its VBA project, with the class id PowerPoint writes there. */
const addinPpa = () =>
  cfb(
    vbaStorages([{ name: 'Inert', kind: 'standard', source: 'Public Sub InertSlides()\n    Set inertDeck = ActivePresentation\n    inertTotal = inertDeck.Slides.Count + 1\nEnd Sub\n' }]),
    '817246F0-720A-11CF-8718-00AA0060263B',
  );

/** A PowerPoint record. */
const prec = (type, body, instance = 0, container = false) => {
  const h = Buffer.alloc(8);
  h.writeUInt16LE((instance << 4) | (container ? 0x0f : 0));
  h.writeUInt16LE(type, 2);
  h.writeUInt32LE(body.length, 4);
  return Buffer.concat([h, body]);
};
/**
 * A PowerPoint 97 presentation whose VBA project is stored compressed, as PowerPoint stores it: the DocumentContainer
 * with a VBAInfoContainer naming the project's persist object, a slide with an action that runs one of its macros,
 * the project's ExOleObjStg, the persist directory and the current edit, which the Current User stream names.
 */
function vbaPpt() {
  const u32 = (...ns) => {
    const b = Buffer.alloc(4 * ns.length);
    for (let i = 0; i < ns.length; i++) b.writeUInt32LE(ns[i] >>> 0, 4 * i);
    return b;
  };
  const docAtom = prec(0x03e9, Buffer.alloc(40));
  const vbaInfo = prec(0x03ff, prec(0x0400, u32(3, 1, 2)), 0, true);
  const document = prec(0x03e8, Buffer.concat([docAtom, vbaInfo]), 1, true);
  const action = prec(0x0ff2, Buffer.concat([prec(0x0ff3, Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0])), prec(0x0fba, Buffer.from('InertSlides', 'utf16le'), 2)]), 0, true);
  const slide = prec(0x03ee, Buffer.concat([prec(0x03ef, Buffer.alloc(24)), prec(0xf00d, action, 0, true)]), 0, true);
  const project = cfb(
    vbaStorages([{ name: 'Inert', kind: 'standard', source: 'Public Sub InertSlides()\n    Set inertDeck = ActivePresentation\n    inertTotal = inertDeck.Slides.Count + 1\nEnd Sub\n' }]),
  );
  const storage = prec(0x1011, Buffer.concat([u32(project.length), zlibStored(project)]), 1);
  const objects = [document, slide, storage];
  const offsets = [];
  let at = 0;
  for (const o of objects) {
    offsets.push(at);
    at += o.length;
  }
  const persistDir = prec(0x1772, u32(1 | (3 << 20), ...offsets));
  const dirAt = at;
  const editAt = dirAt + persistDir.length;
  const edit = prec(0x0ff5, Buffer.concat([u32(256), Buffer.from([0, 0, 3, 3]), u32(0, dirAt, 1, 4), Buffer.alloc(4)]));
  const user = prec(0x0ff6, Buffer.concat([u32(0x14, 0xe391c05f, editAt), Buffer.from([5, 0, 0xf4, 0x03, 3, 0, 0, 0]), B('Inert'), u32(8)]));
  return cfb(
    [
      { name: 'PowerPoint Document', data: Buffer.concat([...objects, persistDir, edit]) },
      { name: 'Current User', data: user },
    ],
    '64818D10-4F9B-11CF-86EA-00AA00B929E8',
  );
}

const SAFE_MACRO = 'Public Sub InertTotal()\n    Dim sum As Double, n As Long\n    For n = 5 To 9\n        sum = sum + Cells(n, 6).Value\n    Next n\n    Cells(10, 6).Value = sum\nEnd Sub\n';
const SHELL_MACRO = 'Public Sub InertTotal()\n    Shell "inert-program.exe", vbHide\nEnd Sub\n';

// ---------------------------------------------------------------------------------------------------------------

const fixtures = {
  'clean.pdf': pdf(),
  'nested.pdf': nest(4, pdf({ js: true })),
  'loop.pdf': loopPdf(),
  'deep.pdf': nest(12, pdf()),
  'wide.pdf': pdf({ attachments: Array.from({ length: 12 }, (_, i) => ({ name: `child${String(i + 1).padStart(2, '0')}.pdf`, bytes: pdf() })) }),
  'bulky.pdf': pdf({ attachments: Array.from({ length: 3 }, (_, i) => ({ name: `bulk${i + 1}.pdf`, bytes: pdf({ pad: 256 * 1024 }) })) }),
  'passwords.pdf': pdf({ password: 'outer pass', attachments: [{ name: 'inner.pdf', bytes: pdf({ password: 'inner pass', js: true }) }] }),
  'mixed.pdf': pdf({
    attachments: [
      { name: 'notes.txt', bytes: B('Plain text notes.\n') },
      { name: 'tool.exe', bytes: Buffer.concat([B('MZ'), Buffer.alloc(62)]) },
      { name: 'picture.png', bytes: Buffer.concat([B('\x89PNG\r\n\x1a\n'), Buffer.alloc(16)]) },
      { name: 'report.pdf', bytes: pdf({ js: true }) },
    ],
  }),
  'unknown.bin': Buffer.concat([Buffer.from([0, 1, 2, 3, 4, 5, 6, 7]), B('Bytes that no package of the family reads.\n')]),
  'embedded.docx': docx({
    embeds: [
      {
        name: 'report.pdf',
        type: 'application/pdf',
        bytes: pdf({ attachments: [{ name: 'inner.docx', bytes: docx({ embeds: [{ name: 'final.pdf', type: 'application/pdf', bytes: pdf({ js: true }) }] }) }] }),
      },
      { name: 'notes.docx', type: DOCX_TYPE, bytes: docx() },
    ],
  }),
  'passwords.docx': agileEncrypt(docx({ embeds: [{ name: 'secret.pdf', type: 'application/pdf', bytes: pdf({ password: 'pdf pass', js: true }) }] }), 'office pass'),
  'archive.zip': zip([['readme.txt', B('A ZIP archive that is not an Office package.\n')]]),
  'photo.jpg': jpeg({ thumbnail: jpeg({ comment: 'thumbnail comment' }) }),
  'images.pdf': pdf({
    info: true,
    attachments: [
      { name: 'photo.jpg', bytes: jpeg({ thumbnail: jpeg({ comment: 'thumbnail comment' }) }) },
      { name: 'chart.png', bytes: png({ text: 'made by hand' }) },
    ],
  }),
  'photo.jp2': jp2({ exifData: exif(jpeg({ comment: 'thumbnail comment' })) }),
  'photo.j2c': codestream({ comment: 'made by hand' }),
  'photo.jxl': jxl(),
  'picture.docx': docx({ media: [{ name: 'image1.png', type: 'image/png', bytes: untidyPng() }] }),
  'flat.fodt': flatOdf(untidyPng()),
  'flat-opc.xml': flatOpc(untidyPng()),
  'pages.xps': xps(untidyPng()),
  'macros.xlsm': xlsm(SAFE_MACRO),
  'shell-macro.xlsm': xlsm(SHELL_MACRO),
  'controls.xlsm': controlsXlsm(),
  'xlm.xls': xlmXls(),
  'addin.ppa': addinPpa(),
  'macros.ppt': vbaPpt(),
  'macros.zip': zip([
    ['macros.xlsm', xlsm(SAFE_MACRO)],
    ['shell-macro.xlsm', xlsm(SHELL_MACRO)],
  ]),
  'field.rtf': rtfField(),
  'object.rtf': rtfObject('report.pdf', pdf({ js: true })),
  'message.msg': msg('report.pdf', 'application/pdf', pdf({ js: true, pad: 4096 })),
  // office-defuse writes the mini stream of this smaller message, which holds the PDF, inside the first 1024 bytes.
  'small-attachment.msg': msg('report.pdf', 'application/pdf', pdf({ js: true })),
  'notes.txt': Buffer.from('Plain text notes, caf\u00e9.\n', 'utf8'),
  'data.csv': Buffer.from(`${csvRows.join('\r\n')}\r\n`, 'utf8'),
  'readme.md': Buffer.from(markdown.join('\n'), 'utf8'),
  'unclosed.csv': B('a,b\n1,"open\n'),
  'legacy.csv': B('name,note\r\nCaf\xe9,=1+2\r\n'),
  'utf16.txt': Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('Hi \u202eevil\u202c there\n', 'utf16le')]),
  // Detection judges text on the first 64 KiB, so what would make the start not text sits after it.
  'late.txt': Buffer.concat([
    Buffer.from([0xef, 0xbb, 0xbf]),
    Buffer.from(`${'Filler line of plain text.\n'.repeat(2500)}`, 'utf8'),
    B('bad \xff byte, bell \x07, '),
    Buffer.from('next line \u0085 control\n', 'utf8'),
  ]),
  'jpeg-zip.bin': jpegZip(),
  'pdf-zip.bin': pdfZip(),
  'inseparable.jpg': jpeg({ quantization: B('%PDF-1.7') }),
  'polyglots.pdf': pdf({
    attachments: [
      { name: 'photo.jpg', bytes: jpegZip() },
      { name: 'photo.zip', bytes: jpegZip() },
    ],
  }),
};

module.exports = { agileEncrypt, docx, jpeg, pdf, png, untidyPng, jpegZip, xlsm };
if (require.main === module) {
  fs.mkdirSync(dir, { recursive: true });
  for (const [name, bytes] of Object.entries(fixtures)) fs.writeFileSync(path.join(dir, name), bytes);
  const formatDir = path.join(dir, 'formats');
  fs.rmSync(formatDir, { recursive: true, force: true });
  fs.mkdirSync(formatDir);
  const expected = {};
  for (const [name, [bytes, mimeType, extension, family, heuristic]] of Object.entries(formats)) {
    fs.writeFileSync(path.join(formatDir, name), bytes);
    expected[name] = { mimeType, extension, family: family ?? null, heuristic: heuristic === 'heuristic' };
  }
  fs.writeFileSync(path.join(dir, 'formats.json'), `${JSON.stringify(expected, null, 2)}\n`);
  console.log(`${Object.keys(fixtures).length} fixtures and ${Object.keys(formats).length} format samples in ${path.relative(process.cwd(), dir) || '.'}`);
}
