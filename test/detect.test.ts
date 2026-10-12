import * as fs from 'node:fs';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import { expect } from 'chai';
import { bufferSource, detectFile, detectFileSource, inspectFile } from '../src';
import { extensionOf } from '../src/detect';
import { deflateBomb, fixture, fixtures, formatsDir, makePdf, zipOf } from './helpers/util';

interface Expected {
  mimeType: string;
  extension: string;
  family: string | null;
  heuristic: boolean;
}

const expected = JSON.parse(fs.readFileSync(path.join(fixtures, 'formats.json'), 'utf8')) as Record<string, Expected>;
const B = (s: string) => Buffer.from(s, 'latin1');

describe('detection', () => {
  describe('every format of the table, by content alone', () => {
    it('has a sample for every entry and an entry for every sample', () => {
      expect(new Set(fs.readdirSync(formatsDir))).to.deep.equal(new Set(Object.keys(expected)));
    });
    for (const [name, want] of Object.entries(expected)) {
      it(`${name}: ${want.mimeType} for ${want.family ?? 'no family'}`, async () => {
        const d = await detectFile(fs.readFileSync(path.join(formatsDir, name)));
        expect({ mimeType: d.mimeType, extension: d.extension, family: d.family ?? null, heuristic: d.heuristic !== undefined }).to.deep.equal(want);
      });
    }
  });

  it('gives the package the container type its plugin reads', async () => {
    const sniffed = async (name: string) => (await detectFile(fs.readFileSync(path.join(formatsDir, name)))).sniffedType;
    expect(await sniffed('docx')).to.equal('application/zip');
    expect(await sniffed('xps')).to.equal('application/zip');
    expect(await sniffed('doc')).to.equal('application/x-ole-storage');
    expect(await sniffed('rtf')).to.equal('application/rtf');
    expect(await sniffed('fodt')).to.equal('application/xml');
    expect(await sniffed('pdf-late')).to.equal('application/pdf');
    expect(await sniffed('jxl')).to.equal('image/jxl');
  });

  it('lists every signature of a polyglot with its offset, the one at the start first', async () => {
    const d = await detectFile(fixture('jpeg-zip.bin'));
    expect(d.signatures.map(s => [s.mimeType, s.family])).to.deep.equal([
      ['image/jpeg', 'image'],
      ['application/zip', 'archive'],
    ]);
    expect(d.signatures[0].offset).to.equal(0);
    // The ZIP archive starts at its first entry's local header, where archive-defuse's reader finds it.
    expect(d.signatures[1].offset).to.equal(fixture('jpeg-zip.bin').indexOf('PK\x03\x04'));
    expect([d.mimeType, d.chosenBy]).to.deep.equal(['image/jpeg', 'firstSignature']);
  });

  it('lets the name, then the declared type, choose among the formats the content matches', async () => {
    const bytes = fixture('jpeg-zip.bin');
    const byName = await detectFile(bytes, { name: 'photo.zip', declaredType: 'image/jpeg' });
    expect([byName.mimeType, byName.family, byName.chosenBy]).to.deep.equal(['application/zip', 'archive', 'name']);
    const byType = await detectFile(bytes, { name: 'photo', declaredType: 'application/zip' });
    expect([byType.mimeType, byType.chosenBy]).to.deep.equal(['application/zip', 'declaredType']);
    const neither = await detectFile(bytes, { name: 'photo.png', declaredType: 'application/pdf' });
    expect([neither.mimeType, neither.chosenBy]).to.deep.equal(['image/jpeg', 'firstSignature']);
  });

  it('never lets a name or declared type choose a family the content does not match', async () => {
    const pdf = await detectFile(fixture('clean.pdf'), { name: 'photo.jpg', declaredType: 'image/jpeg' });
    expect([pdf.family, pdf.chosenBy, pdf.signatures.length]).to.deep.equal(['pdf', undefined, 1]);
    const text = await detectFile(B('Just words.\n'), { name: 'report.pdf', declaredType: 'application/pdf' });
    expect([text.family, text.mimeType]).to.deep.equal(['text', 'text/plain']);
  });

  it('takes a PDF header anywhere in the first 1024 bytes when no signature starts the file, and not past them', async () => {
    expect((await detectFile(Buffer.concat([Buffer.alloc(1000, 1), B('%PDF-1.7')]))).family).to.equal('pdf');
    expect((await detectFile(Buffer.concat([Buffer.alloc(1024, 1), B('%PDF-1.7')]))).family).to.equal(undefined);
  });

  it('chooses text subtypes from the name and the declared type, the name first', async () => {
    const t = async (name?: string, declaredType?: string) => {
      const d = await detectFile(B('a,b\n'), { name, declaredType });
      return [d.mimeType, d.textTypes];
    };
    expect(await t()).to.deep.equal(['text/plain', ['txt']]);
    expect(await t('data.csv')).to.deep.equal(['text/csv', ['csv']]);
    expect(await t('data.tab')).to.deep.equal(['text/tab-separated-values', ['tsv']]);
    expect(await t('notes.markdown', 'text/csv')).to.deep.equal(['text/markdown', ['md', 'csv']]);
    expect(await t(undefined, 'text/csv; charset=utf-8')).to.deep.equal(['text/csv', ['csv']]);
  });

  it('calls text only what decodes and holds no control character but tab, line feed, form feed and carriage return', async () => {
    const family = async (b: Buffer) => (await detectFile(b)).family;
    expect(await family(B('tab\tcr\rlf\nff\f'))).to.equal('text');
    expect(await family(Buffer.alloc(0))).to.equal('text');
    expect(await family(B('nul\0'))).to.equal(undefined);
    expect(await family(B('bell\x07'))).to.equal(undefined);
    expect(await family(B('del\x7f'))).to.equal(undefined);
    expect(await family(Buffer.from('c1 \u0085', 'utf8'))).to.equal(undefined);
    expect(await family(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from([0x41, 0, 0x00, 0xd8, 0x42, 0])]))).to.equal(undefined);
    // Without a byte order mark, UTF-16 is not text: every other byte is NUL.
    expect(await family(Buffer.from('plain', 'utf16le'))).to.equal(undefined);
    const legacy = await detectFile(B('na\xefve\n'));
    expect([legacy.family, legacy.encoding, legacy.heuristic !== undefined]).to.deep.equal(['text', '8-bit', true]);
  });

  it('finds a 7z archive after a program, as archive-defuse does, and takes a run of zero bytes for lzma-alone', async () => {
    const sfx = Buffer.concat([fixture('formats/exe'), Buffer.alloc(200, 0x90), fixture('formats/7z')]);
    expect((await detectFile(sfx)).signatures.map(s => [s.mimeType, s.offset])).to.deep.equal([
      ['application/x-msdownload', 0],
      ['application/x-7z-compressed', 328],
    ]);
    expect((await detectFile(sfx, { name: 'setup.7z' })).family).to.equal('archive');
    // The lzma-alone test accepts a dictionary size of 0 and a size of 0, so 14 zero bytes pass it.
    expect((await detectFile(Buffer.alloc(14))).mimeType).to.equal('application/x-lzma');
  });

  it('finds a ZIP archive with data in front, which archive-defuse reads and office-defuse refuses', async () => {
    const prefixed = Buffer.concat([Buffer.alloc(300, 0xff), fixture('embedded.docx')]);
    const d = await detectFile(prefixed);
    expect([d.mimeType, d.family, d.signatures[0].offset]).to.deep.equal(['application/zip', 'archive', 300]);
  });

  it('stays bounded on a package whose [Content_Types].xml or mimetype inflates to gigabytes', async () => {
    const bomb = deflateBomb(16_000_000);
    // The data is real: its first kilobyte alone inflates to about a megabyte.
    expect(zlib.inflateRawSync(bomb.subarray(0, 1024), { finishFlush: zlib.constants.Z_SYNC_FLUSH }).length).to.be.above(1_000_000);
    const zip = zipOf([
      { name: '[Content_Types].xml', data: bomb, method: 8, size: 0xffffffff },
      { name: 'mimetype', data: bomb, method: 8, size: 0xffffffff },
    ]);
    const zipOnly = zipOf([{ name: 'mimetype', data: bomb, method: 8, size: 0xffffffff }]);
    const before = process.memoryUsage();
    const started = Date.now();
    const d = await detectFile(zip);
    const odf = await detectFile(zipOnly);
    const after = process.memoryUsage();
    expect(Date.now() - started).to.be.below(5000);
    expect(after.arrayBuffers - before.arrayBuffers).to.be.below(64 * 1024 * 1024);
    expect(after.heapUsed - before.heapUsed).to.be.below(64 * 1024 * 1024);
    // office-defuse cannot name either, so they are ZIP archives to archive-defuse, which stops the bomb when it reads.
    expect([d.family, odf.family]).to.deep.equal(['archive', 'archive']);
  });

  it('keeps entry names, schemes and extensions out of plain objects', async () => {
    const zip = zipOf([
      { name: '__proto__', data: B('x') },
      { name: 'constructor', data: B('x') },
    ]);
    expect((await detectFile(zip, { name: 'x.constructor', declaredType: '__proto__' })).family).to.equal('archive');
    const md = await inspectFile(B('[a](constructor:x) [b](__proto__:y) [c](toString:z)\n'), { name: 'notes.md' });
    expect(md.findings).to.deep.equal([]);
    expect(Object.getPrototypeOf({})).to.equal(Object.prototype);
  });

  it('closes the source when the detection ends', async () => {
    let closed = 0;
    const s = bufferSource(makePdf());
    await detectFileSource({
      size: () => s.size(),
      read: (o, l) => s.read(o, l),
      close: async () => {
        closed++;
      },
    });
    expect(closed).to.equal(1);
  });
});

describe('extensionOf', () => {
  it('drops the dots and spaces Windows drops, and reads a long run of them in linear time', () => {
    const cases: Array<[string | undefined, string | undefined]> = [
      ['page.html.', 'html'],
      ['Page.HTML. ', 'html'],
      ['archive.tar.gz', 'gz'],
      ['.bashrc', 'bashrc'],
      ['noext', undefined],
      ['a.b/c', undefined],
      ['a.b\\c', undefined],
      ['...', undefined],
      ['', undefined],
      [undefined, undefined],
    ];
    for (const [name, ext] of cases) expect([name, extensionOf(name)]).to.deep.equal([name, ext]);
    const started = Date.now();
    expect([extensionOf(`${'.'.repeat(200_000)}a`), extensionOf(`${' .'.repeat(100_000)}z`), extensionOf('.'.repeat(200_000))]).to.deep.equal(['a', 'z', undefined]);
    expect(Date.now() - started).to.be.lessThan(200);
  });
});
