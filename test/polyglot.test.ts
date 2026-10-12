import { expect } from 'chai';
import { type DefuseFinding, detectFile, disarmFile, FileCategory, FileDetail, inspectFile } from '../src';
import { fixture, line, makePdf } from './helpers/util';

const polyglot = (findings: DefuseFinding[]) => findings.filter(f => f.category === 'TYPE' && f.detail === 'POLYGLOT');

describe('polyglots', () => {
  describe('a JPEG with a ZIP archive after it', () => {
    const bytes = fixture('jpeg-zip.bin');
    // The ZIP archive starts at its first local header. img-defuse names it at its end record, where ZIP readers look.
    const zipAt = bytes.indexOf('PK\x03\x04');
    const endRecord = bytes.length - 22;

    it('named .jpg: handled as the JPEG, and the archive is removed', async () => {
      const r = await inspectFile(bytes, { name: 'photo.jpg' });
      expect([r.status, r.package]).to.deep.equal(['strippable', 'image']);
      const [f] = polyglot(r.findings);
      expect(f).to.include({ action: 'strip', location: `offset ${zipAt}` });
      expect(f.data).to.deep.equal({ type: 'application/zip', offset: zipAt, handledAs: 'image/jpeg', reason: 'name' });
      expect(f.description).to.equal(`The file is also application/zip, at offset ${zipAt}. It is handled as image/jpeg, chosen by its name, and the application/zip part is removed`);
      // img-defuse reports the same signature at the same offset, so the router's finding adds nothing to the score.
      expect(r.findings.find(x => x.category === 'POLYGLOT' && x.detail === 'ZIP')?.data).to.deep.equal({ offset: endRecord });
      expect(f.weight).to.equal(0);
      expect(r.score).to.equal((await inspectFile(bytes, { name: 'photo.jpg', actionOverrides: [{ category: FileCategory.Type, detail: FileDetail.Polyglot, action: 'info' }] })).score);
      const d = await disarmFile(bytes, { name: 'photo.jpg' });
      expect(d.status).to.equal('defused');
      expect(d.removed.map(line)).to.include('strip TYPE/POLYGLOT');
      const out = await detectFile(d.bytes ?? Buffer.alloc(0));
      expect(out.signatures.map(s => s.mimeType)).to.deep.equal(['image/jpeg']);
    });

    it('without a name: the signature at the start wins', async () => {
      const r = await inspectFile(bytes);
      expect(r.package).to.equal('image');
      expect(polyglot(r.findings)[0].data?.reason).to.equal('firstSignature');
      expect(polyglot(r.findings)[0].description).to.include('chosen by the signature at its start');
    });

    it('named .zip, or declared application/zip: handled as the archive, and the JPEG in front of it is removed', async () => {
      for (const options of [{ name: 'photo.zip' }, { declaredType: 'application/zip' }]) {
        const r = await inspectFile(bytes, options);
        expect([r.status, r.package, ...r.findings.map(line)]).to.deep.equal([
          'strippable',
          'archive',
          'strip TYPE/POLYGLOT',
          'strip STRUCTURE/OFFSET_SHIFT',
          'strip STRUCTURE/LEADING_BYTES',
          'strip STRUCTURE/POLYGLOT',
          'info ENTRY/PLUGIN_PASSED',
        ]);
        const [f] = polyglot(r.findings);
        expect(f.data).to.deep.equal({ type: 'image/jpeg', offset: 0, handledAs: 'application/zip', reason: options.name ? 'name' : 'declaredType' });
        expect(f.description).to.include('the image/jpeg part is removed');
        const d = await disarmFile(bytes, options);
        expect(d.status).to.equal('defused');
        expect((await detectFile(d.bytes ?? Buffer.alloc(0))).signatures.map(s => s.mimeType)).to.deep.equal(['application/zip']);
      }
    });
  });

  describe('a PDF with a ZIP archive after it', () => {
    const bytes = fixture('pdf-zip.bin');

    it('named .pdf or unnamed: handled as the PDF, and the archive is removed', async () => {
      for (const options of [{ name: 'report.pdf' }, {}]) {
        const r = await inspectFile(bytes, options);
        expect([r.status, r.package, ...r.findings.map(line)]).to.deep.equal(['strippable', 'pdf', 'strip TYPE/POLYGLOT', 'strip CORRUPTED/TRAILING_BYTES']);
        // pdf-defuse does not report polyglots, so the router's finding scores at its weight, the family's way.
        expect(polyglot(r.findings)[0].weight).to.equal(50);
        expect(r.score).to.equal(53);
        const d = await disarmFile(bytes, options);
        expect([d.status, ...d.removed.map(line)]).to.deep.equal(['defused', 'strip TYPE/POLYGLOT', 'strip CORRUPTED/TRAILING_BYTES']);
        expect((await detectFile(d.bytes ?? Buffer.alloc(0))).signatures.length).to.equal(1);
      }
    });

    it('named .zip: handled as the archive, and the PDF in front of it is removed', async () => {
      const r = await inspectFile(bytes, { name: 'report.zip' });
      expect(r.findings.map(line)).to.deep.equal(['strip TYPE/POLYGLOT', 'strip STRUCTURE/OFFSET_SHIFT', 'strip STRUCTURE/LEADING_BYTES', 'strip STRUCTURE/POLYGLOT', 'info ENTRY/PLUGIN_PASSED']);
      expect(polyglot(r.findings)[0].data).to.deep.include({ type: 'application/pdf', offset: 0, handledAs: 'application/zip' });
      const d = await disarmFile(bytes, { name: 'report.zip' });
      expect((await detectFile(d.bytes ?? Buffer.alloc(0))).signatures.map(s => s.mimeType)).to.deep.equal(['application/zip']);
    });
  });

  it('rejects a polyglot whose second format sits in data the first one needs', async () => {
    const r = await inspectFile(fixture('inseparable.jpg'));
    expect([r.status, ...r.findings.map(line)]).to.deep.equal(['rejected', 'reject TYPE/POLYGLOT', 'reject POLYGLOT/IMAGE_DATA']);
    const [f] = polyglot(r.findings);
    expect(f.data).to.deep.equal({ type: 'application/pdf', offset: 7, handledAs: 'image/jpeg', reason: 'firstSignature' });
    expect(f.weight).to.equal(0);
    expect((await disarmFile(fixture('inseparable.jpg'))).status).to.equal('rejected');
  });

  it('takes the claim of a file inside a container from the container', async () => {
    const r = await inspectFile(fixture('polyglots.pdf'));
    const asJpeg = polyglot(r.findings).find(f => f.attachment === 'photo.jpg');
    expect(asJpeg?.data).to.deep.equal({ type: 'application/zip', offset: fixture('jpeg-zip.bin').indexOf('PK\x03\x04'), handledAs: 'image/jpeg', reason: 'name' });
    // The attachment named photo.zip is the archive, which archive-defuse reads, and the JPEG in front of it goes.
    expect(r.findings.filter(f => f.data?.name === 'photo.zip').map(line)).to.deep.equal(['info EMBEDDED_FILE/TYPE_MISMATCH', 'info EMBEDDED_FILE/PLUGIN_SCRUBBED']);
    const d = await disarmFile(fixture('polyglots.pdf'));
    expect(d.status).to.equal('defused');
    expect((await inspectFile(d.bytes ?? Buffer.alloc(0))).status).to.equal('clean');
  });

  it('checks the output again and rejects it when the rewrite left a second format, whichever package wrote it', async () => {
    // The PDF header sits past the first 1024 bytes until xml-defuse removes the script in front of it.
    const bytes = Buffer.from(`<!doctype html><html><head><script>${'var x = 1;\n'.repeat(120)}</script></head><body><p>%PDF-1.7 is a version string.</p></body></html>\n`);
    expect((await detectFile(bytes)).signatures.length).to.equal(1);
    expect((await inspectFile(bytes)).status).to.equal('strippable');
    const d = await disarmFile(bytes);
    expect(d.status).to.equal('rejected');
    const failed = d.before.findings.find(f => f.category === 'PROCESSING' && f.detail === 'VERIFICATION_FAILED');
    expect(failed?.action).to.equal('reject');
    expect(String(failed?.data?.reasons)).to.match(/^application\/pdf at offset \d+$/);
    // Inside a container the file goes, and the container keeps going.
    const inPdf = await disarmFile(makePdf({ attachments: [{ name: 'page.html', bytes }] }));
    expect(inPdf.status).to.equal('defused');
    expect(inPdf.before.findings.map(line)).to.include('strip PROCESSING/VERIFICATION_FAILED in page.html');
  });

  it('keeps the extra part when an override makes TYPE/POLYGLOT info, and does not hold it against the output', async () => {
    const options = { name: 'report.pdf', actionOverrides: [{ category: FileCategory.Type, detail: FileDetail.Polyglot, action: 'info' as const }] };
    const r = await inspectFile(fixture('pdf-zip.bin'), options);
    expect(polyglot(r.findings)[0].description).to.include('the application/zip part is kept');
    expect((await disarmFile(fixture('pdf-zip.bin'), options)).status).to.equal('defused');
  });
});
