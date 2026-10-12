import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { disarmImage } from '@patrickdk77/img-defuse';
import { OfficeCategory, OfficeDetail } from '@patrickdk77/office-defuse';
import { passThrough } from '@patrickdk77/pdf-defuse';
import { expect } from 'chai';
import { disarmFile, inspectFile } from '../src';
import { entryOf, fixture, kinds, line, makePdf, rejection } from './helpers/util';

describe('office section', () => {
  it('routes Office packages, compound files and RTF to office-defuse by content', async () => {
    expect((await inspectFile(fixture('embedded.docx'))).package).to.equal('office');
    expect((await inspectFile(fixture('passwords.docx'), { password: 'office pass' })).package).to.equal('office');
    const rtf = await inspectFile(Buffer.from('{\\rtf1\\ansi Hello}'));
    expect([rtf.status, rtf.package]).to.deep.equal(['clean', 'office']);
  });

  it('leaves a ZIP archive with no Office marker to archive-defuse, at the upload and inside a file', async () => {
    const r = await inspectFile(fixture('archive.zip'));
    expect([r.status, r.package, ...r.findings.map(line)]).to.deep.equal(['clean', 'archive', 'info ENTRY/PLUGIN_PASSED']);
    const inPdf = await inspectFile(makePdf({ attachments: [{ name: 'archive.zip', bytes: fixture('archive.zip') }] }));
    expect(inPdf.findings.map(line)).to.deep.equal(['info EMBEDDED_FILE/PLUGIN_PASSED', 'info ENTRY/PLUGIN_PASSED in archive.zip']);
  });

  it('counts depth through both packages, and applies office-defuse its own nesting limit as well', async () => {
    const docx = fixture('embedded.docx');
    expect((await inspectFile(docx, { limits: { nestingDepth: 3 } })).status).to.equal('strippable');
    expect((await inspectFile(docx, { limits: { nestingDepth: 2 } })).findings[0].data).to.deep.equal({ depth: 3, limit: 2 });
    const own = await inspectFile(docx, { office: { limits: { nestingDepth: 1 } } });
    expect([own.status, ...own.findings.map(line)]).to.deep.equal(['rejected', 'reject LIMIT/NESTING_DEPTH']);
  });

  it('gives the top-level password list to office-defuse, and a section password wins over it', async () => {
    const both = { password: ['pdf pass', 'office pass'] };
    expect((await inspectFile(fixture('passwords.docx'), { ...both, office: { password: 'wrong' } })).findings.map(line)).to.deep.equal(['reject ENCRYPTED/PASSWORD_REQUIRED']);
    const pdfWrong = await inspectFile(fixture('passwords.docx'), { ...both, pdf: { password: 'wrong' } });
    expect(pdfWrong.findings.map(line)).to.include('strip ENCRYPTED/PASSWORD_REQUIRED in word/embeddings/secret.pdf');
  });

  it('gives tempDir and memoryThreshold to office-defuse unless its section sets its own', async () => {
    const missing = path.join(os.tmpdir(), 'file-defuse-test-no-such-dir', 'x');
    const e = await rejection(disarmFile(fixture('embedded.docx'), { memoryThreshold: 0, tempDir: missing, pdf: { tempDir: os.tmpdir() } }));
    expect((e as { code?: string }).code).to.equal('ENOENT');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'file-defuse-test-'));
    try {
      const r = await disarmFile(fixture('embedded.docx'), { memoryThreshold: 0, tempDir: missing, pdf: { tempDir: dir }, office: { tempDir: dir } });
      expect(r.status).to.equal('defused');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("puts itself after the office section's own file plugins", async () => {
    const r = await inspectFile(fixture('embedded.docx'), { office: { filePlugins: [passThrough(['.pdf'])] } });
    const report = r.findings.find(f => f.location === 'word/embeddings/report.pdf' && f.category === 'EMBEDDED' && f.detail.startsWith('PLUGIN_'));
    expect(report?.data).to.deep.include({ plugin: 'passThrough(.pdf)' });
    expect(kinds(r.findings)).to.not.include('JAVASCRIPT/OPEN_ACTION');
    expect(r.findings.find(f => f.location === 'word/embeddings/notes.docx' && f.detail === 'PLUGIN_PASSED')?.data).to.deep.include({ plugin: 'file-defuse' });
  });

  it("weighs office-defuse's findings by its weights and the office section's scoreWeights, at every level", async () => {
    const r = await inspectFile(fixture('embedded.docx'), { office: { scoreWeights: [{ category: OfficeCategory.Embedded, detail: OfficeDetail.Package, weight: 5 }] } });
    const packages = r.findings.filter(f => f.detail === 'PACKAGE');
    expect(packages).to.have.length(3);
    for (const f of packages) expect(f.weight).to.equal(5);
    expect(r.findings.find(f => f.detail === 'OPEN_ACTION')?.weight).to.equal(70);
  });

  it('routes XPS, flat OpenDocument and Flat OPC to office-defuse, and their pictures back through file-defuse', async () => {
    for (const [name, picture] of [
      ['pages.xps', 'Resources/image.png'],
      ['flat.fodt', 'unnamed file'],
      ['flat-opc.xml', 'word/media/image1.png'],
    ]) {
      const r = await inspectFile(fixture(name));
      expect([r.package, r.status], name).to.deep.equal(['office', 'strippable']);
      expect(r.findings.map(line), name).to.include(`strip STRUCTURE/TRAILING_DATA in ${picture}`);
      const d = await disarmFile(fixture(name));
      expect(d.status, name).to.equal('defused');
      expect((await inspectFile(d.bytes ?? Buffer.alloc(0))).status, name).to.equal('clean');
    }
  });

  it("sends a picture in a .docx through img-defuse, and keeps img-defuse's copy in the rewritten .docx", async () => {
    const docx = fixture('picture.docx');
    const r = await inspectFile(docx);
    expect(r.findings.map(line)).to.deep.equal(['info EMBEDDED/PLUGIN_SCRUBBED', 'info METADATA/TEXT in word/media/image1.png', 'strip STRUCTURE/TRAILING_DATA in word/media/image1.png']);
    const trailing = r.findings[2];
    expect(trailing.location).to.equal('word/media/image1.png > offset 106');
    expect(trailing.weight).to.equal(10);
    const d = await disarmFile(docx);
    expect(d.status).to.equal('defused');
    const out = d.bytes ?? Buffer.alloc(0);
    const again = await inspectFile(out);
    expect([again.status, ...again.findings.map(line)]).to.deep.equal(['clean', 'info EMBEDDED/PLUGIN_PASSED', 'info METADATA/TEXT in word/media/image1.png']);
    // The picture in the output is the one img-defuse writes for the original.
    const original = entryOf(docx, 'word/media/image1.png') ?? Buffer.alloc(0);
    const defused = await disarmImage(original);
    expect(defused.status).to.equal('defused');
    expect(entryOf(out, 'word/media/image1.png')).to.deep.equal(Buffer.from(defused.bytes ?? []));
  });

  it('disarms a plain RTF upload', async () => {
    const d = await disarmFile(fixture('field.rtf'));
    expect([d.status, d.before.package, ...d.removed.map(line)]).to.deep.equal(['defused', 'office', 'strip DDE/FIELD']);
    const text = Buffer.from(d.bytes ?? []).toString('latin1');
    expect(text).to.not.include('DDEAUTO');
    expect(text).to.include('result');
    expect((await inspectFile(d.bytes ?? Buffer.alloc(0))).status).to.equal('clean');
  });

  it('routes an RTF object that holds a PDF through pdf-defuse', async () => {
    const r = await inspectFile(fixture('object.rtf'));
    expect(r.findings.map(line)).to.deep.equal(['info EMBEDDED/PLUGIN_SCRUBBED', 'strip JAVASCRIPT/OPEN_ACTION in report.pdf', 'info EMBEDDED/OLE_OBJECT']);
    // office-defuse's RTF rewrite only cuts. It cannot write the scrubbed PDF back, so the object goes.
    const d = await disarmFile(fixture('object.rtf'));
    expect(d.status).to.equal('defused');
    const text = Buffer.from(d.bytes ?? []).toString('latin1');
    expect(text).to.not.include('\\object');
    expect((await inspectFile(d.bytes ?? Buffer.alloc(0))).findings).to.deep.equal([]);
  });

  it('disarms a compound file holding an embedded PDF', async () => {
    const r = await inspectFile(fixture('message.msg'));
    expect([r.package, ...r.findings.map(line)]).to.deep.equal(['office', 'info EMBEDDED/PLUGIN_SCRUBBED', 'strip JAVASCRIPT/OPEN_ACTION in report.pdf', 'info EMBEDDED/ATTACHMENT']);
    const d = await disarmFile(fixture('message.msg'));
    expect(d.status).to.equal('defused');
    const out = d.bytes ?? Buffer.alloc(0);
    expect(out.subarray(0, 8)).to.deep.equal(Buffer.from('d0cf11e0a1b11ae1', 'hex'));
    const again = await inspectFile(out);
    expect([again.status, ...again.findings.map(line)]).to.deep.equal(['clean', 'info EMBEDDED/PLUGIN_PASSED', 'info EMBEDDED/ATTACHMENT']);
  });
});
