import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { inspectPdf, PdfCategory, PdfDetail, passThrough } from '@patrickdk77/pdf-defuse';
import { expect } from 'chai';
import {
  allFindingSpecs,
  bufferSink,
  bufferSource,
  type ContainedFile,
  DEFAULT_LIMITS,
  type DefuseFinding,
  disarmFile,
  disarmFileSource,
  FileCategory,
  FileDetail,
  filePlugin,
  inspectFile,
  inspectFileSource,
} from '../src';
import { fixture, kinds, line, makePdf, nest, rejection, slowSource } from './helpers/util';

const entry = (bytes: Buffer, depth: number, name = 'entry.pdf'): ContainedFile => ({ name, size: bytes.length, location: `entry ${name}`, depth, source: bufferSource(bytes) });
const asResult = (r: Awaited<ReturnType<ReturnType<typeof filePlugin>['process']>>) => (typeof r === 'string' ? { result: r } : r);
const own = (findings: DefuseFinding[]) => findings.filter(f => f.attachment === undefined);

describe('the upload', () => {
  it('reports which package read it and its score', async () => {
    const r = await inspectFile(fixture('clean.pdf'));
    expect(r).to.deep.equal({ status: 'clean', score: 0, risk: 'NONE', findings: [], package: 'pdf' });
  });

  it('goes by content, so a PDF after leading bytes still reaches pdf-defuse', async () => {
    const r = await inspectFile(Buffer.concat([Buffer.from('junk before the header\n'), fixture('clean.pdf')]));
    expect(r.package).to.equal('pdf');
    expect(kinds(r.findings)).to.include('CORRUPTED/LEADING_BYTES');
  });

  it('rejects a type no package reads, with the type detection gave it', async () => {
    const r = await inspectFile(fixture('formats/rar'));
    expect(r.status).to.equal('rejected');
    expect(r.package).to.equal(undefined);
    expect(r.findings[0]).to.include({ category: 'TYPE', detail: 'NO_PACKAGE', action: 'reject' });
    expect(r.findings[0].data).to.deep.equal({ sniffed: 'application/vnd.rar' });
    expect(r.findings[0].description).to.include('application/vnd.rar');
    expect((await inspectFile(fixture('unknown.bin'))).findings[0].data).to.equal(undefined);
  });

  it('sends a file to the package that claims it, whose own refusal names the problem', async () => {
    // A .docx cut short: no end record, so office-defuse cannot name it. Its first local header makes it a ZIP archive
    // to archive-defuse, whose reader says why it cannot read it.
    const cut = fixture('embedded.docx').subarray(0, 2000);
    const r = await inspectFile(cut);
    expect([r.status, r.package]).to.deep.equal(['rejected', 'archive']);
    expect(r.findings.map(f => `${f.category}/${f.detail}`)).to.include('CORRUPTED/UNPARSEABLE');
  });

  it('cannot strip an upload no package reads, so a strip override rejects it', async () => {
    const r = await disarmFile(fixture('unknown.bin'), { actionOverrides: [{ category: FileCategory.Type, action: 'strip' }] });
    expect(r.status).to.equal('rejected');
    expect(r.before.findings[0].action).to.equal('reject');
  });

  it('passes an upload no package reads through unchanged when the caller keeps such files', async () => {
    const bytes = fixture('unknown.bin');
    const r = await disarmFile(bytes, { actionOverrides: [{ category: FileCategory.Type, detail: FileDetail.NoPackage, action: 'info' }] });
    expect(r.status).to.equal('clean');
    expect(Buffer.from(r.bytes ?? [])).to.deep.equal(bytes);
    expect(r.before.risk).to.equal('UNKNOWN');
  });

  it('closes the source once, however the run ends', async () => {
    for (const name of ['clean.pdf', 'unknown.bin', 'loop.pdf']) {
      const s = slowSource(fixture(name), 0);
      await inspectFileSource(s);
      expect(s.closed, name).to.equal(1);
      const d = slowSource(fixture(name), 0);
      await disarmFileSource(d, bufferSink());
      expect(d.closed, name).to.equal(1);
    }
  });

  it('fails the run on an I/O error instead of giving a verdict', async () => {
    const bytes = fixture('nested.pdf');
    const source = {
      size: async () => bytes.length,
      read: async (o: number, l: number) => (o > 0 ? Promise.reject(Object.assign(new Error('EIO: injected'), { code: 'EIO' })) : bytes.subarray(o, o + l)),
    };
    const e = await rejection(inspectFileSource(source));
    expect((e as { code?: string }).code).to.equal('EIO');
  });

  it('leaves the sink untouched when it rejects', async () => {
    let touched = 0;
    const touch = async () => {
      touched++;
    };
    const sink = { write: touch, close: touch, abort: touch };
    const r = await disarmFileSource(bufferSource(fixture('loop.pdf')), sink);
    expect(r.status).to.equal('rejected');
    expect(touched).to.equal(0);
  });
});

describe('tree limits', () => {
  it('has defaults for depth, files and decoded bytes, and none for size and time', () => {
    expect(DEFAULT_LIMITS).to.deep.equal({ nestingDepth: 10, files: 10_000, decodedBytes: 2 * 1024 ** 3 });
  });

  it('counts depth from the upload, whatever package found the file', async () => {
    const doc = nest(3, makePdf());
    expect((await inspectFile(doc, { limits: { nestingDepth: 3 } })).status).to.equal('clean');
    const r = await inspectFile(doc, { limits: { nestingDepth: 2 } });
    expect(r.findings.map(line)).to.deep.equal(['reject LIMIT/NESTING_DEPTH']);
    expect(r.findings[0].data).to.deep.equal({ depth: 3, limit: 2 });
  });

  it('counts only the files it hands to a package, not the upload', async () => {
    expect((await inspectFile(fixture('clean.pdf'), { limits: { files: 0 } })).status).to.equal('clean');
    // Of the four attachments, the text, the PNG and the PDF reach a package. pdf-defuse decides the executable.
    const r = await inspectFile(fixture('mixed.pdf'), { limits: { files: 3 } });
    expect(r.status).to.equal('strippable');
    expect((await inspectFile(fixture('mixed.pdf'), { limits: { files: 2 } })).findings.map(line)).to.include('reject LIMIT/FILE_COUNT');
  });

  it('adds up decoded sizes across levels', async () => {
    const inner = makePdf();
    const doc = nest(2, inner);
    const level1 = makePdf({ attachments: [{ name: 'level2.pdf', bytes: inner }] });
    const total = level1.length + inner.length;
    expect((await inspectFile(doc, { limits: { decodedBytes: total } })).status).to.equal('clean');
    expect((await inspectFile(doc, { limits: { decodedBytes: total - 1 } })).findings.map(line)).to.deep.equal(['reject LIMIT/DECODED_SIZE']);
  });

  it('shares one deadline with every level, and rejects for time', async () => {
    const s = slowSource(fixture('nested.pdf'), 20);
    const r = await inspectFileSource(s, { limits: { timeMs: 30 } });
    expect(r.findings.map(line)).to.deep.equal(['reject LIMIT/TIME']);
    expect([r.status, r.score, r.risk]).to.deep.equal(['rejected', null, 'UNKNOWN']);
  });

  it("caps pdf-defuse's own time limit with what is left of the tree's", async () => {
    // clean.pdf holds no file, so only pdf-defuse's own checks can stop it.
    const options = { pdf: { limits: { timeMs: 900_000 } } };
    expect((await inspectFileSource(slowSource(fixture('clean.pdf'), 20), options)).status).to.equal('clean');
    const r = await inspectFileSource(slowSource(fixture('clean.pdf'), 20), { ...options, limits: { timeMs: 30 } });
    expect(r.findings.map(line)).to.deep.equal(['reject LIMIT/TIME']);
  });

  it('reports a limit only file-defuse counts under its own detail, in place of the time limit a package would name', async () => {
    const r = await inspectFile(fixture('wide.pdf'), { limits: { files: 3 } });
    expect(kinds(own(r.findings)).filter(k => k.startsWith('LIMIT/'))).to.deep.equal(['LIMIT/FILE_COUNT']);
    expect(r.findings.at(-1)?.description).to.equal('The upload holds more files than the file count limit allows');
  });

  it('stops a file that holds itself at the nesting depth', async () => {
    const r = await inspectFile(fixture('loop.pdf'), { limits: { nestingDepth: 5 } });
    expect(r.findings[0].data).to.deep.equal({ depth: 6, limit: 5 });
  });

  it('rejects an upload over the size limit without reading it', async () => {
    let reads = 0;
    const bytes = fixture('nested.pdf');
    const read = async () => {
      reads++;
      return bytes;
    };
    const r = await inspectFileSource({ size: async () => bytes.length, read }, { limits: { fileSize: bytes.length - 1 } });
    expect(r.findings[0]).to.include({ category: 'LIMIT', detail: 'FILE_SIZE' });
    expect(r.findings[0].data).to.deep.equal({ size: bytes.length });
    expect(reads).to.equal(0);
  });
});

describe('options for the packages', () => {
  it('gives the top-level password list to every PDF, and a section password wins over it', async () => {
    const both = { password: ['outer pass', 'inner pass'] };
    expect((await inspectFile(fixture('passwords.pdf'), both)).findings.map(line)).to.include('strip JAVASCRIPT/OPEN_ACTION in inner.pdf');
    const r = await inspectFile(fixture('passwords.pdf'), { ...both, pdf: { password: 'wrong' } });
    expect(r.findings.map(line)).to.deep.equal(['reject ENCRYPTED/PASSWORD_REQUIRED']);
  });

  it('gives stripMetadata to every PDF unless the section sets its own', async () => {
    const doc = makePdf({ info: true, attachments: [{ name: 'inner.pdf', bytes: makePdf({ info: true }) }] });
    const on = await inspectFile(doc, { stripMetadata: true });
    expect(on.findings.map(line)).to.include.members(['info METADATA/STRIPPED', 'info METADATA/STRIPPED in inner.pdf']);
    const off = await inspectFile(doc, { stripMetadata: true, pdf: { stripMetadata: false } });
    expect(kinds(off.findings)).to.not.include('METADATA/STRIPPED');
  });

  it('gives memoryThreshold and tempDir to every PDF unless the section sets its own', async () => {
    const doc = fixture('nested.pdf');
    const spilled = await inspectFile(doc, { memoryThreshold: 0 });
    expect(kinds(spilled.findings)).to.include('PROCESSING/MEMORY_FALLBACK');
    const missing = path.join(os.tmpdir(), 'file-defuse-test-no-such-dir', 'x');
    const e = await rejection(inspectFile(doc, { memoryThreshold: 0, tempDir: missing }));
    expect((e as { code?: string }).code).to.equal('ENOENT');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'file-defuse-test-'));
    try {
      expect((await inspectFile(doc, { memoryThreshold: 0, tempDir: missing, pdf: { tempDir: dir } })).status).to.equal('strippable');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("puts itself after the caller's own file plugins", async () => {
    const r = await inspectFile(fixture('nested.pdf'), { pdf: { filePlugins: [passThrough(['.pdf'])] } });
    expect(r.findings).to.have.length(1);
    expect(r.findings[0]).to.include({ category: 'EMBEDDED_FILE', detail: 'PLUGIN_PASSED' });
    expect(r.findings[0].data).to.deep.include({ plugin: 'passThrough(.pdf)' });
  });

  it("applies each section's own limits to its package's runs, for the upload and for every file inside it", async () => {
    const limits = (r: { findings: DefuseFinding[] }) => r.findings.filter(f => f.category === 'LIMIT').map(line);
    expect(limits(await inspectFile(fixture('clean.pdf'), { pdf: { limits: { objects: 3 } } }))).to.deep.equal(['reject LIMIT/OBJECT_COUNT']);
    expect(limits(await inspectFile(fixture('embedded.docx'), { office: { limits: { entries: 2 } } }))).to.deep.equal(['reject LIMIT/ENTRY_COUNT']);
    // The 2 x 2 PNG fits a limit of 10 pixels, and the 8 x 8 JPEG inside the same PDF does not.
    const images = await inspectFile(fixture('images.pdf'), { image: { limits: { pixels: 10 } } });
    expect(images.status).to.equal('strippable');
    expect(limits(images)).to.deep.equal(['strip LIMIT/PIXELS in photo.jpg > EXIF thumbnail', 'strip LIMIT/PIXELS in photo.jpg']);
    expect(images.findings.map(line)).to.include('info METADATA/TEXT in chart.png');
  });

  it("weighs every finding by its package's weights and the section's scoreWeights", async () => {
    const r = await inspectFile(fixture('nested.pdf'), { pdf: { scoreWeights: [{ category: PdfCategory.EmbeddedFile, detail: PdfDetail.PluginScrubbed, weight: 7 }] } });
    const scrubbed = r.findings.filter(f => f.detail === 'PLUGIN_SCRUBBED');
    expect(scrubbed).to.have.length(4);
    for (const f of scrubbed) expect(f.weight).to.equal(7);
    expect(r.findings.find(f => f.detail === 'OPEN_ACTION')?.weight).to.equal(70);
  });
});

describe('filePlugin', () => {
  it('routes files inside a pdf-defuse run of the caller', async () => {
    const r = await inspectPdf(nest(2, makePdf({ js: true })), { filePlugins: [filePlugin()] });
    expect(r.findings.map(line)).to.include('strip JAVASCRIPT/OPEN_ACTION in level1.pdf > level2.pdf');
  });

  it('accepts files a package reads, by content alone', async () => {
    const p = filePlugin();
    expect(await p.accepts({ ...entry(makePdf(), 1, 'notes.txt'), declaredType: 'text/plain' })).to.equal(true);
    expect(await p.accepts({ ...entry(fixture('unknown.bin'), 1, 'report.pdf'), declaredType: 'application/pdf', sniffedType: 'application/pdf' })).to.equal(false);
    // Text a name calls a PDF is text, and the text rules take it.
    expect(await p.accepts({ ...entry(Buffer.from('plain text'), 1, 'report.pdf'), declaredType: 'application/pdf' })).to.equal(true);
  });

  it('counts the file it gets as the root of its own tree', async () => {
    // Each child of wide.pdf is a tree of one file, so a file limit of 0 stops none of them.
    const r = await inspectPdf(fixture('wide.pdf'), { filePlugins: [filePlugin({ limits: { files: 0 } })] });
    expect(r.status).to.equal('clean');
  });

  it('throws a tree limit with the DEFUSE_LIMIT code below the upload', async () => {
    const e = await rejection(filePlugin({ limits: { nestingDepth: 2 } }).process(entry(nest(2, makePdf()), 1), bufferSink(), { depth: 1 }));
    expect(e).to.include({ code: 'DEFUSE_LIMIT', limit: 'nesting' });
  });

  it('passes an I/O error from inside a file up with the DEFUSE_IO code', async () => {
    const bytes = nest(1, makePdf());
    const failing: ContainedFile = {
      ...entry(bytes, 1),
      source: { size: async () => bytes.length, read: async (o, l) => (o > 0 ? Promise.reject(Object.assign(new Error('EIO: injected'), { code: 'EIO' })) : bytes.subarray(o, o + l)) },
    };
    const e = await rejection(filePlugin().process(failing, bufferSink(), { depth: 1 }));
    expect((e as { code?: string }).code).to.equal('DEFUSE_IO');
  });

  it('treats a file at depth 0 as the upload: a limit gives a finding, and the source is closed', async () => {
    const s = slowSource(fixture('loop.pdf'), 0);
    const r = asResult(await filePlugin().process({ size: await s.size(), location: 'upload', depth: 0, source: s }, bufferSink(), { depth: 0 }));
    expect(r.result).to.equal('removed');
    expect((r.findings ?? []).map(line)).to.deep.equal(['reject LIMIT/NESTING_DEPTH']);
    expect(s.closed).to.equal(1);
  });

  it('returns NO_PACKAGE for a file no package reads that it gets anyway', async () => {
    const r = asResult(await filePlugin().process(entry(fixture('unknown.bin'), 0), bufferSink(), { depth: 0 }));
    expect(r.result).to.equal('removed');
    expect((r.findings ?? []).map(line)).to.deep.equal(['reject TYPE/NO_PACKAGE']);
    const kept = asResult(await filePlugin({ actionOverrides: [{ category: FileCategory.Type, action: 'info' }] }).process(entry(fixture('unknown.bin'), 0), bufferSink(), { depth: 0 }));
    expect(kept.result).to.equal('passed');
  });

  it('removes a file over the size limit without a code, as a package does', async () => {
    const r = asResult(await filePlugin({ limits: { fileSize: 10 } }).process(entry(makePdf(), 2), bufferSink(), { depth: 2 }));
    expect(r.result).to.equal('removed');
    expect((r.findings ?? []).map(line)).to.deep.equal(['reject LIMIT/FILE_SIZE']);
  });
});

describe('finding specs', () => {
  it('lists every kind file-defuse makes, with its default action and weight', () => {
    const specs = allFindingSpecs().map(s => `${s.action} ${s.weight} ${s.category}/${s.detail}`);
    expect(specs).to.deep.equal([
      'reject 0 TYPE/NO_PACKAGE',
      'strip 50 TYPE/POLYGLOT',
      'reject 0 LIMIT/FILE_SIZE',
      'reject 0 LIMIT/NESTING_DEPTH',
      'reject 0 LIMIT/FILE_COUNT',
      'reject 0 LIMIT/DECODED_SIZE',
      'reject 0 LIMIT/TIME',
      'strip 10 TEXT/ENCODING',
      'info 0 TEXT/UNNAMED_ENCODING',
      'strip 10 TEXT/CONTROL_CHARACTER',
      'strip 30 TEXT/BIDI_CONTROL',
      'strip 50 TEXT/FORMULA',
      'reject 0 TEXT/UNCLOSED_QUOTE',
      'strip 50 LINK/SCRIPT_URL',
      'strip 60 LINK/DATA_URL',
      'reject 0 PROCESSING/VERIFICATION_FAILED',
    ]);
  });
});
