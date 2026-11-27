import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import { inspectPdf } from '@patrickdk77/pdf-defuse';
import { expect } from 'chai';
import {
  bufferSink,
  bufferSource,
  type ContainedFile,
  type DefuseFinding,
  disarmFile,
  FileCategory as FC,
  FileDetail as FD,
  type FileDisarmResult,
  type FileOptions,
  filePlugin,
  inspectFile,
} from '../src';
import { checkNodeVersion, type Flattener, type FlattenNote, loadFlattener, setFlattenerLoader } from '../src/flatten';
import { crc32, entryOf, kinds, line, makePdf, rejection, runCli, zipOf } from './helpers/util';
import { drawnText, FORM_TEXT, makeXfaForm } from './helpers/xfa';

/** The engines.node of the installed xfa-flatten. */
const engines = (JSON.parse(fs.readFileSync(require.resolve('@patrickdk77/xfa-flatten/package.json'), 'utf8')) as { engines: { node: string } }).engines.node;

/** True when this Node meets xfa-flatten's floor. Below it, every disarm with the option on must throw. */
const canFlatten = (() => {
  try {
    checkNodeVersion(process.versions.node, engines);
    return true;
  } catch {
    return false;
  }
})();

const OLD_NODE =
  /^The flattenXfa option needs Node 22\.13\.0 or later, as @patrickdk77\/xfa-flatten declares in engines\.node, and this is Node v?[\d.]+\. Install @patrickdk77\/xfa-flatten and run Node 22\.13 or later\.$/;
const NOT_LOADABLE = /^The flattenXfa option needs @patrickdk77\/xfa-flatten, which could not be loaded: .+\. Install @patrickdk77\/xfa-flatten and run Node 22\.13 or later\.$/;

/** A ZIP archive of deflated entries, so no PDF inside it shows as a second format of the archive. */
const zipped = (entries: Array<{ name: string; data: Buffer }>) => zipOf(entries.map(e => ({ name: e.name, data: zlib.deflateRawSync(e.data), method: 8, size: e.data.length, crc: crc32(e.data) })));

const squash = (s: string) => s.replace(/\s+/g, '');
const latin1 = (b: Uint8Array | undefined) => Buffer.from(b ?? new Uint8Array(0)).toString('latin1');
const flattenFindings = (findings: DefuseFinding[] | undefined) => (findings ?? []).filter(f => f.category === FC.Flatten);

/**
 * disarmFile with the flattenXfa option on. Below xfa-flatten's Node floor, it checks that the disarm throws the error
 * that says so, and returns undefined for the test to end there.
 */
async function flattened(bytes: Uint8Array, options: FileOptions = {}): Promise<(FileDisarmResult & { bytes?: Uint8Array }) | undefined> {
  const run = disarmFile(bytes, { flattenXfa: true, ...options });
  if (canFlatten) return run;
  const e = await rejection(run);
  expect(e).to.be.instanceOf(Error);
  expect((e as Error).message).to.match(OLD_NODE);
  return undefined;
}

describe('flattenXfa', () => {
  it('draws a dynamic XFA upload as a plain PDF of its pages, with the form and its data in it', async () => {
    const form = makeXfaForm({ rows: 30 });
    const r = await flattened(form);
    if (!r) return;
    expect(r.status).to.equal('defused');
    const xfa = r.before.findings.find(f => f.category === FC.Flatten);
    expect(xfa).to.deep.include({ category: 'FLATTEN', detail: 'XFA', action: 'strip', weight: 0, data: { pages: 2 } });
    expect(r.removed.map(line)).to.deep.equal(['strip FLATTEN/XFA']);
    // inspect and disarm agree on the score of the upload.
    const inspected = await inspectFile(form);
    expect(r.before.score).to.equal(inspected.score);
    expect(r.before.status).to.equal('strippable');
    const raw = latin1(r.bytes);
    for (const key of ['/XFA', '/NeedsRendering', '/AcroForm']) expect(raw, key).to.not.include(key);
    expect((await inspectPdf(r.bytes ?? new Uint8Array(0))).pages).to.equal(2);
    const text = drawnText(r.bytes ?? new Uint8Array(0));
    for (const t of [...FORM_TEXT, 'Rowan Thistlewood', 'Bed row 30 heirloom squash']) expect(text).to.include(squash(t));
    expect(r.after?.status).to.equal('clean');
    expect(flattenFindings(r.after?.findings)).to.deep.equal([]);
    const again = await inspectFile(r.bytes ?? new Uint8Array(0));
    expect(again.findings.filter(f => f.action !== 'info')).to.deep.equal([]);
  });

  it('leaves the XFA form when the option is off', async () => {
    const r = await disarmFile(makeXfaForm({ rows: 30 }));
    expect(r.status).to.equal('clean');
    expect(latin1(r.bytes)).to.include('/XFA');
    expect(kinds(r.before.findings)).to.include('FORM/XFA');
    expect(flattenFindings(r.before.findings)).to.deep.equal([]);
  });

  it('changes nothing for a PDF without XFA or a form that is not pure XFA', async () => {
    for (const bytes of [makePdf({ js: true, info: true }), makeXfaForm({ staticForm: true })]) {
      const r = await flattened(bytes);
      if (!r) return;
      expect(r).to.deep.equal(await disarmFile(bytes));
    }
  });

  it('flattens a dynamic form inside a ZIP archive or attached to a PDF', async () => {
    const form = makeXfaForm({ rows: 2 });
    const zip = zipped([
      { name: 'plot.pdf', data: form },
      { name: 'notes.txt', data: Buffer.from('Water the beds on Tuesday.\n') },
    ]);
    const r = await flattened(zip);
    if (!r) return;
    expect(r.status).to.equal('defused');
    expect(r.before.findings.map(line)).to.include('strip FLATTEN/XFA in plot.pdf');
    expect(r.removed.map(line)).to.include('strip FLATTEN/XFA in plot.pdf');
    const inner = entryOf(r.bytes ?? new Uint8Array(0), 'plot.pdf');
    expect(latin1(inner)).to.not.include('/XFA');
    expect(drawnText(inner ?? new Uint8Array(0))).to.include(squash(FORM_TEXT[0]));
    expect(entryOf(r.bytes ?? new Uint8Array(0), 'notes.txt')?.toString()).to.equal('Water the beds on Tuesday.\n');

    const pdf = await flattened(makePdf({ attachments: [{ name: 'plot.pdf', bytes: form }] }));
    if (!pdf) return;
    expect(pdf.before.findings.map(line)).to.include('strip FLATTEN/XFA in plot.pdf');
    const raw = latin1(pdf.bytes);
    expect(raw).to.include('/EmbeddedFile');
    expect(raw).to.not.include('/XFA');
  });

  it('keeps pdf-defuse output, with FLATTEN/FAILED, when pdf.js cannot lay the form out', async () => {
    const bare = makeXfaForm({ bareTemplate: true });
    const r = await flattened(bare);
    if (!r) return;
    const without = await disarmFile(bare);
    expect(r.status).to.equal(without.status);
    expect(Buffer.from(r.bytes ?? new Uint8Array(0)).equals(Buffer.from(without.bytes ?? new Uint8Array(0)))).to.equal(true);
    expect(latin1(r.bytes)).to.include('/XFA');
    const failed = flattenFindings(r.after?.findings);
    expect(failed.map(line)).to.deep.equal(['info FLATTEN/FAILED']);
    expect(failed[0].data?.kind).to.equal('layout-error');
    expect(failed[0].description).to.match(/^The dynamic XFA form could not be flattened, so it stays as pdf-defuse cleaned it: pdf\.js could not open or lay out the form/);
    expect(failed[0].description).to.include('no template in the XFA template namespace');
    expect(flattenFindings(r.before.findings)).to.deep.equal([]);
    expect(r.removed).to.deep.equal(without.removed);
  });

  it('rejects a form that does not flatten when FLATTEN/FAILED is overridden to reject, and to strip', async () => {
    for (const action of ['reject', 'strip'] as const) {
      const r = await flattened(makeXfaForm({ bareTemplate: true }), { actionOverrides: [{ category: FC.Flatten, detail: FD.Failed, action }] });
      if (!r) return;
      expect(r.status).to.equal('rejected');
      expect(r.bytes).to.equal(undefined);
      expect(r.before.status).to.equal('rejected');
      expect(flattenFindings(r.before.findings).map(line)).to.deep.equal(['reject FLATTEN/FAILED']);
    }
    // A form that flattens still passes.
    const ok = await flattened(makeXfaForm(), { actionOverrides: [{ category: FC.Flatten, detail: FD.Failed, action: 'reject' }] });
    expect(ok?.status).to.equal('defused');
  });

  it('keeps the form when FLATTEN/XFA is overridden to info, and rejects it on reject', async () => {
    const form = makeXfaForm();
    const kept = await flattened(form, { actionOverrides: [{ category: FC.Flatten, detail: FD.Xfa, action: 'info' }] });
    if (!kept) return;
    const without = await disarmFile(form);
    expect(Buffer.from(kept.bytes ?? new Uint8Array(0)).equals(Buffer.from(without.bytes ?? new Uint8Array(0)))).to.equal(true);
    expect(flattenFindings(kept.before.findings).map(line)).to.deep.equal(['info FLATTEN/XFA']);
    expect([kept.status, kept.removed]).to.deep.equal([without.status, []]);
    const refused = await flattened(form, { actionOverrides: [{ category: FC.Flatten, action: 'reject' }] });
    expect(refused?.status).to.equal('rejected');
    expect(flattenFindings(refused?.before.findings).map(line)).to.deep.equal(['reject FLATTEN/XFA']);
  });

  it('flattens an encrypted form that the password opens', async () => {
    const r = await flattened(makeXfaForm({ password: 'marrow-7' }), { password: ['wrong-one', 'marrow-7'] });
    if (!r) return;
    expect(r.status).to.equal('defused');
    expect(r.removed.map(line)).to.deep.equal(['strip ENCRYPTED/USER_PASSWORD', 'strip FLATTEN/XFA']);
    const raw = latin1(r.bytes);
    expect(raw).to.not.include('/Encrypt');
    expect(raw).to.not.include('/XFA');
    expect(drawnText(r.bytes ?? new Uint8Array(0))).to.include(squash('Rowan Thistlewood'));
  });

  it('flattens with filePlugin, and never in an inspection', async () => {
    const form = makeXfaForm();
    const file: ContainedFile = { name: 'plot.pdf', size: form.length, location: 'entry plot.pdf', depth: 1, source: bufferSource(form) };
    if (!canFlatten) expect(() => filePlugin({ flattenXfa: true })).to.throw(OLD_NODE);
    else {
      const sink = bufferSink();
      const out = await filePlugin({ flattenXfa: true }).process(file, sink, { depth: 1 });
      const r = typeof out === 'string' ? { result: out } : out;
      expect(r.result).to.equal('scrubbed');
      expect((r.findings ?? []).map(line)).to.include('strip FLATTEN/XFA');
      expect(latin1(sink.result())).to.not.include('/XFA');
    }
    expect(await inspectFile(form, { flattenXfa: true })).to.deep.equal(await inspectFile(form));
  });

  it('takes --flatten-xfa on the command line', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'file-defuse-flatten-'));
    try {
      const input = path.join(dir, 'plot.pdf');
      const output = path.join(dir, 'out.pdf');
      fs.writeFileSync(input, makeXfaForm());
      const r = runCli(['defuse', input, output, '--flatten-xfa']);
      if (!canFlatten) {
        expect(r.status).to.equal(3);
        expect(r.stderr.toString()).to.include('Install @patrickdk77/xfa-flatten and run Node 22.13 or later');
        return;
      }
      expect(r.status).to.equal(1);
      expect(r.stdout.toString()).to.include('strip  FLATTEN/XFA');
      expect(fs.readFileSync(output, 'latin1')).to.not.include('/XFA');
      expect(runCli(['defuse', input, output]).status).to.equal(0);
      expect(fs.readFileSync(output, 'latin1')).to.include('/XFA');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('loading xfa-flatten', () => {
  afterEach(() => setFlattenerLoader());

  it('checks the Node version against the floor engines.node declares', () => {
    for (const v of ['22.13.0', '22.13.1', '22.20.0', '23.0.0', '24.18.0', 'v24.0.0']) expect(() => checkNodeVersion(v, '>=22.13.0'), v).to.not.throw();
    for (const v of ['22.12.9', '22.0.0', '20.19.0', '18.20.8', 'v16.20.2']) expect(() => checkNodeVersion(v, '>=22.13.0'), v).to.throw(OLD_NODE);
    expect(() => checkNodeVersion('18.20.8', '>=22.13.0')).to.throw('and this is Node 18.20.8.');
    expect(() => checkNodeVersion('18.0.0', undefined)).to.not.throw();
    // With alternatives, the lowest one is the floor.
    expect(() => checkNodeVersion('20.19.0', '^20.19.0 || >=22.12.0')).to.not.throw();
    expect(() => checkNodeVersion('20.18.3', '^20.19.0 || >=22.12.0')).to.throw(/needs Node 20\.19\.0 or later/);
  });

  it('says the package could not be loaded, and checks the version before loading it', () => {
    const missing = (id: string) => {
      throw Object.assign(new Error(`Cannot find module '${id}'`), { code: 'MODULE_NOT_FOUND' });
    };
    expect(() => loadFlattener(missing, '24.18.0')).to.throw(NOT_LOADABLE);
    expect(() => loadFlattener(missing, '24.18.0')).to.throw("Cannot find module '@patrickdk77/xfa-flatten/package.json'");
    const loaded: string[] = [];
    const old = (id: string) => {
      loaded.push(id);
      return id.endsWith('package.json') ? { engines: { node: '>=22.13.0' } } : { flattenXfaSource: () => undefined };
    };
    expect(() => loadFlattener(old, '18.20.8')).to.throw(OLD_NODE);
    expect(loaded).to.deep.equal(['@patrickdk77/xfa-flatten/package.json']);
    expect(() => loadFlattener(id => (id.endsWith('package.json') ? {} : {}), '24.18.0')).to.throw(/could not be loaded: it has no flattenXfaSource export/);
    const broken = (id: string) => {
      if (id.endsWith('package.json')) return { engines: { node: '>=22.13.0' } };
      throw new SyntaxError('Unexpected token');
    };
    expect(() => loadFlattener(broken, '24.18.0')).to.throw(/could not be loaded: Unexpected token/);
    expect(typeof loadFlattener(old, '24.18.0').flattenXfaSource).to.equal('function');
  });

  it('throws from every disarm and from filePlugin when it cannot run, and never skips the flatten', async () => {
    for (const [load, message] of [
      [
        () =>
          loadFlattener(id => {
            throw new Error(`Cannot find module '${id}'`);
          }, '24.18.0'),
        NOT_LOADABLE,
      ],
      [() => loadFlattener(() => ({ engines: { node: '>=22.13.0' } }), '18.20.8'), OLD_NODE],
    ] as const) {
      setFlattenerLoader(load);
      for (const bytes of [makeXfaForm(), makePdf(), Buffer.from('plain text\n')]) {
        const e = await rejection(disarmFile(bytes, { flattenXfa: {} }));
        expect((e as Error).message).to.match(message);
      }
      expect(() => filePlugin({ flattenXfa: true })).to.throw(message);
      expect((await disarmFile(makePdf())).status).to.equal('clean');
      expect((await inspectFile(makeXfaForm(), { flattenXfa: true })).status).to.equal('clean');
    }
  });
});

describe("xfa-flatten's results", () => {
  afterEach(() => setFlattenerLoader());

  /** A stand-in for xfa-flatten that writes `output` and returns `result`, recording what it was given. */
  function fake(result: { status: string; pages?: number; notes: FlattenNote[] }, output = makePdf()) {
    const seen: { input?: Buffer; options?: unknown } = {};
    const flattener: Flattener = {
      async flattenXfaSource(source, sink, options) {
        seen.input = Buffer.from(await source.read(0, await source.size()));
        seen.options = options;
        if (result.status === 'flattened') {
          await sink.write(output);
          await sink.close();
        }
        return result;
      },
    };
    setFlattenerLoader(() => flattener);
    return seen;
  }

  it("reads pdf-defuse's output, with the tree's deadline and the pixel limit", async () => {
    const form = makeXfaForm();
    const seen = fake({ status: 'unchanged', notes: [] });
    const start = Date.now();
    const r = await disarmFile(form, { flattenXfa: { limits: { pixels: 4096 } }, limits: { timeMs: 60_000 } });
    const without = await disarmFile(form);
    expect(r).to.deep.equal(without);
    expect(seen.input?.equals(Buffer.from(without.bytes ?? new Uint8Array(0)))).to.equal(true);
    expect(seen.input?.equals(form)).to.equal(false);
    const options = seen.options as { deadline: number; limits: unknown };
    expect(options.limits).to.deep.equal({ pixels: 4096 });
    expect(options.deadline).to.be.within(start + 60_000, Date.now() + 60_000);
    await disarmFile(form, { flattenXfa: true });
    expect(seen.options).to.deep.equal({});
  });

  it('reports each note as FLATTEN/NOTE, with control and direction characters as ? and long text cut', async () => {
    const [bell, rlo, rlm] = [0x07, 0x202e, 0x200f].map(c => String.fromCodePoint(c));
    const long = `A calculate script did not run${bell} and the total${rlo} is not shown. ${'x'.repeat(400)}`;
    fake({ status: 'flattened', pages: 1, notes: [{ kind: 'script-not-run', location: `plot[0].total${rlm}[0]`, detail: long }] });
    const r = await disarmFile(makeXfaForm(), { flattenXfa: true });
    expect(r.status).to.equal('defused');
    const notes = flattenFindings(r.after?.findings);
    expect(notes.map(line)).to.deep.equal(['info FLATTEN/NOTE']);
    expect(notes[0]).to.deep.include({ location: 'plot[0].total?[0]', weight: 0, data: { kind: 'script-not-run' } });
    expect(notes[0].description).to.have.length(300);
    expect(notes[0].description.startsWith('A calculate script did not run? and the total? is not shown. xxx')).to.equal(true);
    expect(notes[0].description.endsWith('...')).to.equal(true);
    expect(r.after?.status).to.equal('clean');
  });

  it('rejects the upload when FLATTEN/NOTE is overridden to reject or strip', async () => {
    for (const action of ['reject', 'strip'] as const) {
      fake({ status: 'flattened', pages: 1, notes: [{ kind: 'image-format', location: 'page 1', detail: 'An image was not drawn.' }] });
      const r = await disarmFile(makeXfaForm(), { flattenXfa: true, actionOverrides: [{ category: FC.Flatten, detail: FD.Note, action }] });
      expect(r.status).to.equal('rejected');
      expect(flattenFindings(r.before.findings).map(line)).to.deep.equal(['strip FLATTEN/XFA', 'reject FLATTEN/NOTE']);
    }
  });

  it('stops at the time limit when xfa-flatten says the deadline passed', async () => {
    fake({ status: 'failed', notes: [{ kind: 'deadline', location: 'document', detail: 'The deadline passed before the form was laid out.' }] });
    const r = await disarmFile(makeXfaForm(), { flattenXfa: true });
    expect(r.status).to.equal('rejected');
    expect(r.before.score).to.equal(null);
    expect(r.before.findings.map(line)).to.deep.equal(['reject LIMIT/TIME']);
    // Inside a ZIP archive the whole upload stops too.
    const zip = await disarmFile(zipped([{ name: 'plot.pdf', data: makeXfaForm() }]), { flattenXfa: true });
    expect(zip.status).to.equal('rejected');
    expect(kinds(zip.before.findings)).to.include('LIMIT/TIME');
  });

  it('rejects with PROCESSING/VERIFICATION_FAILED when pdf-defuse rejects the drawn form', async () => {
    fake({ status: 'flattened', pages: 1, notes: [] }, Buffer.from('this is not a PDF at all'));
    const r = await disarmFile(makeXfaForm(), { flattenXfa: true });
    expect(r.status).to.equal('rejected');
    const failed = r.before.findings.find(f => f.detail === 'VERIFICATION_FAILED');
    expect(failed?.action).to.equal('reject');
    expect(failed?.description).to.match(/pdf-defuse rejected the drawn form for /);
    // Inside a ZIP archive the PDF goes and the archive stays.
    const zip = await disarmFile(zipped([{ name: 'plot.pdf', data: makeXfaForm() }]), { flattenXfa: true });
    expect(zip.before.findings.map(line)).to.include('strip PROCESSING/VERIFICATION_FAILED in plot.pdf');
    expect(entryOf(zip.bytes ?? new Uint8Array(0), 'plot.pdf')).to.equal(undefined);
  });

  it('treats a status it does not know as an error', async () => {
    fake({ status: 'partial', notes: [] });
    const e = await rejection(disarmFile(makeXfaForm(), { flattenXfa: true }));
    expect((e as Error).message).to.equal('@patrickdk77/xfa-flatten returned an unknown status, partial');
  });
});
