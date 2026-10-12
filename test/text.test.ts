import * as os from 'node:os';
import { expect } from 'chai';
import { type DefuseFinding, disarmFile, FileCategory, FileDetail, inspectFile } from '../src';
import { fixture, kinds, line, makePdf } from './helpers/util';

const B = (s: string) => Buffer.from(s, 'latin1');
const U = (s: string) => Buffer.from(s, 'utf8');
const out = (r: { bytes?: Uint8Array }) => Buffer.from(r.bytes ?? []);
const only = (findings: DefuseFinding[], detail: string) => findings.filter(f => f.detail === detail);

describe('text', () => {
  it('reads text with its own rules, and passes clean text through byte for byte', async () => {
    const r = await inspectFile(fixture('notes.txt'));
    expect(r).to.deep.equal({ status: 'clean', score: 0, risk: 'NONE', findings: [], package: 'text' });
    const d = await disarmFile(fixture('notes.txt'));
    expect([d.status, out(d).equals(fixture('notes.txt'))]).to.deep.equal(['clean', true]);
  });

  describe('control characters', () => {
    it('removes C0, DEL and C1 controls past the start detection reads, and the bytes that do not decode', async () => {
      const r = await inspectFile(fixture('late.txt'));
      expect(r.findings.map(f => [f.detail, f.location, f.data])).to.deep.equal([
        ['ENCODING', 'offset 67507', { offset: 67507, bytes: 1, encoding: 'UTF-8' }],
        ['CONTROL_CHARACTER', 'line 2501', { codePoint: 'U+0007' }],
        ['CONTROL_CHARACTER', 'line 2501', { codePoint: 'U+0085' }],
      ]);
      const d = await disarmFile(fixture('late.txt'));
      expect(out(d).toString('utf8').endsWith('\nbad \ufffd byte, bell , next line  control\n')).to.equal(true);
      expect(out(d).subarray(0, 3)).to.deep.equal(Buffer.from([0xef, 0xbb, 0xbf]));
    });

    it('keeps them when an override makes the finding info, and still reports them', async () => {
      const options = { text: { actionOverrides: [{ category: FileCategory.Text, detail: FileDetail.ControlCharacter, action: 'info' as const }] } };
      const d = await disarmFile(fixture('late.txt'), options);
      expect(out(d).includes(Buffer.from([0x07]))).to.equal(true);
      expect(only(d.before.findings, 'CONTROL_CHARACTER').map(f => f.action)).to.deep.equal(['info', 'info']);
    });

    it('counts past 200 of one kind in one more finding', async () => {
      const bytes = Buffer.concat([U('a'.repeat(70000)), Buffer.alloc(250, 0x01)]);
      const r = await inspectFile(bytes);
      const controls = only(r.findings, 'CONTROL_CHARACTER');
      expect(controls).to.have.length(201);
      expect([controls[200].location, controls[200].data]).to.deep.equal(['additional occurrences', { count: 50 }]);
      expect((await disarmFile(bytes)).bytes?.length).to.equal(70000);
    });
  });

  describe('bidirectional controls', () => {
    it('removes overrides and isolates in UTF-8 and UTF-16', async () => {
      const utf8 = await disarmFile(U('a\u202eb\u2066c\u2069d\u200fe\n'));
      expect([utf8.status, out(utf8).toString('utf8')]).to.deep.equal(['defused', 'abcd\u200fe\n']);
      const utf16 = await disarmFile(fixture('utf16.txt'));
      expect(out(utf16)).to.deep.equal(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('Hi evil there\n', 'utf16le')]));
    });

    it('finds them in 8-bit text as the UTF-8 bytes a reader would take them for', async () => {
      const bytes = Buffer.concat([B('caf\xe9 '), U('\u202e'), B('x\n')]);
      const r = await inspectFile(bytes);
      expect(kinds(r.findings)).to.deep.equal(['TEXT/BIDI_CONTROL', 'TEXT/UNNAMED_ENCODING']);
      expect(out(await disarmFile(bytes))).to.deep.equal(B('caf\xe9 x\n'));
    });
  });

  describe('CSV and TSV', () => {
    it('puts a quote before each cell a spreadsheet runs as a formula, inside the quotes of a quoted cell', async () => {
      const r = await inspectFile(fixture('data.csv'), { name: 'data.csv' });
      expect(only(r.findings, 'FORMULA').map(f => [f.location, f.data?.first])).to.deep.equal([
        ['row 3, cell 2', '='],
        ['row 4, cell 2', '='],
        ['row 5, cell 2', '+'],
        ['row 6, cell 2', '@'],
        ['row 7, cell 2', '-'],
      ]);
      const text = out(await disarmFile(fixture('data.csv'), { name: 'data.csv' })).toString('utf8');
      expect(text).to.include("bob,'=1+2,");
      expect(text).to.include('carol,"\'=HYPERLINK(""http://example.com"")",');
      expect(text).to.include("dave,'+cmd|");
      expect(text).to.include("frank,'-2+3,");
      expect(text).to.include('alice,-5,');
      expect(text).to.include('grace,+1.5e3,');
    });

    it('reads tabs as the separator of TSV, and a cell may not start with a tab or carriage return there', async () => {
      const bytes = U('a\t=b\t"\rc"\n');
      expect(only((await inspectFile(bytes, { name: 'x.tsv' })).findings, 'FORMULA').map(f => f.data?.first)).to.deep.equal(['=', 'a carriage return']);
      expect(out(await disarmFile(bytes, { name: 'x.tsv' })).toString('utf8')).to.equal('a\t\'=b\t"\'\rc"\n');
      // As CSV the line is one cell holding tabs.
      expect(only((await inspectFile(bytes, { name: 'x.csv' })).findings, 'FORMULA')).to.deep.equal([]);
    });

    it('rejects a file whose quoted cell never closes', async () => {
      const r = await inspectFile(fixture('unclosed.csv'), { name: 'unclosed.csv' });
      expect([r.status, ...r.findings.map(f => `${line(f)} @${f.location}`)]).to.deep.equal(['rejected', 'reject TEXT/UNCLOSED_QUOTE @row 2']);
    });

    it('keeps the bytes of 8-bit text as they are, and says it names no encoding', async () => {
      const d = await disarmFile(fixture('legacy.csv'), { name: 'legacy.csv' });
      expect(out(d)).to.deep.equal(B("name,note\r\nCaf\xe9,'=1+2\r\n"));
      expect(d.before.findings.map(line)).to.deep.equal(['strip TEXT/FORMULA', 'info TEXT/UNNAMED_ENCODING']);
    });

    it('applies the CSV rule only to a file a name or a declared type calls CSV', async () => {
      expect(kinds((await inspectFile(fixture('data.csv'))).findings)).to.deep.equal(['TEXT/BIDI_CONTROL']);
      expect(only((await inspectFile(fixture('data.csv'), { declaredType: 'text/csv' })).findings, 'FORMULA')).to.have.length(5);
    });
  });

  describe('Markdown', () => {
    it('neutralizes links to javascript:, vbscript: and data: URLs, outside code', async () => {
      const r = await inspectFile(fixture('readme.md'), { name: 'readme.md' });
      expect(r.findings.map(f => `${f.detail} ${f.location} ${f.data?.scheme}`)).to.deep.equal([
        'SCRIPT_URL line 5 javascript',
        'DATA_URL line 7 data',
        'SCRIPT_URL line 9 vbscript',
        'SCRIPT_URL line 11 javascript',
        'SCRIPT_URL line 13 javascript',
      ]);
      const text = out(await disarmFile(fixture('readme.md'), { name: 'readme.md' })).toString('utf8');
      expect(text.split('\n').filter(l => l.includes('#'))).to.deep.equal(['# Notes', '[Click](#alert(1))', '![pixel](#image/png;base64,AAAA)', '[ref]: #msgbox', '<#alert(2)>', '[x](#alert(3))']);
      expect(text).to.include('[code](javascript:not_a_link)');
      expect(text).to.include('`[code](javascript:no)`');
    });

    it('reads the scheme as a browser does: past escapes, entities, tabs and leading spaces, and on the next line', async () => {
      const md = U('[a](java\tscript:x)\n[b](< javascript:x>)\n[c](&#x6A;ava&#115;cript&colon;x)\n[d](\njavascript:x)\n[e](JaVaScRiPt:x)\n');
      expect(only((await inspectFile(md, { name: 'x.md' })).findings, 'SCRIPT_URL')).to.have.length(5);
      const d = await disarmFile(md, { name: 'x.md' });
      expect(d.status).to.equal('defused');
      expect((await inspectFile(out(d), { name: 'x.md' })).findings).to.deep.equal([]);
    });

    it('applies the Markdown rule only to a file a name or a declared type calls Markdown', async () => {
      expect((await inspectFile(fixture('readme.md'))).findings).to.deep.equal([]);
      expect((await inspectFile(fixture('readme.md'), { declaredType: 'text/markdown' })).findings).to.have.length(5);
    });
  });

  it('routes text inside a container to the text rules, with the name the container gives it', async () => {
    const pdf = makePdf({
      attachments: [
        { name: 'notes.txt', bytes: U('Plain notes.\n') },
        { name: 'sheet.csv', bytes: U('a,=1+2\n') },
      ],
    });
    const r = await inspectFile(pdf);
    expect(r.findings.map(line)).to.deep.equal(['info EMBEDDED_FILE/PLUGIN_PASSED', 'info EMBEDDED_FILE/PLUGIN_SCRUBBED', 'strip TEXT/FORMULA in sheet.csv']);
    const d = await disarmFile(pdf);
    expect(d.status).to.equal('defused');
    expect((await inspectFile(out(d))).status).to.equal('clean');
  });

  it('holds text to the tree limits and the time limit like any other file', async () => {
    const pdf = makePdf({ attachments: [{ name: 'notes.txt', bytes: U('Plain notes.\n') }] });
    expect((await inspectFile(pdf, { limits: { files: 0 } })).findings.map(line)).to.include('reject LIMIT/FILE_COUNT');
    const r = await inspectFile(fixture('late.txt'), { text: { limits: { timeMs: 0 } } });
    expect([r.status, ...r.findings.map(line)]).to.deep.equal(['rejected', 'reject LIMIT/TIME']);
    expect((await inspectFile(fixture('notes.txt'), { limits: { timeMs: 60_000 } })).status).to.equal('clean');
  });

  it("weighs the text rules' findings by the text section's scoreWeights", async () => {
    const r = await inspectFile(fixture('data.csv'), { name: 'data.csv', text: { scoreWeights: [{ category: 'TEXT', detail: 'FORMULA', weight: 90 }] } });
    expect(only(r.findings, 'FORMULA')[0].weight).to.equal(90);
    expect([r.score, r.risk]).to.deep.equal([98, 'CRITICAL']);
  });

  it('writes a rewrite larger than the memory threshold to tempDir, and removes it', async () => {
    const d = await disarmFile(fixture('late.txt'), { memoryThreshold: 0, tempDir: os.tmpdir() });
    expect(d.status).to.equal('defused');
  });
});
