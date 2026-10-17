import * as zlib from 'node:zlib';
import { expect } from 'chai';
import { disarmFile, inspectFile } from '../src';
import { entryOf, fixture, line, makePdf } from './helpers/util';

const B = (s: string) => Buffer.from(s, 'latin1');

/** PDF literal string syntax for a script: backslashes and parentheses escaped. */
const lit = (s: string) => `(${s.replace(/[\\()]/g, c => `\\${c}`)})`;

/** A one-page PDF with `catalog` entries and extra objects numbered from 4. */
function pdfOf(catalog: string, objects: Array<string | { dict: string; data: Buffer }> = []): Buffer {
  const bodies: Array<string | { dict: string; data: Buffer }> = [
    `<< /Type /Catalog /Pages 2 0 R ${catalog} >>`,
    '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>',
    '<< /Type /Page /Parent 2 0 R >>',
    ...objects,
  ];
  const out: Buffer[] = [B('%PDF-1.7\n')];
  let offset = out[0].length;
  const offsets: number[] = [];
  bodies.forEach((body, i) => {
    const bytes =
      typeof body === 'string'
        ? B(`${i + 1} 0 obj\n${body}\nendobj\n`)
        : Buffer.concat([B(`${i + 1} 0 obj\n${body.dict.replace(/>>$/, `/Length ${body.data.length} >>`)}\nstream\n`), body.data, B('\nendstream\nendobj\n')]);
    offsets.push(offset);
    out.push(bytes);
    offset += bytes.length;
  });
  let xref = `xref\n0 ${bodies.length + 1}\n0000000000 65535 f\r\n`;
  for (const o of offsets) xref += `${String(o).padStart(10, '0')} 00000 n\r\n`;
  out.push(B(`${xref}trailer\n<< /Size ${bodies.length + 1} /Root 1 0 R >>\nstartxref\n${offset}\n%%EOF\n`));
  return Buffer.concat(out);
}

/** A form whose field calculates with a helper; `withHelper` puts the helper in a document-level script. */
function formWithHelper(withHelper: boolean): Buffer {
  const field = `<< /FT /Tx /T (Total) /AA << /C << /S /JavaScript /JS ${lit('event.value = triple(this.getField("Qty").value);')} >> >> >>`;
  const helper = `<< /S /JavaScript /JS ${lit('function triple(n) { return n * 3; }')} >>`;
  return withHelper ? pdfOf('/AcroForm << /Fields [4 0 R] >> /Names << /JavaScript << /Names [(lib) 5 0 R] >> >>', [field, helper]) : pdfOf('/AcroForm << /Fields [4 0 R] >>', [field]);
}

describe('script-defuse in the pdf route', () => {
  it('keeps form scripts: a field calculation and the document helper it calls', async () => {
    const r = await disarmFile(formWithHelper(true));
    expect(r.status).to.equal('clean');
    const found = r.before.findings.map(line);
    expect(found.filter(l => l.startsWith('strip'))).to.deep.equal([]);
    expect(found.filter(l => l === 'info JAVASCRIPT/PLUGIN_PASSED')).to.have.length(2);
    // The scripts are still in the output, and still pass.
    const out = (await inspectFile(r.bytes ?? Buffer.alloc(0))).findings.map(line);
    expect(out.filter(l => l === 'info JAVASCRIPT/PLUGIN_PASSED')).to.have.length(2);
  });

  it('gives every PDF of an upload a plugin of its own, so a helper one PDF defines is unknown to the next', async () => {
    const upload = makePdf({
      attachments: [
        { name: 'with-helper.pdf', bytes: formWithHelper(true) },
        { name: 'without-helper.pdf', bytes: formWithHelper(false) },
      ],
    });
    const found = (await inspectFile(upload)).findings.map(line);
    expect(found).to.include('info JAVASCRIPT/PLUGIN_PASSED in with-helper.pdf');
    expect(found).to.include('strip JAVASCRIPT/PLUGIN_REMOVED in without-helper.pdf');
    expect(found).to.include('strip SCRIPT_API/UNKNOWN in without-helper.pdf');
  });

  it('keeps an XFA FormCalc calculation and removes an XFA click script that opens a URL', async () => {
    const xdp = B(
      '<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/"><template xmlns="http://www.xfa.org/schema/xfa-template/3.3/"><subform name="order">' +
        '<field name="Total"><calculate><script>Sum(Qty, Price)</script></calculate></field>' +
        '<field name="Help"><event activity="click"><script contentType="application/x-javascript">xfa.host.gotoURL("https://example.invalid/");</script></event></field>' +
        '</subform></template></xdp:xdp>',
    );
    const pdf = pdfOf('/AcroForm << /Fields [] /XFA 4 0 R >>', [{ dict: '<< /Filter /FlateDecode >>', data: zlib.deflateSync(xdp) }]);
    const r = await disarmFile(pdf);
    expect(r.status).to.equal('defused');
    const found = r.before.findings.map(line);
    expect(found).to.include('info JAVASCRIPT/PLUGIN_PASSED');
    expect(found).to.include('strip SCRIPT_EXTERNAL/URL');
    const out = (await inspectFile(r.bytes ?? Buffer.alloc(0))).findings.map(line);
    expect(out.filter(l => l.startsWith('strip'))).to.deep.equal([]);
  });
});

describe('script-defuse in the office route', () => {
  it('keeps a VBA project whose modules only work on their workbook, and writes it without the compiled code', async () => {
    const original = entryOf(fixture('macros.xlsm'), 'xl/vbaProject.bin') ?? Buffer.alloc(0);
    expect([original.includes('inert p-code'), original.includes('inert performance cache'), original.includes('inert cache')]).to.deep.equal([true, true, true]);
    const r = await disarmFile(fixture('macros.xlsm'));
    expect([r.status, ...r.removed.map(line)]).to.deep.equal(['defused', 'strip MACRO/COMPILED_CODE']);
    const out = Buffer.from(r.bytes ?? []);
    const project = entryOf(out, 'xl/vbaProject.bin') ?? Buffer.alloc(0);
    expect([project.length > 0, project.includes('inert p-code'), project.includes('inert performance cache'), project.includes('inert cache')]).to.deep.equal([true, false, false, false]);
    // The output keeps the project, and script-defuse passes it again with nothing left to remove.
    const again = await inspectFile(out);
    expect([again.status, ...again.findings.map(line)]).to.deep.equal([
      'clean',
      'info MACRO/PLUGIN_PASSED',
      'info SCRIPT_FORM/DOCUMENT_MACRO',
      'info MACRO/PLUGIN_PASSED',
      'info SCRIPT_FORM/DOCUMENT_MACRO',
    ]);
  });

  it('removes a VBA project with a module that starts a program', async () => {
    const r = await disarmFile(fixture('shell-macro.xlsm'));
    expect(r.status).to.equal('defused');
    expect(r.before.findings.find(f => f.detail === 'PROCESS')?.data).to.deep.include({ api: 'Shell' });
    expect(entryOf(Buffer.from(r.bytes ?? []), 'xl/vbaProject.bin')).to.equal(undefined);
  });

  it("puts script-defuse after the office section's own script plugins", async () => {
    const refuse = {
      kind: 'script' as const,
      name: 'refuse-all',
      accepts: () => true,
      process: async () => ({ result: 'removed' as const }),
    };
    const r = await inspectFile(fixture('macros.xlsm'), { office: { scriptPlugins: [refuse] } });
    expect(r.findings.filter(f => f.detail === 'PLUGIN_REMOVED').map(f => f.data?.plugin)).to.deep.equal(['refuse-all', 'refuse-all']);
    // The plugin's answer removed the project, so office-defuse reports nothing of its own about it.
    expect([r.status, r.findings.filter(f => f.detail === 'VBA_PROJECT').length]).to.deep.equal(['strippable', 0]);
  });
});

describe('office-defuse rewrites in the office route', () => {
  it('keeps a Forms 2.0 control as it was, and the VBA module that handles it', async () => {
    const original = fixture('controls.xlsm');
    const r = await disarmFile(original);
    const out = Buffer.from(r.bytes ?? []);
    expect(r.status).to.equal('defused');
    expect(entryOf(out, 'xl/activeX/activeX1.bin')).to.deep.equal(entryOf(original, 'xl/activeX/activeX1.bin'));
    expect(entryOf(out, 'xl/vbaProject.bin')).to.not.equal(undefined);
    expect((await inspectFile(out)).status).to.equal('clean');
  });

  it('rewrites an Excel 4.0 macro sheet, a PowerPoint 97 project and an add-in instead of rejecting them', async () => {
    for (const name of ['xlm.xls', 'macros.ppt', 'addin.ppa']) {
      const r = await disarmFile(fixture(name));
      expect([name, r.status, r.after?.status], name).to.deep.equal([name, 'defused', 'clean']);
      const again = await inspectFile(Buffer.from(r.bytes ?? []));
      expect([name, again.status, again.package]).to.deep.equal([name, 'clean', 'office']);
    }
  });
});
