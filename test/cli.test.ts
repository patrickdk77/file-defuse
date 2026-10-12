import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { expect } from 'chai';
import { type FileInspection, inspectFile } from '../src';
import { fixture, fixtures, makePdf, runCli } from './helpers/util';

describe('command line', () => {
  let tmp: string;
  before(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'file-defuse-cli-'));
  });
  after(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });
  const fx = (name: string) => path.join(fixtures, name);
  const write = (name: string, text: string) => {
    const p = path.join(tmp, name);
    fs.writeFileSync(p, text);
    return p;
  };

  it('exits 0 for a clean file, 1 for a strippable one and 2 for a rejected one', () => {
    const clean = runCli(['inspect', fx('clean.pdf')]);
    expect(clean.status).to.equal(0);
    expect(clean.stdout.toString()).to.include('inspection: clean, risk NONE (score 0), read by pdf');
    expect(runCli(['inspect', fx('nested.pdf')]).status).to.equal(1);
    const loop = runCli(['inspect', fx('loop.pdf')]);
    expect(loop.status).to.equal(2);
    expect(loop.stdout.toString()).to.include('LIMIT/NESTING_DEPTH');
    const docx = runCli(['inspect', fx('embedded.docx')]);
    expect(docx.status).to.equal(1);
    expect(docx.stdout.toString()).to.include('read by office');
    const unknown = runCli(['inspect', fx('unknown.bin')]);
    expect(unknown.status).to.equal(2);
    expect(unknown.stdout.toString()).to.include('no package reads it');
  });

  it('defuses to a file, and the output inspects clean', async () => {
    const out = path.join(tmp, 'out.pdf');
    const r = runCli(['defuse', fx('nested.pdf'), out]);
    expect(r.status).to.equal(1);
    expect(r.stdout.toString()).to.match(/^result: defused\nbefore: strippable/);
    expect((await inspectFile(fs.readFileSync(out))).status).to.equal('clean');
  });

  it('reads stdin and writes stdout with -, and puts the report on stderr', async () => {
    const r = runCli(['defuse', '-', '-'], { input: fixture('nested.pdf') });
    expect(r.status).to.equal(1);
    expect(r.stdout.subarray(0, 5).toString()).to.equal('%PDF-');
    expect(r.stderr.toString()).to.include('result: defused');
    expect((await inspectFile(r.stdout)).status).to.equal('clean');
  });

  it('stops copying stdin one byte past the size limit', () => {
    const r = runCli(['inspect', '-', '--limit', 'fileSize=100', '--json'], { input: fixture('nested.pdf') });
    expect(r.status).to.equal(2);
    const report = JSON.parse(r.stdout.toString()) as FileInspection;
    expect(report.findings[0].data).to.deep.equal({ size: 101 });
  });

  it('reads one password per line from --password-file, skipping blank lines and dropping carriage returns', () => {
    const file = write('pw.txt', 'outer pass\r\n\r\n\ninner pass\n');
    const r = runCli(['inspect', fx('passwords.pdf'), '--password-file', file]);
    expect(r.status).to.equal(1);
    expect(r.stdout.toString()).to.include('JAVASCRIPT/OPEN_ACTION');
  });

  it('gives the password list to every package', () => {
    const file = write('both.txt', 'pdf pass\noffice pass\n');
    const r = runCli(['inspect', fx('passwords.docx'), '--password-file', file]);
    expect(r.status).to.equal(1);
    expect(r.stdout.toString()).to.include('JAVASCRIPT/OPEN_ACTION');
  });

  it('takes one password from FILE_DEFUSE_PASSWORD, and --password-file replaces it', () => {
    const one = runCli(['inspect', fx('passwords.pdf')], { env: { FILE_DEFUSE_PASSWORD: 'outer pass' } });
    expect(one.status).to.equal(1);
    expect(one.stdout.toString()).to.include('EMBEDDED_FILE/PLUGIN_REMOVED');
    const file = write('wrong.txt', 'wrong\n');
    const replaced = runCli(['inspect', fx('passwords.pdf'), '--password-file', file], { env: { FILE_DEFUSE_PASSWORD: 'outer pass' } });
    expect(replaced.status).to.equal(2);
  });

  it('refuses a password on the command line, without echoing it', () => {
    const r = runCli(['inspect', fx('passwords.pdf'), '--password', 'secret']);
    expect(r.status).to.equal(3);
    expect(r.stderr.toString()).to.include('--password-file');
    const eq = runCli(['inspect', fx('passwords.pdf'), '--passwd=hunter2']);
    expect(eq.status).to.equal(3);
    expect(eq.stderr.toString()).to.not.include('hunter2');
  });

  it('sets tree limits with --limit and refuses bad ones', () => {
    expect(runCli(['inspect', fx('wide.pdf'), '--limit', 'files=10']).status).to.equal(2);
    expect(runCli(['inspect', fx('deep.pdf'), '--limit', 'nestingDepth=12']).status).to.equal(0);
    expect(runCli(['inspect', fx('bulky.pdf'), '--limit', 'decodedBytes=600kb']).status).to.equal(2);
    expect(runCli(['inspect', fx('clean.pdf'), '--limit', 'timeMs=60000']).status).to.equal(0);
    expect(runCli(['inspect', fx('clean.pdf'), '--limit', 'timeMs=soon']).status).to.equal(3);
    expect(runCli(['inspect', fx('clean.pdf'), '--limit', 'objects=5']).status).to.equal(3);
    expect(runCli(['inspect', fx('clean.pdf'), '--limit', 'files']).status).to.equal(3);
  });

  it('loads a --config module, and the flags apply on top', () => {
    const cfg = write('keep.cjs', "module.exports = { actionOverrides: [{ category: 'TYPE', detail: 'NO_PACKAGE', action: 'info' }], limits: { files: 1 } };");
    expect(runCli(['inspect', fx('unknown.bin'), '--config', cfg]).status).to.equal(0);
    expect(runCli(['inspect', fx('wide.pdf'), '--config', cfg]).status).to.equal(2);
    expect(runCli(['inspect', fx('wide.pdf'), '--config', cfg, '--limit', 'files=20']).status).to.equal(0);
  });

  it('turns on metadata stripping with --strip-metadata', () => {
    const file = path.join(tmp, 'info.pdf');
    fs.writeFileSync(file, makePdf({ info: true }));
    expect(runCli(['inspect', file]).status).to.equal(0);
    const r = runCli(['inspect', file, '--strip-metadata']);
    expect(r.status).to.equal(1);
    expect(r.stdout.toString()).to.include('METADATA/STRIPPED');
  });

  it('prints JSON with --json', () => {
    const r = runCli(['defuse', fx('nested.pdf'), path.join(tmp, 'json.pdf'), '--json']);
    const result = JSON.parse(r.stdout.toString()) as { status: string; before: FileInspection };
    expect(result.status).to.equal('defused');
    expect(result.before.findings.at(-1)?.attachment).to.equal('level1.pdf > level2.pdf > level3.pdf > level4.pdf');
  });

  it('prints what detection makes of a file with detect, using its base name as the claim', () => {
    const r = runCli(['detect', fx('jpeg-zip.bin')]);
    expect(r.status).to.equal(0);
    const d = JSON.parse(r.stdout.toString()) as { mimeType: string; family: string; chosenBy: string; signatures: Array<{ mimeType: string }> };
    expect([d.mimeType, d.family, d.chosenBy, d.signatures.map(s => s.mimeType)]).to.deep.equal(['image/jpeg', 'image', 'firstSignature', ['image/jpeg', 'application/zip']]);
    const named = path.join(tmp, 'photo.zip');
    fs.copyFileSync(fx('jpeg-zip.bin'), named);
    expect((JSON.parse(runCli(['detect', named]).stdout.toString()) as { chosenBy: string }).chosenBy).to.equal('name');
    const csv = runCli(['detect', fx('data.csv')]);
    expect((JSON.parse(csv.stdout.toString()) as { textTypes: string[] }).textTypes).to.deep.equal(['csv']);
    expect(runCli(['detect', '-'], { input: fixture('clean.pdf') }).stdout.toString()).to.include('"family": "pdf"');
    expect(runCli(['detect']).status).to.equal(3);
  });

  it('gives the file name to the run, so a .csv gets the CSV rule', () => {
    const r = runCli(['inspect', fx('data.csv')]);
    expect(r.status).to.equal(1);
    expect(r.stdout.toString()).to.include('TEXT/FORMULA');
    const piped = runCli(['inspect', '-'], { input: fixture('data.csv') });
    expect(piped.stdout.toString()).to.not.include('TEXT/FORMULA');
    const cfg = write('name.cjs', "module.exports = { name: 'piped.csv' };");
    expect(runCli(['inspect', '-', '--config', cfg], { input: fixture('data.csv') }).stdout.toString()).to.include('TEXT/FORMULA');
  });

  it('exits 3 for usage and I/O errors', () => {
    expect(runCli([]).status).to.equal(3);
    expect(runCli(['scan', fx('clean.pdf')]).status).to.equal(3);
    expect(runCli(['inspect']).status).to.equal(3);
    expect(runCli(['inspect', fx('clean.pdf'), '--bogus']).status).to.equal(3);
    const missing = runCli(['inspect', path.join(tmp, 'missing.pdf')]);
    expect(missing.status).to.equal(3);
    expect(missing.stderr.toString()).to.include('ENOENT');
    const same = path.join(tmp, 'same.pdf');
    fs.copyFileSync(fx('nested.pdf'), same);
    expect(runCli(['defuse', same, same]).status).to.equal(3);
    expect(fs.readFileSync(same)).to.deep.equal(fixture('nested.pdf'));
  });
});
