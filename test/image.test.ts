import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { ImageCategory, ImageDetail } from '@patrickdk77/img-defuse';
import { passThrough } from '@patrickdk77/pdf-defuse';
import { expect } from 'chai';
import { disarmFile, inspectFile } from '../src';
import { fixture, kinds, line, makePdf, rejection } from './helpers/util';

describe('image section', () => {
  it('routes the images img-defuse reads to it by content', async () => {
    expect((await inspectFile(fixture('photo.jpg'))).package).to.equal('image');
    const named = await inspectFile(makePdf({ attachments: [{ name: 'notes.txt', type: 'text/plain', bytes: fixture('photo.jpg') }] }));
    expect(named.findings.map(line)).to.include('info METADATA/EXIF in notes.txt');
  });

  it('routes JPEG 2000 and JPEG XL to img-defuse, and the images inside them back through file-defuse', async () => {
    const jp2 = await inspectFile(fixture('photo.jp2'));
    expect([jp2.status, jp2.package]).to.deep.equal(['clean', 'image']);
    expect(jp2.findings.map(line)).to.include('info METADATA/COMMENT in EXIF thumbnail');
    expect(jp2.findings.find(f => f.detail === 'PLUGIN_PASSED')?.data).to.deep.include({ plugin: 'file-defuse' });
    const j2c = await inspectFile(fixture('photo.j2c'));
    expect([j2c.status, j2c.package, ...j2c.findings.map(line)]).to.deep.equal(['clean', 'image', 'info METADATA/COMMENT']);
    // The gain map is a bare JPEG XL codestream, which file-defuse sends back to img-defuse.
    const jxl = await inspectFile(fixture('photo.jxl'));
    expect(jxl.findings.map(line)).to.deep.equal(['info METADATA/SECONDARY_IMAGE', 'info EMBEDDED_IMAGE/PLUGIN_PASSED']);
    expect(jxl.findings[1].data).to.deep.include({ plugin: 'file-defuse' });
    expect((await inspectFile(fixture('photo.jxl'), { limits: { files: 0 } })).findings.map(line)).to.include('reject LIMIT/FILE_COUNT');
  });

  it('hands an image format img-defuse does not read to img-defuse, whose refusal rejects the upload and removes the file from a container', async () => {
    // A JPEG 2000 file of brand JPM, which img-defuse does not read: the JP2 signature box, then a file type box.
    const bytes = Buffer.concat([Buffer.from('0000000c6a5020200d0a870a00000014', 'hex'), Buffer.from('ftypjpm \0\0\0\0jpm ', 'latin1')]);
    const r = await inspectFile(bytes);
    expect([r.status, r.package, r.findings[0].category, r.findings[0].detail]).to.deep.equal(['rejected', 'image', 'FORMAT', 'UNSUPPORTED']);
    expect(r.findings[0].data).to.deep.include({ format: 'JPM' });
    const inPdf = await inspectFile(makePdf({ attachments: [{ name: 'picture', bytes }] }));
    expect(inPdf.findings.map(line)).to.deep.equal(['strip EMBEDDED_FILE/PLUGIN_REMOVED', 'strip FORMAT/UNSUPPORTED in picture']);
  });

  it('routes a thumbnail back through file-defuse, counted as a file at its own depth', async () => {
    expect((await inspectFile(fixture('photo.jpg'), { limits: { files: 0 } })).findings.map(line)).to.include('reject LIMIT/FILE_COUNT');
    const pdf = fixture('images.pdf');
    expect((await inspectFile(pdf, { limits: { nestingDepth: 2 } })).status).to.equal('clean');
    const r = await inspectFile(pdf, { limits: { nestingDepth: 1 } });
    expect(r.findings.at(-1)?.data).to.deep.equal({ depth: 2, limit: 1 });
    const own = await inspectFile(pdf, { image: { limits: { nestingDepth: 1 } } });
    expect([own.status, ...kinds(own.findings).filter(k => k.startsWith('LIMIT/'))]).to.deep.equal(['rejected', 'LIMIT/NESTING_DEPTH']);
  });

  it('gives tempDir and memoryThreshold to img-defuse unless its section sets its own', async () => {
    const missing = path.join(os.tmpdir(), 'file-defuse-test-no-such-dir', 'x');
    const e = await rejection(disarmFile(fixture('photo.jpg'), { memoryThreshold: 0, tempDir: missing }));
    expect((e as { code?: string }).code).to.equal('ENOENT');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'file-defuse-test-'));
    try {
      expect((await disarmFile(fixture('photo.jpg'), { memoryThreshold: 0, tempDir: missing, image: { tempDir: dir } })).status).to.equal('clean');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("puts itself after the image section's own file plugins", async () => {
    const r = await inspectFile(fixture('photo.jpg'), { image: { filePlugins: [passThrough(['image/jpeg'])] } });
    expect(r.findings.find(f => f.detail === 'PLUGIN_PASSED')?.data).to.deep.include({ plugin: 'passThrough(image/jpeg)' });
    expect(kinds(r.findings)).to.not.include('METADATA/COMMENT');
  });

  it("weighs img-defuse's findings by its weights and the image section's scoreWeights", async () => {
    const weight = (findings: Array<{ detail: string; weight?: number }>) => findings.find(f => f.detail === 'PLUGIN_PASSED')?.weight;
    // The finding that records a plugin's answer weighs nothing, unless the section says otherwise.
    expect(weight((await inspectFile(fixture('photo.jpg'))).findings)).to.equal(0);
    const r = await inspectFile(fixture('photo.jpg'), { image: { scoreWeights: [{ category: ImageCategory.EmbeddedImage, detail: ImageDetail.PluginPassed, weight: 9 }] } });
    expect(weight(r.findings)).to.equal(9);
  });
});
