import * as fs from 'node:fs';
import * as path from 'node:path';
import { expect } from 'chai';
import { disarmFile, type FileOptions, inspectFile } from '../src';
import { fixture, fixtures, line } from './helpers/util';

interface Case {
  file: string;
  about: string;
  options: FileOptions;
  inspect: string;
  disarm: string;
  findings: string[];
}

const manifest = JSON.parse(fs.readFileSync(path.join(fixtures, 'manifest.json'), 'utf8')) as { cases: Case[] };

describe('fixtures', () => {
  it('has a case for every fixture file', () => {
    // formats/ holds one sample of each format detection names, and formats.json what detection makes of each.
    const files = fs.readdirSync(fixtures).filter(f => f !== 'manifest.json' && f !== 'formats.json' && f !== 'formats');
    expect(new Set(manifest.cases.map(c => c.file))).to.deep.equal(new Set(files));
  });

  for (const c of manifest.cases) {
    describe(`${c.file} ${JSON.stringify(c.options)}`, () => {
      it('inspects to the verdict and findings in the manifest', async () => {
        const r = await inspectFile(fixture(c.file), c.options);
        expect(r.status).to.equal(c.inspect);
        expect(r.findings.map(line)).to.deep.equal(c.findings);
        for (const f of r.findings) expect(f.weight, `${f.category}/${f.detail}`).to.be.a('number');
        // A run that stops has no score. A reject finding that does not stop the run, such as a polyglot img-defuse
        // cannot separate, keeps its score. An upload no package reads has none either.
        expect(r.score === null).to.equal(r.risk === 'UNKNOWN');
      });

      it('disarms to the verdict in the manifest', async () => {
        const r = await disarmFile(fixture(c.file), c.options);
        expect(r.status).to.equal(c.disarm);
        if (r.status === 'rejected') {
          expect(r.bytes).to.equal(undefined);
          return;
        }
        // The output holds nothing left to remove, and inspects the same way again.
        const again = await inspectFile(r.bytes ?? Buffer.alloc(0), c.options);
        expect(again.status).to.equal('clean');
        expect(again.findings.filter(f => f.action !== 'info')).to.deep.equal([]);
      });
    });
  }
});
