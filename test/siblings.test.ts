import * as fs from 'node:fs';
import * as path from 'node:path';
import { detectArchive } from '@patrickdk77/archive-defuse';
import { detectImage } from '@patrickdk77/img-defuse';
import { detectOffice } from '@patrickdk77/office-defuse';
import { detectPdf } from '@patrickdk77/pdf-defuse';
import { detectXml } from '@patrickdk77/xml-defuse';
import { expect } from 'chai';
import { detectFile, type FileFamily } from '../src';
import { root } from './helpers/util';

type Detect = (bytes: Uint8Array, options: { name?: string }) => Promise<{ mimeType: string } | undefined>;

/** Each sibling package, the family file-defuse routes to it, and its own detect function. */
const SIBLINGS: Array<[string, FileFamily, Detect]> = [
  ['pdf-defuse', 'pdf', detectPdf],
  ['office-defuse', 'office', detectOffice],
  ['img-defuse', 'image', detectImage],
  ['xml-defuse', 'xml', detectXml],
  ['archive-defuse', 'archive', detectArchive],
];

const walk = (dir: string): string[] => fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => (e.isDirectory() ? walk(path.join(dir, e.name)) : e.isFile() ? [path.join(dir, e.name)] : []));

describe("the sibling packages' own fixtures", () => {
  for (const [repo, family, detect] of SIBLINGS) {
    const dir = path.join(root, '..', repo, 'test', 'fixtures');
    it(`reach ${repo} exactly when its own detect claims them`, async function () {
      // The sibling repositories sit beside this one in a development checkout, and nowhere else.
      if (!fs.existsSync(dir)) this.skip();
      this.timeout(300_000);
      const wrong: string[] = [];
      for (const file of walk(dir)) {
        if (/(^|\/)(manifest\.json|MANIFEST[^/]*|README(\.md)?|LICENSE|NOTICE)$/i.test(file)) continue;
        const key = `${repo}/${path.relative(dir, file).split(path.sep).join('/')}`;
        const bytes = fs.readFileSync(file);
        const name = path.basename(file);
        const claimed = (await detect(bytes, { name })) !== undefined;
        const d = await detectFile(bytes, { name });
        const reached = d.signatures.some(s => s.family === family);
        // archive-defuse reads every ZIP, and its claim gives way to the Office package office-defuse names in it.
        const officeNamed = family === 'archive' && d.signatures.some(s => s.family === 'office');
        if (claimed !== reached && !(claimed && officeNamed)) wrong.push(`${key}: ${repo} ${claimed ? 'claims it' : 'does not claim it'}, file-defuse found ${d.family ?? 'none'} (${d.mimeType})`);
        // One format alone is handled as that format.
        if (claimed && d.signatures.length === 1 && d.family !== family && !officeNamed) wrong.push(`${key}: handled as ${d.family ?? 'none'}`);
      }
      expect(wrong).to.deep.equal([]);
    });
  }
});
