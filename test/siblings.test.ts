import * as fs from 'node:fs';
import * as path from 'node:path';
import { expect } from 'chai';
import { detectFile } from '../src';
import { root } from './helpers/util';

/** The family each sibling package's own test fixtures belong to. */
const SIBLINGS = new Map([
  ['pdf-defuse', 'pdf'],
  ['office-defuse', 'office'],
  ['img-defuse', 'image'],
  ['xml-defuse', 'xml'],
  ['archive-defuse', 'archive'],
]);

/**
 * Fixtures whose content is not their package's format, on purpose: each tests how the package refuses something.
 * Detection goes by content, so these route elsewhere, and the reason says why.
 */
const ELSEWHERE = new Map([
  ['pdf-defuse/cases/header-missing.pdf', ['text', 'no %PDF- header in the first 1024 bytes']],
  ['pdf-defuse/cases/header-missing-unreadable.pdf', ['text', 'no %PDF- header in the first 1024 bytes']],
  ['pdf-defuse/cases/header-missing-trailer-cut-root-direct.pdf', ['text', 'no %PDF- header in the first 1024 bytes']],
  ['pdf-defuse/cases/not-a-pdf.pdf', ['text', 'plain text']],
  ['office-defuse/cases/empty-archive.xlsx', ['archive', 'a ZIP archive with no entries']],
  ['office-defuse/cases/encrypted-entries.zip', ['archive', 'a ZIP archive with no Office marker']],
  ['office-defuse/cases/plain-archive.zip', ['archive', 'a ZIP archive with no Office marker']],
  ['office-defuse/cases/odf-inside-folder.odt', ['archive', 'its mimetype and manifest sit in a folder, not at the root']],
  ['office-defuse/cases/ole-bare-equation-object.bin', ['none', 'a compound file that names no Office format']],
  ['office-defuse/cases/ole-powerpoint4.ppt', ['none', 'a compound file that names no Office format']],
  ['office-defuse/ole/bare-object.bin', ['none', 'a compound file that names no Office format']],
  ['img-defuse/detect/avif.avif', ['none', 'AVIF is outside the family']],
  ['img-defuse/detect/heic.heic', ['none', 'HEIC is outside the family']],
  ['img-defuse/detect/svg.svg', ['xml', "SVG is xml-defuse's"]],
  ['img-defuse/detect/unknown.bin', ['text', 'plain text']],
  ['xml-defuse/cases/not-markup.bin', ['none', 'binary content with no markup']],
  ['archive-defuse/lzma/cases/7z-not-7z.7z', ['text', 'plain text']],
  ['xml-defuse/cases/office-flat.fodt', ['office', "a flat OpenDocument file, which xml-defuse refuses as office-defuse's"]],
  ['xml-defuse/cases/text-only.html', ['text', 'text with no markup at the start']],
]);

/**
 * Brotli has no signature, so content cannot name it, and a Brotli stream routes as whatever its bytes look like. The
 * .d64 files are raw Deflate64 streams for archive-defuse's decoder tests, with no signature either.
 */
const NO_SIGNATURE = /\.(br|d64)$/;

const walk = (dir: string): string[] => fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => (e.isDirectory() ? walk(path.join(dir, e.name)) : e.isFile() ? [path.join(dir, e.name)] : []));

describe("the sibling packages' own fixtures", () => {
  for (const [repo, family] of SIBLINGS) {
    const dir = path.join(root, '..', repo, 'test', 'fixtures');
    it(`route ${repo}'s fixtures to ${family}, except the ones built to be something else`, async function () {
      // The sibling repositories sit beside this one in a development checkout, and nowhere else.
      if (!fs.existsSync(dir)) this.skip();
      this.timeout(120_000);
      const wrong: string[] = [];
      for (const file of walk(dir)) {
        if (/(^|\/)(manifest\.json|MANIFEST[^/]*|README(\.md)?|LICENSE)$/i.test(file)) continue;
        const key = `${repo}/${path.relative(dir, file).split(path.sep).join('/')}`;
        const d = await detectFile(fs.readFileSync(file), { name: path.basename(file) });
        if (NO_SIGNATURE.test(file)) {
          if (d.family === family) wrong.push(`${key}: ${family}, which content alone cannot show`);
          continue;
        }
        const want = ELSEWHERE.get(key)?.[0] ?? family;
        if ((d.family ?? 'none') !== want) wrong.push(`${key}: ${d.family ?? 'none'} (${d.mimeType})`);
      }
      expect(wrong).to.deep.equal([]);
    });
  }
});
