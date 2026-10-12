import * as os from 'node:os';
import { createArchiveBytes } from '@patrickdk77/archive-defuse';
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
      // As plain text the links do nothing, and the URLs get only TEXT/SCRIPT_URL, for information.
      const plain = await inspectFile(fixture('readme.md'));
      expect([plain.status, [...new Set(plain.findings.map(f => `${f.action} ${f.category}/${f.detail}`))]]).to.deep.equal(['clean', ['info TEXT/SCRIPT_URL']]);
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

/** The kinds of findings in a report, each once, with the action they take. */
const actions = (findings: DefuseFinding[]) => [...new Set(findings.map(f => `${f.action} ${f.category}/${f.detail}`))];
const text = (r: { bytes?: Uint8Array }) => out(r).toString('utf8');

describe('terminal escape sequences', () => {
  it('removes whole CSI, OSC and two-character escapes, so a log keeps its words and loses its colours', async () => {
    const d = await disarmFile(U('\x1b[32mINFO\x1b[0m started\n\x1b]0;title\x07next\n\x1b]52;c;ZXZpbA==\x1b\\after\nreset\x1bc done\n'), { name: 'app.log' });
    expect(d.before.findings.map(f => [f.detail, f.data?.sequence])).to.deep.equal([
      ['TERMINAL_ESCAPE', 'CSI'],
      ['TERMINAL_ESCAPE', 'CSI'],
      ['TERMINAL_ESCAPE', 'OSC'],
      ['TERMINAL_ESCAPE', 'OSC'],
      ['TERMINAL_ESCAPE', 'ESC'],
    ]);
    expect(text(d)).to.equal('INFO started\nnext\nafter\nreset done\n');
  });

  it('reads the C1 forms in Unicode text, and ends a string sequence at the next escape', async () => {
    expect(text(await disarmFile(U('csi \u009b31mred\u009b0m, osc \u009d0;t\u009c end\n')))).to.equal('csi red, osc  end\n');
    expect(text(await disarmFile(U('a\x1b]0;title\x1b[1mbold\x1b[0m z\n')))).to.equal('abold z\n');
  });

  it('removes only the opening of a string sequence that never ends, and keeps the rest as text', async () => {
    expect(text(await disarmFile(U('before \x1b]8;;http://x\nrest\n')))).to.equal('before 8;;http://x\nrest\n');
  });

  it('keeps the sequences byte for byte when an override makes the finding info, without reporting them as controls', async () => {
    const bytes = U('\x1b[31mred\x1b[0m\n');
    const d = await disarmFile(bytes, { text: { actionOverrides: [{ category: FileCategory.Text, detail: FileDetail.TerminalEscape, action: 'info' }] } });
    expect([d.status, out(d).equals(bytes), actions(d.before.findings)]).to.deep.equal(['clean', true, ['info TEXT/TERMINAL_ESCAPE']]);
  });

  it('leaves backspace and a bell to the control character rule', async () => {
    const d = await disarmFile(B('N\bNA\bAM\bME\bE ring\x07\n'), { name: 'page.txt' });
    expect([actions(d.before.findings), text(d)]).to.deep.equal([['strip TEXT/CONTROL_CHARACTER'], 'NNAAMMEE ring\n']);
  });
});

describe('markup in text', () => {
  it('puts a space after the < of a tag that runs script, which a browser then shows as text', async () => {
    const log =
      'q=<script>alert(1)</script>\n<img src=x onerror=alert(1)>\n<a title="x>y" href="java&#x73;cript:alert(1)">l</a> <b>bold</b> <meta http-equiv=refresh content="0;url=x"> <meta charset=utf-8>\n';
    const d = await disarmFile(U(log), { name: 'access.log' });
    expect(only(d.before.findings, 'MARKUP').map(f => [f.location, f.data?.tag])).to.deep.equal([
      ['line 1', 'script'],
      ['line 2', 'img'],
      ['line 3', 'a'],
      ['line 3', 'meta'],
    ]);
    expect(text(d)).to.equal(log.replace('<script', '< script').replace('<img', '< img').replace('<a ', '< a ').replace('<meta http', '< meta http'));
  });

  it('reads a tag the way the HTML tokenizer does: a quoted value may hold >, and an end tag or < without a letter is no tag', async () => {
    expect((await inspectFile(U('a < b and c <= d, </script> <3 <!-- note -->\n'))).findings).to.deep.equal([]);
    expect(only((await inspectFile(U('note <p title="a > b" onclick="go()">x</p>\n'))).findings, 'MARKUP').map(f => f.data?.tag)).to.deep.equal(['p']);
  });

  it('applies to CSV and Markdown too, and not to JSON or JavaScript', async () => {
    expect(actions((await inspectFile(U('a,<iframe src=x>\n'), { name: 'a.csv' })).findings)).to.deep.equal(['strip TEXT/MARKUP']);
    expect(actions((await inspectFile(U('# Title\n\n<script>alert(1)</script>\n'), { name: 'a.md' })).findings)).to.deep.equal(['strip TEXT/MARKUP']);
    expect(only((await inspectFile(U('document.write("<script>x</script>")\n'), { name: 'a.js' })).findings, 'MARKUP')).to.deep.equal([]);
  });

  it('reports a javascript: or vbscript: URL in plain text for information, where a scheme can start', async () => {
    const r = await inspectFile(U('referer: javascript:alert(1) and VBScript:x, but notjavascript:x and my.javascript:x\n'));
    expect(r.findings.map(f => [f.action, f.detail, f.data?.scheme])).to.deep.equal([
      ['info', 'SCRIPT_URL', 'javascript'],
      ['info', 'SCRIPT_URL', 'vbscript'],
    ]);
  });
});

describe('JSON', () => {
  it('finds JSON by content, as libmagic does, and by a name or a declared type', async () => {
    expect((await inspectFile(U('{"a":1}'))).findings).to.deep.equal([]);
    const d = await disarmFile(U('{"a":"<b>"}'));
    expect([d.status, text(d)]).to.deep.equal(['defused', '{"a":"\\u003cb\\u003e"}']);
    expect(actions((await inspectFile(U('not json'), { name: 'data.json' })).findings)).to.deep.equal(['reject JSON/MALFORMED']);
    expect(actions((await inspectFile(U('not json'), { declaredType: 'application/vnd.api+json' })).findings)).to.deep.equal(['reject JSON/MALFORMED']);
  });

  it('removes earlier duplicates and keeps the last value, as JSON.parse does, with each member taking its own comma', async () => {
    const d = await disarmFile(U('{"a":1,"b":2,"a":3,"b":4,"a":5}'), { name: 'a.json' });
    expect([only(d.before.findings, 'DUPLICATE_KEY').map(f => f.data?.key), text(d)]).to.deep.equal([['a', 'b', 'a'], '{"b":4,"a":5}']);
    expect(JSON.parse(text(d))).to.deep.equal(JSON.parse('{"a":1,"b":2,"a":3,"b":4,"a":5}'));
  });

  it('removes __proto__ members and a prototype under constructor', async () => {
    const d = await disarmFile(U('{"__proto__":{"isAdmin":true},"x":{"constructor":{"prototype":{"p":1}}},"y":[{"__proto__":1}]}'), { name: 'a.json' });
    expect(only(d.before.findings, 'PROTOTYPE_KEY').map(f => [f.data?.key, f.data?.path])).to.deep.equal([
      ['__proto__', '/__proto__'],
      ['constructor.prototype', '/x/constructor/prototype'],
      ['__proto__', '/y/0/__proto__'],
    ]);
    expect(text(d)).to.equal('{"x":{"constructor":{}},"y":[{}]}');
  });

  it('escapes characters that can end a script element, and lone surrogate escapes, keeping every value', async () => {
    const source = '{"s":"</script><b>&x\u2028\u2029","k<":1,"u":"\\ud800 \\udc00 \\ud83d\\ude00"}';
    const d = await disarmFile(U(source), { name: 'a.json' });
    expect(actions(d.before.findings)).to.deep.equal(['strip JSON/HTML_BREAKOUT', 'strip JSON/LONE_SURROGATE']);
    expect(text(d)).to.equal('{"s":"\\u003c/script\\u003e\\u003cb\\u003e\\u0026x\\u2028\\u2029","k\\u003c":1,"u":"\\ufffd \\ufffd \\ud83d\\ude00"}');
    const before = JSON.parse(source);
    const after = JSON.parse(text(d));
    expect([after.s, after['k<']]).to.deep.equal([before.s, before['k<']]);
  });

  it('reports integers JavaScript cannot hold, rejects what nests past the depth limit, and rejects what is not JSON', async () => {
    expect((await inspectFile(U('[9007199254740991, 9007199254740993, -12345678901234567890, 1.5e300]'), { name: 'a.json' })).findings.map(f => f.data?.value)).to.deep.equal([
      '9007199254740993',
      '-12345678901234567890',
    ]);
    expect(actions((await inspectFile(U(`${'['.repeat(20)}${']'.repeat(20)}`), { name: 'a.json', text: { limits: { depth: 10 } } })).findings)).to.deep.equal(['reject JSON/DEPTH']);
    for (const bad of ['{"a":1,}', "{'a':1}", '{"a":NaN}', '[1] [2]', '{"a":01}', '"\\x"', '', '{"a":1} // note']) {
      expect(actions((await inspectFile(U(bad), { name: 'a.json' })).findings), bad).to.deep.equal(['reject JSON/MALFORMED']);
    }
  });

  it('reads newline-delimited JSON one value per line, and rejects two values on one line', async () => {
    const d = await disarmFile(U('{"a":"<b>"}\n{"b":2}\n'));
    expect([d.status, text(d)]).to.deep.equal(['defused', '{"a":"\\u003cb\\u003e"}\n{"b":2}\n']);
    expect(actions((await inspectFile(U('{"a":1} {"b":2}\n'), { name: 'a.jsonl' })).findings)).to.deep.equal(['reject JSON/MALFORMED']);
  });

  it('writes its escapes in the file encoding', async () => {
    const utf16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('{"a":"<"}', 'utf16le')]);
    const d = await disarmFile(utf16, { name: 'a.json' });
    expect(out(d)).to.deep.equal(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('{"a":"\\u003c"}', 'utf16le')]));
  });

  it('turns script URLs in a source map into #, and reports the source code it carries', async () => {
    const map = JSON.stringify({
      version: 3,
      file: 'app.js',
      sourceRoot: ' data:text/html,x',
      sources: ['javascript:alert(1)', 'src/a.js'],
      sourcesContent: ['alert(1)', null],
      mappings: 'AAAA',
      names: [],
    });
    const d = await disarmFile(U(map), { name: 'app.js.map' });
    expect(actions(d.before.findings)).to.deep.equal(['info TEXT/SCRIPT_URL', 'strip SOURCEMAP/SCRIPT_URL', 'info SOURCEMAP/SOURCES_CONTENT']);
    expect(JSON.parse(text(d))).to.include({ sourceRoot: '#text/html,x' });
    expect(JSON.parse(text(d)).sources).to.deep.equal(['#alert(1)', 'src/a.js']);
    // A JSON file without version 3 and mappings is no source map.
    expect(only((await inspectFile(U('{"sources":["javascript:x"]}'))).findings, 'SCRIPT_URL').map(f => f.category)).to.deep.equal(['TEXT']);
  });

  it('leaves a .map file that is not JSON to the plain text rules', async () => {
    expect((await inspectFile(U('Linker map\n  .text 0x0000 main.o\n'), { name: 'app.map' })).findings).to.deep.equal([]);
  });
});

describe('YAML', () => {
  it('removes tags outside the YAML schemas and keeps their values, through the document directives', async () => {
    const d = await disarmFile(U('a: !!python/object/apply:os.system ["id"]\nb: !local\n  k: v\nok: !!str fine\nc: !<tag:example.com,2000:x> 1\n'), { name: 'a.yml' });
    expect(only(d.before.findings, 'TAG').map(f => f.data?.tag)).to.deep.equal(['tag:yaml.org,2002:python/object/apply:os.system', '!local', 'tag:example.com,2000:x']);
    expect(text(d)).to.equal('a: ["id"]\nb: \n  k: v\nok: !!str fine\nc: 1\n');
    const redefined = await inspectFile(U('%TAG !! tag:evil.example,2000:\n---\na: !!str x\n'), { name: 'a.yaml' });
    expect(only(redefined.findings, 'TAG').map(f => f.data?.tag)).to.deep.equal(['tag:evil.example,2000:str']);
  });

  it('removes __proto__ keys from block and flow mappings, wherever the pair sits', async () => {
    const cases: Array<[string, string]> = [
      ['__proto__:\n  isAdmin: true\nlast: 1\n', 'last: 1\n'],
      ['a: 1\n__proto__: x\n', 'a: 1\n'],
      ['n:\n  a: 1\n  __proto__: x\n  b: 2\n', 'n:\n  a: 1\n  b: 2\n'],
      ['- __proto__: x\n  b: 1\n', '- b: 1\n'],
      ['m: {__proto__: 1, a: 2}\nn: {a: 2, __proto__: 1}\n', 'm: {a: 2}\nn: {a: 2}\n'],
    ];
    for (const [yaml, expected] of cases) {
      const d = await disarmFile(U(yaml), { name: 'a.yaml' });
      expect([d.status, text(d)], yaml).to.deep.equal(['defused', expected]);
    }
  });

  it('rejects duplicate keys, aliases that expand past the limit, and what does not parse', async () => {
    expect(actions((await inspectFile(U('a: 1\na: 2\n'), { name: 'a.yaml' })).findings)).to.deep.equal(['reject YAML/DUPLICATE_KEY']);
    // A repeated merge key is a common way to merge two mappings.
    expect((await inspectFile(U('x: &x {a: 1}\ny: &y {b: 2}\nz:\n  <<: *x\n  <<: *y\n'), { name: 'a.yaml' })).findings).to.deep.equal([]);
    const level = (name: string, of: string) => `${name}: &${name} [${new Array(10).fill(of).join(',')}]\n`;
    const bomb = `${level('a', '"x"')}${level('b', '*a')}${level('c', '*b')}${level('d', '*c')}e: [${new Array(10).fill('*d').join(',')}]\n`;
    expect(actions((await inspectFile(U(bomb), { name: 'a.yaml' })).findings)).to.deep.equal(['reject YAML/ALIAS_EXPANSION']);
    expect((await inspectFile(U(`${level('a', '"x"')}b: [*a, *a]\n`), { name: 'a.yaml' })).findings).to.deep.equal([]);
    expect(actions((await inspectFile(U('a: [1, 2\nb: }\n'), { name: 'a.yaml' })).findings)).to.deep.equal(['reject YAML/MALFORMED']);
  });

  it('rejects nesting past the depth limit, even past what the parser can recurse through', async () => {
    expect(actions((await inspectFile(U(`${'['.repeat(20)}${']'.repeat(20)}\n`), { name: 'a.yaml', text: { limits: { depth: 10 } } })).findings)).to.deep.equal(['reject YAML/DEPTH']);
    // The parser recurses, so this runs it out of stack, which is the depth finding too.
    for (const deep of [`${'['.repeat(200_000)}${']'.repeat(200_000)}\n`, `${Array.from({ length: 3000 }, (_, i) => `${' '.repeat(i)}a:`).join('\n')} 1\n`]) {
      expect(actions((await inspectFile(U(deep), { name: 'a.yaml' })).findings)).to.deep.equal(['reject YAML/DEPTH']);
    }
  });

  it('finds its edits by byte offset in UTF-16 too', async () => {
    const bom = Buffer.from([0xff, 0xfe]);
    const d = await disarmFile(Buffer.concat([bom, Buffer.from('caf\u00e9: !x 1\n__proto__: 2\n', 'utf16le')]), { name: 'a.yaml' });
    expect(out(d)).to.deep.equal(Buffer.concat([bom, Buffer.from('caf\u00e9: 1\n', 'utf16le')]));
  });
});

describe('JavaScript', () => {
  it('claims .js files and node shebangs, keeps them, and says the file is code', async () => {
    const source = U('#!/usr/bin/env node\nconsole.log("<script>")\n');
    const d = await disarmFile(source);
    expect([d.status, out(d).equals(source), actions(d.before.findings)]).to.deep.equal(['clean', true, ['info TEXT/JAVASCRIPT']]);
    expect(actions((await inspectFile(U('let a = 1;\n'), { name: 'a.mjs' })).findings)).to.deep.equal(['info TEXT/JAVASCRIPT']);
  });

  it('still removes bidirectional controls, the Trojan Source attack', async () => {
    const d = await disarmFile(U('if (role === "user\u202e \u2066// admin\u2069 \u2066") {}\n'), { name: 'a.js' });
    expect(only(d.before.findings, 'BIDI_CONTROL')).to.have.length(4);
    expect(text(d)).to.equal('if (role === "user // admin ") {}\n');
  });
});

describe('JSON and YAML inside a container', () => {
  it('reads them by the name the container gives, and JSON by its content, and rewrites them in place', async () => {
    const zip = await createArchiveBytes('zip', [
      { name: 'config/app.yml', data: 'cmd: !!python/object/apply:os.system ["id"]\n' },
      { name: 'data/export', data: '{"__proto__":{"admin":true},"ok":1}' },
      { name: 'notes.txt', data: 'see <script>alert(1)</script>\n' },
    ]);
    const r = await inspectFile(zip, { name: 'bundle.zip' });
    expect(r.findings.filter(f => f.action !== 'info').map(line)).to.deep.equal(['strip YAML/TAG in config/app.yml', 'strip JSON/PROTOTYPE_KEY in data/export', 'strip TEXT/MARKUP in notes.txt']);
    const d = await disarmFile(zip, { name: 'bundle.zip' });
    expect(d.status).to.equal('defused');
    expect((await inspectFile(out(d), { name: 'bundle.zip' })).findings.filter(f => f.action !== 'info')).to.deep.equal([]);
  });
});

describe('style sheets', () => {
  it('go to xml-defuse when the name or the declared type says CSS, and stay text otherwise', async () => {
    const css = U('body { background: url(javascript:alert(1)); width: expression(1); }\na { color: red; }\n');
    for (const hints of [{ name: 'site.css' }, { declaredType: 'text/css' }]) {
      expect((await inspectFile(css, hints)).package).to.equal('xml');
      const d = await disarmFile(css, hints);
      expect([d.status, actions(d.before.findings)]).to.deep.equal(['defused', ['strip SCRIPT/URL', 'strip STYLE/EXPRESSION']]);
      expect(text(d)).to.equal('body {   }\na { color: red; }\n');
    }
    expect((await inspectFile(css)).package).to.equal('text');
  });
});
