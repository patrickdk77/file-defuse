import type { FindingFactory } from './findings';
import { type ByteSink, type ByteSource, FileCategory as C, FileDetail as D, type FileFinding, type FileOptions } from './types';

/** The optional peer that flattens dynamic XFA forms. */
export const FLATTEN_PACKAGE = '@patrickdk77/xfa-flatten';

const HOW = `Install ${FLATTEN_PACKAGE} and run Node 22.13 or later.`;

/** Something xfa-flatten did not draw or do, and why. */
export interface FlattenNote {
  kind: string;
  location: string;
  detail: string;
}

/**
 * The part of @patrickdk77/xfa-flatten file-defuse calls. It is declared here, so that no type file-defuse publishes
 * names the optional peer.
 */
export interface Flattener {
  flattenXfaSource(source: ByteSource, sink: ByteSink, options: { deadline?: number; limits?: { pixels?: number } }): Promise<{ status: string; pages?: number; notes: FlattenNote[] }>;
}

/** A version as [major, minor, patch], from text such as "22.13.0", "v24.1" or ">=22.13.0". */
function versionIn(text: string): number[] | undefined {
  const m = /(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(text);
  return m ? [Number(m[1]), Number(m[2] ?? 0), Number(m[3] ?? 0)] : undefined;
}

const below = (a: number[], b: number[]) => (a[0] !== b[0] ? a[0] < b[0] : a[1] !== b[1] ? a[1] < b[1] : a[2] < b[2]);

/**
 * Throws when Node `running` is below the lowest version an `engines.node` range names. xfa-flatten's is ">=22.13.0",
 * the floor of pdfjs-dist 6. On an older Node the module can load and pdf.js fail later inside every form, which would
 * read as a quiet FLATTEN/FAILED, so the check runs before the module loads.
 */
export function checkNodeVersion(running: string, range: string | undefined): void {
  if (range === undefined) return;
  const floors = range
    .split('||')
    .map(versionIn)
    .filter((v): v is number[] => v !== undefined);
  if (!floors.length) return;
  const floor = floors.reduce((low, v) => (below(v, low) ? v : low));
  const now = versionIn(running);
  if (now === undefined || below(now, floor)) {
    throw new Error(`The flattenXfa option needs Node ${floor.join('.')} or later, as ${FLATTEN_PACKAGE} declares in engines.node, and this is Node ${running}. ${HOW}`);
  }
}

function notLoadable(e: unknown): Error {
  const reason = e instanceof Error ? e.message.split('\n')[0] : String(e);
  return new Error(`The flattenXfa option needs ${FLATTEN_PACKAGE}, which could not be loaded: ${reason}. ${HOW}`, { cause: e });
}

/**
 * Loads xfa-flatten's CommonJS entry with `load`, after checking that Node `running` meets the floor its package.json
 * declares. Throws an Error that says why when it cannot run.
 */
export function loadFlattener(load: (id: string) => unknown, running: string): Flattener {
  let engines: unknown;
  try {
    engines = (load(`${FLATTEN_PACKAGE}/package.json`) as { engines?: { node?: unknown } } | undefined)?.engines?.node;
  } catch (e) {
    throw notLoadable(e);
  }
  checkNodeVersion(running, typeof engines === 'string' ? engines : undefined);
  let mod: unknown;
  try {
    mod = load(FLATTEN_PACKAGE);
  } catch (e) {
    throw notLoadable(e);
  }
  if (typeof (mod as Partial<Flattener> | undefined)?.flattenXfaSource !== 'function') throw notLoadable(new Error('it has no flattenXfaSource export'));
  return mod as Flattener;
}

const realLoader = (): Flattener => loadFlattener(require, process.versions.node);
let loader = realLoader;
/** The outcome of the one load per process. */
let loaded: { flattener: Flattener } | { error: unknown } | undefined;

/** For tests: loads xfa-flatten with `load` from now on, or the real way again when it is undefined. */
export function setFlattenerLoader(load?: () => Flattener): void {
  loader = load ?? realLoader;
  loaded = undefined;
}

/**
 * xfa-flatten for a disarm with `options`, or undefined when the flattenXfa option is off. It is loaded once per
 * process, and a failed load throws the same error every time.
 */
export function flattenerFor(options: FileOptions): Flattener | undefined {
  if (!options.flattenXfa) return undefined;
  if (!loaded) {
    try {
      loaded = { flattener: loader() };
    } catch (error) {
      loaded = { error };
    }
  }
  if ('error' in loaded) throw loaded.error;
  return loaded.flattener;
}

/** The options for xfa-flatten's run. */
export function flattenOptions(options: FileOptions, deadline: number | undefined): { deadline?: number; limits?: { pixels?: number } } {
  const pixels = typeof options.flattenXfa === 'object' ? options.flattenXfa.limits?.pixels : undefined;
  return { ...(deadline === undefined ? {} : { deadline }), ...(pixels === undefined ? {} : { limits: { pixels } }) };
}

/**
 * Text from xfa-flatten, which can hold names, paths and values from the PDF, as pdf-defuse shows such values in a
 * description: each control or format character, the bidirectional controls among them, becomes "?", and text over
 * `max` characters is cut, with "..." at the end.
 */
export function shown(text: string, max: number): string {
  const chars = [...text.replace(/[\p{Cc}\p{Cf}]/gu, '?')];
  return chars.length > max ? `${chars.slice(0, max - 3).join('')}...` : chars.join('');
}

/** How long a description from xfa-flatten's notes may be. A note is a sentence, longer than a value from the PDF. */
const DETAIL_MAX = 300;

/** The note kinds xfa-flatten gives the reason a run failed under. */
const FAILURE_KINDS = new Set(['layout-error', 'render-error', 'deadline', 'too-large', 'too-complex']);

/** True when a note says the deadline passed. */
export const deadlinePassed = (notes: FlattenNote[]) => notes.some(n => n.kind === 'deadline');

/**
 * A finding that can only keep the file or refuse it: removing what it names would remove the whole file, so `strip`
 * rejects, as for TYPE/NO_PACKAGE.
 */
function keepOrReject(f: FileFinding): FileFinding {
  if (f.action === 'strip') f.action = 'reject';
  return f;
}

/** FLATTEN/NOTE for one of xfa-flatten's notes on a form it flattened. */
export function noteFinding(factory: FindingFactory, note: FlattenNote): FileFinding {
  const f = factory.make(C.Flatten, D.Note, { kind: shown(note.kind, 60) }, shown(note.detail, DETAIL_MAX));
  f.location = shown(note.location, DETAIL_MAX);
  return keepOrReject(f);
}

/** FLATTEN/FAILED, with xfa-flatten's notes as the reason, the ones that say why it failed first. */
export function failedFinding(factory: FindingFactory, notes: FlattenNote[]): FileFinding {
  const ordered = [...notes.filter(n => FAILURE_KINDS.has(n.kind)), ...notes.filter(n => !FAILURE_KINDS.has(n.kind))];
  const data = ordered.length ? { kind: shown(ordered[0].kind, 60), reason: shown(ordered.map(n => n.detail).join(' '), DETAIL_MAX) } : undefined;
  return keepOrReject(factory.make(C.Flatten, D.Failed, data));
}
