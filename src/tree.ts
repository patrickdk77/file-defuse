import { type Detected, type DetectHints, detectSource, type FileFamily, type FileSignature } from './detect';
import { FindingFactory } from './findings';
import { type PackageInspection, type Reader, readerFor } from './routes';
import { DEFAULT_MEMORY_THRESHOLD, Spill } from './spill';
import {
  type ByteSink,
  type ByteSource,
  FileCategory as C,
  type ContainedFile,
  type ContainedFilePlugin,
  type ContainedFileResult,
  FileDetail as D,
  type DefuseFinding,
  type FileDisarmResult,
  type FileFinding,
  type FileInspection,
  type FileOptions,
  FileRisk,
  type PluginContext,
} from './types';

export const DEFAULT_LIMITS = { nestingDepth: 10, files: 10_000, decodedBytes: 2 * 1024 ** 3 };

/**
 * Thrown when the tree crosses one of file-defuse's limits. The code makes every package of the family pass it up to
 * the upload. `limit` is 'nesting' or 'time' for the limits every package knows, and 'files' or 'decodedBytes' for
 * the two only file-defuse counts.
 */
export class TreeLimitError extends Error {
  readonly code = 'DEFUSE_LIMIT';
  constructor(
    readonly limit: 'nesting' | 'time' | 'files' | 'decodedBytes',
    readonly finding: FileFinding,
  ) {
    super(finding.description);
  }
}

/** The code of an error that stops the whole tree of files, from any package of the family. */
export function stopsTree(e: unknown): 'DEFUSE_LIMIT' | 'DEFUSE_IO' | undefined {
  const code = typeof e === 'object' && e !== null ? (e as { code?: unknown }).code : undefined;
  return code === 'DEFUSE_LIMIT' || code === 'DEFUSE_IO' ? code : undefined;
}

/** The source without its close(), so a package cannot close a source file-defuse or a container still reads. */
const unclosable = (source: ByteSource): ByteSource => ({ size: () => source.size(), read: (offset, length) => source.read(offset, length) });

const RISKS = new Set<string>(Object.values(FileRisk));
const toRisk = (risk: string): FileRisk => (RISKS.has(risk) ? (risk as FileRisk) : FileRisk.Unknown);
const DEFAULT_BANDS = { low: 1, medium: 25, high: 50, critical: 80 };
const riskOf = (score: number, bands = DEFAULT_BANDS) =>
  score >= bands.critical ? FileRisk.Critical : score >= bands.high ? FileRisk.High : score >= bands.medium ? FileRisk.Medium : score >= bands.low ? FileRisk.Low : FileRisk.None;

const isLimit = (f: DefuseFinding) => f.attachment === undefined && f.category === 'LIMIT' && (f.detail === 'TIME' || f.detail === 'NESTING_DEPTH');

/** The family's score of a set of findings: the highest weight in full and a quarter of each other kind's. */
function familyScore(findings: DefuseFinding[]): number {
  const byKind = new Map<string, number>();
  for (const f of findings) byKind.set(`${f.category}/${f.detail}`, Math.max(byKind.get(`${f.category}/${f.detail}`) ?? 0, f.weight ?? 0));
  const w = [...byKind.values()].sort((a, b) => b - a);
  return w.length ? w[0] + w.slice(1).reduce((t, x) => t + x / 4, 0) : 0;
}

/** Findings an upload's score leaves out, as every package of the family does: files a plugin kept. */
const scored = (f: DefuseFinding) => f.attachment === undefined && f.detail !== 'PLUGIN_PASSED' && f.detail !== 'PLUGIN_SCRUBBED';

const REASONS: Record<NonNullable<Detected['chosenBy']>, string> = { name: 'by its name', declaredType: 'by its declared type', firstSignature: 'by the signature at its start' };

/** The package for a file, with the file as that package sees it, and what detection found either way. */
export type Pick = { reader: Reader; file: ContainedFile; detection: Detected } | { reader?: undefined; detection: Detected };

/**
 * One upload and every file inside it. The tree counts the files and their decoded bytes, keeps the one deadline, and
 * puts its router in every package's filePlugins, so each file a package finds comes back here.
 */
export class Tree {
  readonly deadline?: number;
  /** The tree limit the run crossed, once the router has thrown it. */
  stopped?: TreeLimitError;
  readonly router: ContainedFilePlugin;
  readonly factory: FindingFactory;
  private readonly readers = new Map<string, Reader | undefined>();
  private files = 0;
  private decoded = 0;

  /**
   * `rootDepth` is the depth of the file the tree starts at, which is not counted. `deadline` comes from the context
   * of a container that called file-defuse, and the earlier of it and the tree's own time limit applies.
   */
  constructor(
    private readonly options: FileOptions,
    private readonly rootDepth: number,
    deadline?: number,
  ) {
    const timeMs = options.limits?.timeMs;
    const own = timeMs === undefined ? undefined : Date.now() + timeMs;
    this.deadline = deadline === undefined ? own : own === undefined ? deadline : Math.min(deadline, own);
    this.factory = new FindingFactory(options.actionOverrides);
    this.router = {
      kind: 'file',
      name: 'file-defuse',
      accepts: file => this.accepts(file),
      process: (file, sink, context) => this.process(file, sink, context),
    };
  }

  private reader(family: FileFamily): Reader | undefined {
    if (!this.readers.has(family)) this.readers.set(family, readerFor(family, this.options, this.router));
    return this.readers.get(family);
  }

  /** Detects the file's format and asks the package's plugin whether it takes the file. */
  async pick(file: ContainedFile): Promise<Pick> {
    const detection = await detectSource(file.source, file.size, { name: file.name, declaredType: file.declaredType }, this.deadline);
    const reader = detection.family && this.reader(detection.family);
    if (!reader) return { detection };
    const view: ContainedFile = { ...file, sniffedType: detection.sniffedType, source: unclosable(file.source) };
    if (await reader.plugin.accepts(view)) return { reader, file: view, detection };
    return { detection };
  }

  /**
   * The package for the upload. When its plugin does not take the file, such as an Office package whose ZIP structure
   * office-defuse refuses, the package of the detected family still reads it, so its own refusal names the problem.
   */
  async pickUpload(file: ContainedFile): Promise<Pick> {
    const picked = await this.pick(file);
    const reader = !picked.reader && picked.detection.family ? this.reader(picked.detection.family) : undefined;
    if (!reader) return picked;
    return { reader, file: { ...file, sniffedType: picked.detection.sniffedType, source: unclosable(file.source) }, detection: picked.detection };
  }

  /** True when a package of the family reads the file. Otherwise the container's own rule decides it. */
  async accepts(file: ContainedFile): Promise<boolean> {
    return (await this.pick(file)).reader !== undefined;
  }

  /** The time left, for a package that takes a time limit instead of a deadline. */
  remaining(): number | undefined {
    return this.deadline === undefined ? undefined : Math.max(0, this.deadline - Date.now());
  }

  private stop(limit: TreeLimitError['limit'], detail: D, data?: Record<string, string | number>): never {
    this.stopped = new TreeLimitError(limit, this.factory.make(C.Limit, detail, data));
    throw this.stopped;
  }

  /** Counts a file inside the upload and throws when the tree crosses a limit. */
  private enter(file: ContainedFile, depth: number): void {
    if (this.stopped) throw this.stopped;
    const limits = { ...DEFAULT_LIMITS, ...this.options.limits };
    if (depth > this.rootDepth) {
      this.files++;
      this.decoded += file.size;
    }
    if (depth > limits.nestingDepth) this.stop('nesting', D.NestingDepth, { depth, limit: limits.nestingDepth });
    if (this.files > limits.files) this.stop('files', D.FileCount, { limit: limits.files });
    if (this.decoded > limits.decodedBytes) this.stop('decodedBytes', D.DecodedSize, { limit: limits.decodedBytes });
    this.checkTime();
  }

  /** Throws the time limit once the deadline has passed. */
  checkTime(): void {
    if (this.deadline !== undefined && Date.now() > this.deadline) this.stop('time', D.Time);
  }

  /**
   * A place for a package's output, so the router can check it before it goes on. It keeps to the memory threshold
   * and temporary directory the package itself uses.
   */
  spill(reader: Reader): Spill {
    return new Spill(reader.memoryThreshold ?? this.options.memoryThreshold ?? DEFAULT_MEMORY_THRESHOLD, reader.tempDir ?? this.options.tempDir);
  }

  /**
   * The router's findings for a polyglot: one for each format the file is not handled as. A part the package keeps in
   * data it needs, as its own POLYGLOT finding at that offset says, or any part when no package rewrites the file,
   * cannot be removed, so the finding rejects. A package's own finding for the same signature keeps the score, and
   * this one adds nothing to it.
   */
  polyglot(d: Detected, packageFindings: DefuseFinding[] | undefined, rewritten: boolean): FileFinding[] {
    const out: FileFinding[] = [];
    // A package names the same part at its own offset, such as img-defuse a ZIP archive at its end record, so a finding
    // is the package's own for a signature when it falls between that signature and the next one.
    const starts = d.signatures.map(x => x.offset).sort((a, b) => a - b);
    for (const s of d.others) {
      const end = starts.find(o => o > s.offset) ?? Number.POSITIVE_INFINITY;
      const own = packageFindings?.find(p => {
        const at = p.data?.offset;
        return p.attachment === undefined && p.category === 'POLYGLOT' && typeof at === 'number' && at >= s.offset && at < end;
      });
      const reason = d.chosenBy ?? 'firstSignature';
      const data = { type: s.mimeType, offset: s.offset, handledAs: d.mimeType, reason };
      const f = this.factory.make(C.Type, D.Polyglot, data);
      if (f.action === 'strip' && (!rewritten || own?.action === 'reject')) f.action = 'reject';
      const outcome = f.action === 'strip' ? 'is removed' : f.action === 'reject' ? 'cannot be removed without breaking the file, so the file is rejected' : 'is kept';
      f.description = `The file is also ${s.mimeType}, at offset ${s.offset}. It is handled as ${d.mimeType}, chosen ${REASONS[reason]}, and the ${s.mimeType} part ${outcome}`;
      f.location = `offset ${s.offset}`;
      if (own) f.weight = 0;
      out.push(f);
    }
    return out;
  }

  /**
   * Detects the output again. A format besides the one the output is handled as is a part the rewrite left, and so is
   * any format at all when the output no longer belongs to the family the file was read by. A format whose polyglot
   * finding an override made `info` is not held against it.
   */
  async leftover(d: Detected, output: ByteSource, size: number, hints: DetectHints, findings: FileFinding[]): Promise<FileSignature[]> {
    const again = await detectSource(output, size, hints, this.deadline);
    const kept = new Set(findings.filter(f => f.action === 'info').map(f => f.data?.type));
    const second = again.family === d.family ? again.others : again.signatures;
    return second.filter(s => !kept.has(s.mimeType));
  }

  verificationFailed(left: FileSignature[]): FileFinding {
    return this.factory.make(C.Processing, D.VerificationFailed, { reasons: left.map(s => `${s.mimeType} at offset ${s.offset}`).join(', ') });
  }

  /**
   * Routes one file to the package that reads it, with the context its container gave and the tree's deadline. A
   * tree limit throws, whatever the depth: the package that found the file passes the error up to the upload. The
   * package writes to a spill, and the router checks the output for a second format before it reaches `sink`.
   */
  async process(file: ContainedFile, sink: ByteSink, context: PluginContext): Promise<ContainedFileResult> {
    this.enter(file, context.depth);
    const picked = await this.pick(file);
    if (!picked.reader) return this.unknown(picked.detection);
    const deadline = context.deadline === undefined ? this.deadline : this.deadline === undefined ? context.deadline : Math.min(context.deadline, this.deadline);
    const spill = this.spill(picked.reader);
    try {
      const out = await picked.reader.plugin.process(picked.file, spill, { depth: context.depth, deadline });
      const r: ContainedFileResult = typeof out === 'string' ? { result: out } : out;
      picked.reader.weigh(r.findings);
      picked.reader.weigh(r.outputFindings);
      const poly = this.polyglot(picked.detection, r.findings, true);
      if (poly.length) r.findings = [...poly, ...(r.findings ?? [])];
      if (r.result === 'removed') return r;
      if (poly.some(f => f.action === 'reject')) return { result: 'removed', findings: r.findings };
      const hints = { name: file.name, declaredType: file.declaredType };
      const written = spill.size > 0;
      const output = written ? spill.source() : picked.file.source;
      const left = await this.leftover(picked.detection, output, written ? spill.size : file.size, hints, poly);
      if (left.length) return { result: 'removed', findings: [...(r.findings ?? []), this.verificationFailed(left)] };
      if (written) await spill.copyTo(sink, () => this.checkTime());
      if (r.result === 'passed' && written && poly.some(f => f.action === 'strip')) r.result = 'scrubbed';
      return r;
    } finally {
      await spill.dispose();
    }
  }

  /**
   * A file no package reads, handed to file-defuse directly instead of through accepts(). Its finding can only keep
   * the file or reject it, since stripping the whole file would leave nothing.
   */
  unknown(d: Detected): ContainedFileResult {
    const findings = [...this.polyglot(d, undefined, false), this.noPackage(d)];
    return { result: findings.some(f => f.action !== 'info') ? 'removed' : 'passed', findings };
  }

  noPackage(d: Detected): FileFinding {
    const data: Record<string, string> = {};
    if (d.mimeType !== 'application/octet-stream') data.sniffed = d.mimeType;
    const f = this.factory.make(C.Type, D.NoPackage, Object.keys(data).length ? data : undefined);
    if (f.action === 'strip') f.action = 'reject';
    return f;
  }

  /** The finding for a limit error at the upload, from file-defuse or from a package. */
  limitFinding(e: unknown): FileFinding {
    if (e instanceof TreeLimitError) return e.finding;
    return this.factory.make(C.Limit, (e as { limit?: unknown }).limit === 'nesting' ? D.NestingDepth : D.Time);
  }

  /**
   * After a tree limit stopped the run, the package's report of it gives way to file-defuse's own, whose detail
   * names the limit the tree crossed. True when the run was stopped.
   */
  settle(findings: DefuseFinding[]): boolean {
    if (!this.stopped) return false;
    for (let i = findings.length - 1; i >= 0; i--) {
      if (isLimit(findings[i])) {
        findings.splice(i, 1);
        break;
      }
    }
    findings.push(this.stopped.finding);
    return true;
  }

  /**
   * The upload's inspection from the package that read it, weighted, with the router's polyglot findings first, or
   * rejected when a tree limit stopped it. A polyglot finding that rejects rejects the upload, and one that strips
   * makes it strippable. Its weight adds to the package's score the way the family adds a kind of finding.
   */
  wrap(reader: Reader, i: PackageInspection, d?: Detected): FileInspection {
    reader.weigh(i.findings);
    const poly = d ? this.polyglot(d, i.findings, true) : [];
    const findings = [...poly, ...i.findings];
    if (this.settle(findings)) return { status: 'rejected', score: null, risk: FileRisk.Unknown, findings, package: reader.section };
    let status = i.status;
    if (poly.some(f => f.action === 'reject')) status = 'rejected';
    else if (status === 'clean' && poly.some(f => f.action === 'strip')) status = 'strippable';
    let score = i.score;
    let risk = toRisk(i.risk);
    const added = poly.filter(f => (f.weight ?? 0) > 0);
    if (score !== null && added.length) {
      const base = i.findings.filter(scored);
      score = Math.min(100, Math.round(score + familyScore([...base, ...added]) - familyScore(base)));
      risk = riskOf(score, reader.bands);
    }
    return { status, score, risk, findings, package: reader.section };
  }

  /** An upload rejected without a package's verdict. */
  static rejected(findings: DefuseFinding[]): FileInspection {
    return { status: 'rejected', score: null, risk: FileRisk.Unknown, findings };
  }

  /** The inspection of an upload no package reads. */
  unknownInspection(d: Detected): FileInspection {
    const findings = [...this.polyglot(d, undefined, false), this.noPackage(d)];
    return { status: findings.some(f => f.action !== 'info') ? 'rejected' : 'clean', score: null, risk: FileRisk.Unknown, findings };
  }

  /** A rejected disarm result from an inspection. */
  static refused(before: FileInspection): FileDisarmResult {
    return { status: 'rejected', before, removed: [] };
  }
}
