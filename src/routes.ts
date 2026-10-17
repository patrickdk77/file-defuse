import { type ArchiveOptions, archivePlugin, allFindingSpecs as archiveSpecs, disarmArchiveSource, inspectArchiveSource } from '@patrickdk77/archive-defuse';
import { disarmImageSource, type ImageOptions, imagePlugin, allFindingSpecs as imageSpecs, inspectImageSource } from '@patrickdk77/img-defuse';
import { disarmOfficeSource, inspectOfficeSource, type OfficeOptions, officePlugin, allFindingSpecs as officeSpecs } from '@patrickdk77/office-defuse';
import { disarmPdfSource, inspectPdfSource, type PdfOptions, pdfPlugin, allFindingSpecs as pdfSpecs } from '@patrickdk77/pdf-defuse';
import { formScriptPlugin } from '@patrickdk77/script-defuse';
import { disarmXmlSource, inspectXmlSource, type XmlOptions, xmlPlugin, allFindingSpecs as xmlSpecs } from '@patrickdk77/xml-defuse';
import type { DetectHints, FileFamily } from './detect';
import { TextReader, textPlugin } from './text';
import type { ByteSink, ByteSource, ContainedFilePlugin, DefuseFinding, FileOptions, FileSection } from './types';

/** An inspection as every package of the family returns one. */
export interface PackageInspection {
  status: 'clean' | 'strippable' | 'rejected';
  score: number | null;
  risk: string;
  findings: DefuseFinding[];
}

/** A disarm result as every package of the family returns one. */
export interface PackageDisarm {
  status: 'clean' | 'defused' | 'rejected';
  before: PackageInspection;
  after?: PackageInspection;
  removed: DefuseFinding[];
}

/** One package, with the options one tree of files uses for it. */
export interface Reader {
  section: FileSection;
  /** The package's plugin, which the tree hands every file of this type inside the upload. */
  plugin: ContainedFilePlugin;
  /** Runs the package on the upload. `timeMs`, when given, caps the package's own time limit. */
  inspect(source: ByteSource, timeMs: number | undefined, hints: DetectHints): Promise<PackageInspection>;
  disarm(source: ByteSource, sink: ByteSink, timeMs: number | undefined, hints: DetectHints): Promise<PackageDisarm>;
  /** Sets `weight` on the package's own findings, and 0 on any finding from inside a file that came without one. */
  weigh(findings: DefuseFinding[] | undefined): void;
  /** The section's score bands, when it sets them. */
  bands?: { low: number; medium: number; high: number; critical: number };
  /** The memory threshold and temporary directory the package uses, which the router's copy of its output keeps to. */
  memoryThreshold?: number;
  tempDir?: string;
}

/** The options file-defuse shares with the packages that take them. */
interface Shared {
  password?: string | string[];
  stripMetadata?: boolean;
  tempDir?: string;
  memoryThreshold?: number;
  filePlugins?: ContainedFilePlugin[];
  limits?: { timeMs?: number };
  scoreWeights?: ReadonlyArray<{ category: string; detail?: string; weight: number }>;
  scoreBands?: { low: number; medium: number; high: number; critical: number };
}

type SharedKey = 'password' | 'stripMetadata' | 'tempDir' | 'memoryThreshold';

interface Package<O extends Shared> {
  section: FileSection;
  /** The shared options this package takes. */
  takes: ReadonlyArray<SharedKey>;
  options(o: FileOptions): O | undefined;
  plugin(o: O): ContainedFilePlugin;
  inspect(source: ByteSource, o: O): Promise<PackageInspection>;
  disarm(source: ByteSource, sink: ByteSink, o: O): Promise<PackageDisarm>;
  /** The options for the upload alone, from what the caller says of it, such as its name. */
  upload?(o: O, hints: DetectHints): O;
  /** The weight of each kind of finding the package makes, by "CATEGORY/DETAIL". */
  weights: ReadonlyMap<string, number>;
}

/** The section with the shared options the package takes, unless the section sets them. */
function withShared<O extends Shared>(section: O, takes: ReadonlyArray<SharedKey>, options: FileOptions): O {
  const shared: Shared = section;
  for (const key of takes) {
    if (shared[key] !== undefined || options[key] === undefined) continue;
    if (key === 'password') shared.password = options.password;
    else if (key === 'stripMetadata') shared.stripMetadata = options.stripMetadata;
    else if (key === 'tempDir') shared.tempDir = options.tempDir;
    else shared.memoryThreshold = options.memoryThreshold;
  }
  return section;
}

/** The time limit of a run: the section's own, or what is left of the tree's when that is shorter. */
function timed<O extends Shared>(bound: O, timeMs?: number): O {
  if (timeMs === undefined) return bound;
  const own = bound.limits?.timeMs;
  return { ...bound, limits: { ...bound.limits, timeMs: own === undefined ? timeMs : Math.min(own, timeMs) } };
}

/** A weight function: the section's scoreWeights first, then the package's table, then the weight the finding carries. */
function weigher(scoreWeights: Shared['scoreWeights'], table: ReadonlyMap<string, number>) {
  return (f: DefuseFinding): number => {
    const w = scoreWeights ?? [];
    const exact = w.find(x => x.category === f.category && x.detail === f.detail);
    if (exact) return exact.weight;
    const cat = w.find(x => x.category === f.category && x.detail === undefined);
    if (cat) return cat.weight;
    return table.get(`${f.category}/${f.detail}`) ?? f.weight ?? 0;
  };
}

/**
 * The package's section with the shared options it takes, unless the section sets them, and with `router` after the
 * caller's own file plugins.
 */
function bind<O extends Shared>(p: Package<O>, options: FileOptions, router: ContainedFilePlugin): Reader {
  const section = p.options(options) ?? ({} as O);
  const bound = withShared<O>({ ...section, filePlugins: [...(section.filePlugins ?? []), router] }, p.takes, options);
  const weightOf = weigher(bound.scoreWeights, p.weights);
  return {
    section: p.section,
    plugin: p.plugin(bound),
    inspect: (source, timeMs, hints) => p.inspect(source, timed(p.upload ? p.upload(bound, hints) : bound, timeMs)),
    disarm: (source, sink, timeMs, hints) => p.disarm(source, sink, timed(p.upload ? p.upload(bound, hints) : bound, timeMs)),
    weigh(findings) {
      // A finding from inside a file carries the weight its own package gave it.
      for (const f of findings ?? []) f.weight = f.attachment === undefined ? weightOf(f) : (f.weight ?? 0);
    },
    bands: bound.scoreBands,
    memoryThreshold: bound.memoryThreshold,
    tempDir: bound.tempDir,
  };
}

const weightsOf = (specs: ReadonlyArray<{ category: string; detail: string; weight: number }>) => new Map(specs.map(s => [`${s.category}/${s.detail}`, s.weight]));

/**
 * The options of one PDF's run, with a script-defuse plugin of its own after any script plugins the caller gave. The
 * plugin keeps the AcroForm and XFA scripts that only format, check or calculate form fields, and remembers the
 * document scripts it kept for the field scripts that call them, so every PDF needs a new one.
 */
function withScripts(o: PdfOptions): PdfOptions {
  return { ...o, scriptPlugins: [...(o.scriptPlugins ?? []), formScriptPlugin()] };
}

const PDF: Package<PdfOptions> = {
  section: 'pdf',
  takes: ['password', 'stripMetadata', 'tempDir', 'memoryThreshold'],
  options: o => o.pdf,
  // Every PDF found inside a file runs with these options, so each one gets its plugin when it is processed.
  plugin: o => {
    const plugin = pdfPlugin(o);
    return { ...plugin, process: (file, sink, context) => pdfPlugin(withScripts(o)).process(file, sink, context) };
  },
  inspect: (source, o) => inspectPdfSource(source, withScripts(o)),
  disarm: (source, sink, o) => disarmPdfSource(source, sink, withScripts(o)),
  weights: weightsOf(pdfSpecs()),
};

/**
 * The options of one Office file's run, with a script-defuse plugin of its own after any script plugins the caller
 * gave. office-defuse shows it the modules of the file's VBA project, which stays when the plugin passes every module.
 */
function withOfficeScripts(o: OfficeOptions): OfficeOptions {
  return { ...o, scriptPlugins: [...(o.scriptPlugins ?? []), formScriptPlugin()] };
}

const OFFICE: Package<OfficeOptions> = {
  section: 'office',
  takes: ['password', 'tempDir', 'memoryThreshold'],
  options: o => o.office,
  // Every Office file found inside a file runs with these options, so each one gets its plugin when it is processed.
  plugin: o => {
    const plugin = officePlugin(o);
    return { ...plugin, process: (file, sink, context) => officePlugin(withOfficeScripts(o)).process(file, sink, context) };
  },
  inspect: (source, o) => inspectOfficeSource(source, withOfficeScripts(o)),
  disarm: (source, sink, o) => disarmOfficeSource(source, sink, withOfficeScripts(o)),
  weights: weightsOf(officeSpecs()),
};

const IMAGE: Package<ImageOptions> = {
  section: 'image',
  takes: ['stripMetadata', 'tempDir', 'memoryThreshold'],
  options: o => o.image,
  plugin: imagePlugin,
  inspect: inspectImageSource,
  disarm: disarmImageSource,
  weights: weightsOf(imageSpecs()),
};

const XML: Package<XmlOptions> = {
  section: 'xml',
  takes: ['stripMetadata', 'tempDir', 'memoryThreshold'],
  options: o => o.xml,
  plugin: xmlPlugin,
  inspect: inspectXmlSource,
  disarm: disarmXmlSource,
  // xml-defuse reads the upload's name for a name ending in .hta, and the name and declared type to read a style sheet.
  // A file inside gets its own from the plugin.
  upload: (o, hints) => ({ ...o, ...(hints.name === undefined ? {} : { name: hints.name }), ...(hints.declaredType === undefined ? {} : { declaredType: hints.declaredType }) }),
  weights: weightsOf(xmlSpecs()),
};

const ARCHIVE: Package<ArchiveOptions> = {
  section: 'archive',
  takes: ['password', 'stripMetadata', 'tempDir', 'memoryThreshold'],
  options: o => o.archive,
  plugin: archivePlugin,
  inspect: inspectArchiveSource,
  disarm: disarmArchiveSource,
  weights: weightsOf(archiveSpecs()),
};

/** file-defuse's own text rules, as a reader like any package's. */
function textReader(options: FileOptions): Reader {
  const section = withShared({ ...(options.text ?? {}) }, ['tempDir', 'memoryThreshold'], options);
  const reader = new TextReader(section);
  const deadlineOf = (timeMs?: number) => (timeMs === undefined ? undefined : Date.now() + timeMs);
  return {
    section: 'text',
    plugin: textPlugin(reader),
    inspect: (source, timeMs, hints) => reader.inspect(source, hints, deadlineOf(timeMs)),
    disarm: (source, sink, timeMs, hints) => reader.disarm(source, sink, hints, deadlineOf(timeMs)),
    weigh(findings) {
      for (const f of findings ?? []) f.weight = f.attachment === undefined ? reader.weightOf(f) : (f.weight ?? 0);
    },
    bands: section.scoreBands,
    memoryThreshold: section.memoryThreshold,
    tempDir: section.tempDir,
  };
}

/** The packages file-defuse calls, by family. A family with no entry has no package wired in yet. */
const PACKAGES: Partial<Record<FileFamily, (options: FileOptions, router: ContainedFilePlugin) => Reader>> = {
  pdf: (options, router) => bind(PDF, options, router),
  office: (options, router) => bind(OFFICE, options, router),
  image: (options, router) => bind(IMAGE, options, router),
  xml: (options, router) => bind(XML, options, router),
  archive: (options, router) => bind(ARCHIVE, options, router),
  text: options => textReader(options),
};

/** The reader for files of a family, or undefined when no package of the family reads them yet. */
export function readerFor(family: FileFamily, options: FileOptions, router: ContainedFilePlugin): Reader | undefined {
  return PACKAGES[family]?.(options, router);
}
