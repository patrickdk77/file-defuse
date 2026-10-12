import type { ArchiveOptions } from '@patrickdk77/archive-defuse';
import type { ImageOptions } from '@patrickdk77/img-defuse';
import type { OfficeOptions } from '@patrickdk77/office-defuse';
import type { PdfOptions } from '@patrickdk77/pdf-defuse';
import type { XmlOptions } from '@patrickdk77/xml-defuse';
import type { TextOptions } from './text';

/** High-level kind of a finding file-defuse makes itself. */
export enum FileCategory {
  Type = 'TYPE',
  Limit = 'LIMIT',
  Text = 'TEXT',
  Link = 'LINK',
  Processing = 'PROCESSING',
}

/** Exact variant of a finding file-defuse makes itself. */
export enum FileDetail {
  // TYPE
  NoPackage = 'NO_PACKAGE',
  Polyglot = 'POLYGLOT',
  // TEXT
  Encoding = 'ENCODING',
  UnnamedEncoding = 'UNNAMED_ENCODING',
  ControlCharacter = 'CONTROL_CHARACTER',
  BidiControl = 'BIDI_CONTROL',
  Formula = 'FORMULA',
  UnclosedQuote = 'UNCLOSED_QUOTE',
  // LINK
  ScriptUrl = 'SCRIPT_URL',
  DataUrl = 'DATA_URL',
  // PROCESSING
  VerificationFailed = 'VERIFICATION_FAILED',
  // LIMIT
  FileSize = 'FILE_SIZE',
  NestingDepth = 'NESTING_DEPTH',
  FileCount = 'FILE_COUNT',
  DecodedSize = 'DECODED_SIZE',
  Time = 'TIME',
}

export type FileFindingAction = 'reject' | 'strip' | 'info';

/**
 * A finding as any package of the defuse family reports it. Category and detail are plain strings, since the string
 * enums of two packages never match each other.
 */
export interface DefuseFinding {
  category: string;
  detail: string;
  /** Plain sentence, safe to show the uploader. */
  description: string;
  /** Default action after any caller override. */
  action: 'reject' | 'strip' | 'info';
  /** Where in the file, e.g. "page 3, annotation 2". */
  location?: string;
  /** Extra values: the URI, key length, plugin name, counts. */
  data?: Record<string, string | number>;
  /**
   * Set when the finding comes from inside a contained file, such as a PDF attached to the PDF: the file's
   * name, with " > " between nesting levels. `location` then starts with where that file sits.
   */
  attachment?: string;
  /** How much the finding adds to a score, set by the package that made it. */
  weight?: number;
}

/** A finding file-defuse makes itself. */
export interface FileFinding extends DefuseFinding {
  category: FileCategory;
  detail: FileDetail;
}

export enum FileRisk {
  None = 'NONE',
  Low = 'LOW',
  Medium = 'MEDIUM',
  High = 'HIGH',
  Critical = 'CRITICAL',
  /** The file could not be inspected: no package reads its type, or a limit stopped the run. */
  Unknown = 'UNKNOWN',
}

/** The options section, and the package, that reads a type of file. `text` is file-defuse's own text rules. */
export type FileSection = 'pdf' | 'office' | 'image' | 'xml' | 'archive' | 'text';

export interface FileInspection {
  status: 'clean' | 'strippable' | 'rejected';
  /** 0 to 100, null when risk is UNKNOWN. */
  score: number | null;
  risk: FileRisk;
  /** The upload's findings, then those of the files inside it, each with its `weight`. */
  findings: DefuseFinding[];
  /** The section of the package that read the upload. Absent when no package reads its type. */
  package?: FileSection;
}

export interface FileDisarmResult {
  status: 'clean' | 'defused' | 'rejected';
  /** The upload and its score. */
  before: FileInspection;
  /** The output and its remaining score. Absent when rejected. */
  after?: FileInspection;
  /** Findings whose content was removed. */
  removed: DefuseFinding[];
}

/** Random-access input. A buffer, a local file and an S3 ranged GetObject all fit. */
export interface ByteSource {
  size(): Promise<number>;
  read(offset: number, length: number): Promise<Uint8Array>;
  close?(): Promise<void>;
}

/** Append-only output. Never seeks. */
export interface ByteSink {
  write(chunk: Uint8Array): Promise<void>;
  close(): Promise<void>;
  /** Called instead of close() when copying to the sink fails, so a partial output is not taken for a whole one. */
  abort?(error: unknown): Promise<void>;
}

/** What a contained file plugin learns of the run, with nothing format-specific, so any package of the family can make one. */
export interface PluginContext {
  /** The depth of the file itself: 0 for the upload, 1 for a file inside it, and so on, whatever the formats. */
  depth: number;
  /** When a time limit is set, the Date.now() value the whole run must finish by. Nested runs share it. */
  deadline?: number;
}

export interface ContainedFile {
  name?: string;
  /** The MIME type the container declares for the file. */
  declaredType?: string;
  /** From the first bytes. */
  sniffedType?: string;
  /** Decoded size. */
  size: number;
  location: string;
  /** The depth of the file itself: 0 for the upload, 1 for a file inside it, and so on, whatever the formats. */
  depth: number;
  /** Decoded bytes. */
  source: ByteSource;
}

/** What a file plugin did, plus anything it found inside the file. */
export interface ContainedFileResult {
  result: 'scrubbed' | 'passed' | 'removed';
  /** Findings inside the file as it arrived. They go into the report of the file that contains it. */
  findings?: DefuseFinding[];
  /** Findings inside the bytes the plugin kept. They go into the report of the output. */
  outputFindings?: DefuseFinding[];
}

export interface ContainedFilePlugin {
  kind: 'file';
  name: string;
  accepts(file: ContainedFile): boolean | Promise<boolean>;
  /** Writes the bytes to keep. Returning 'removed' drops the file after all. */
  process(file: ContainedFile, sink: ByteSink, context: PluginContext): Promise<'scrubbed' | 'passed' | 'removed' | ContainedFileResult>;
}

/** Limits on the whole upload, counted across every file inside it at any depth. */
export interface FileLimits {
  /** Bytes in the upload. Not enforced unless set. */
  fileSize?: number;
  /** The deepest a file may sit in the upload. The upload is at depth 0 and a file inside it at 1. Default 10. */
  nestingDepth?: number;
  /** Files inside the upload, at every depth, that file-defuse hands to a package. Default 10,000. */
  files?: number;
  /** Decoded sizes of those files added together, in bytes. Default 2 GiB. */
  decodedBytes?: number;
  /** Milliseconds for the upload and every file inside it. Not enforced unless set. */
  timeMs?: number;
}

export interface FileActionOverride {
  category: FileCategory;
  detail?: FileDetail;
  action: FileFindingAction;
}

export interface FileOptions {
  /** Options for @patrickdk77/pdf-defuse, used for the upload and for every PDF inside it. */
  pdf?: PdfOptions;
  /** Options for @patrickdk77/office-defuse, used for the upload and for every Office or OpenDocument file inside it. */
  office?: OfficeOptions;
  /** Options for @patrickdk77/img-defuse, used for the upload and for every image inside it. */
  image?: ImageOptions;
  /**
   * Options for @patrickdk77/xml-defuse, used for the upload and for every HTML, XML, SVG, XSLT or MHT file inside it.
   * Its `name` is the upload's own name, which file-defuse passes for the upload only.
   */
  xml?: XmlOptions;
  /** Options for @patrickdk77/archive-defuse, used for the upload and for every archive or compressed file inside it. */
  archive?: ArchiveOptions;
  /** Options for file-defuse's text rules, used for the upload and for every text file inside it. */
  text?: TextOptions;
  /**
   * The upload's file name. Its extension never chooses a package. It chooses a text subtype, and among the formats
   * of a polyglot. A file inside the upload uses the name its container gives it.
   */
  name?: string;
  /** The upload's declared MIME type, used the way `name` is, after it. */
  declaredType?: string;
  limits?: FileLimits;
  /** Passwords for encrypted files. The package that meets one tries each entry in order. */
  password?: string | string[];
  /** Goes to each package that takes it, unless its section sets its own. */
  stripMetadata?: boolean;
  /** Directory for temporary files. Goes to each package that takes it, unless its section sets its own. */
  tempDir?: string;
  /** Goes to each package that takes it, unless its section sets its own. */
  memoryThreshold?: number;
  /** Changes the action of file-defuse's own findings. A section's overrides cover that package's findings. */
  actionOverrides?: FileActionOverride[];
}
