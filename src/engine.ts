import { bufferSink, bufferSource } from '@patrickdk77/pdf-defuse';
import { stopsTree, Tree } from './tree';
import {
  type ByteSink,
  type ByteSource,
  FileCategory as C,
  type ContainedFile,
  type ContainedFilePlugin,
  FileDetail as D,
  type FileDisarmResult,
  type FileFinding,
  type FileInspection,
  type FileOptions,
} from './types';

async function closeSource(source: ByteSource): Promise<void> {
  try {
    await source.close?.();
  } catch {
    // The run's result stands.
  }
}

/** An error at the upload: a limit rejects the file, and an I/O error fails the run with its cause. */
function atUpload(tree: Tree, e: unknown): FileInspection {
  const code = stopsTree(e);
  if (code === 'DEFUSE_LIMIT') return Tree.rejected([tree.limitFinding(e)]);
  if (code === 'DEFUSE_IO') throw (e as { cause?: unknown }).cause ?? e;
  throw e;
}

/**
 * Copies the whole source to the sink, checking the deadline before each chunk. On failure it aborts the sink instead
 * of closing it, so a partial copy does not look whole.
 */
async function deliver(source: ByteSource, sink: ByteSink, tree: Tree): Promise<void> {
  try {
    const total = await source.size();
    const chunk = 262144;
    for (let pos = 0; pos < total; pos += chunk) {
      tree.checkTime();
      const want = Math.min(chunk, total - pos);
      const b = await source.read(pos, want);
      if (b.length !== want) throw Object.assign(new Error(`The source returned ${b.length} bytes at offset ${pos} where ${want} were expected`), { code: 'EIO' });
      await sink.write(b);
    }
  } catch (e) {
    try {
      await sink.abort?.(e);
    } catch {
      // The copy's error is the one to report.
    }
    throw e;
  }
  await sink.close();
}

/** The upload as a contained file, with the name and declared type the options give it. */
const upload = (source: ByteSource, size: number, options: FileOptions): ContainedFile => ({ size, location: 'upload', depth: 0, source, name: options.name, declaredType: options.declaredType });

/** Inspects any file without changing it, with every file inside it. The source is closed when the run ends. */
export async function inspectFileSource(source: ByteSource, options: FileOptions = {}): Promise<FileInspection> {
  const tree = new Tree(options, 0);
  try {
    const size = await source.size();
    const fileSize = options.limits?.fileSize;
    if (fileSize !== undefined && size > fileSize) return Tree.rejected([tree.factory.make(C.Limit, D.FileSize, { size })]);
    const picked = await tree.pickUpload(upload(source, size, options));
    if (!picked.reader) return tree.unknownInspection(picked.detection);
    const hints = { name: options.name, declaredType: options.declaredType };
    return tree.wrap(picked.reader, await picked.reader.inspect(picked.file.source, tree.remaining(), hints), picked.detection);
  } catch (e) {
    return atUpload(tree, e);
  } finally {
    await closeSource(source);
  }
}

/**
 * Writes a defused copy of any file to `sink`, with every file inside it defused too. The package that reads the
 * file writes its output to a temporary copy, and the router detects the copy again before any of it reaches the
 * sink: a second format still there rejects the upload with PROCESSING/VERIFICATION_FAILED. The source is closed when
 * the run ends.
 */
export async function disarmFileSource(source: ByteSource, sink: ByteSink, options: FileOptions = {}): Promise<FileDisarmResult> {
  const tree = new Tree(options, 0);
  try {
    const size = await source.size();
    const fileSize = options.limits?.fileSize;
    if (fileSize !== undefined && size > fileSize) return Tree.refused(Tree.rejected([tree.factory.make(C.Limit, D.FileSize, { size })]));
    const picked = await tree.pickUpload(upload(source, size, options));
    if (!picked.reader) {
      const before = tree.unknownInspection(picked.detection);
      if (before.status === 'rejected') return Tree.refused(before);
      // The caller keeps files no package reads, so the bytes go through unchanged.
      await deliver(source, sink, tree);
      return { status: 'clean', before, after: before, removed: [] };
    }
    const hints = { name: options.name, declaredType: options.declaredType };
    const spill = tree.spill(picked.reader);
    try {
      const r = await picked.reader.disarm(picked.file.source, spill, tree.remaining(), hints);
      const before = tree.wrap(picked.reader, r.before, picked.detection);
      if (r.status === 'rejected' || tree.stopped || before.status === 'rejected') return Tree.refused(before);
      const poly = before.findings.filter(f => f.category === C.Type && f.detail === D.Polyglot && f.attachment === undefined) as FileFinding[];
      const left = await tree.leftover(picked.detection, spill.source(), spill.size, hints, poly);
      if (left.length) {
        before.findings.push(tree.verificationFailed(left));
        return Tree.refused({ ...before, status: 'rejected' });
      }
      await deliver(spill.source(), sink, tree);
      const stripped = poly.filter(f => f.action === 'strip');
      const status = r.status === 'clean' && stripped.length ? 'defused' : r.status;
      return { status, before, after: r.after && tree.wrap(picked.reader, r.after), removed: [...stripped, ...r.removed] };
    } finally {
      await spill.dispose();
    }
  } catch (e) {
    return Tree.refused(atUpload(tree, e));
  } finally {
    await closeSource(source);
  }
}

/** Inspects the bytes of any file. */
export async function inspectFile(bytes: Uint8Array, options: FileOptions = {}): Promise<FileInspection> {
  return inspectFileSource(bufferSource(bytes), options);
}

/** Defuses the bytes of any file. `bytes` holds the output unless the file was rejected. */
export async function disarmFile(bytes: Uint8Array, options: FileOptions = {}): Promise<FileDisarmResult & { bytes?: Uint8Array }> {
  const sink = bufferSink();
  const result = await disarmFileSource(bufferSource(bytes), sink, options);
  return result.status === 'rejected' ? result : { ...result, bytes: sink.result() };
}

/**
 * file-defuse as a contained file plugin, for a container that is not part of it. It accepts any file a package of the
 * family reads and routes it like an upload, with `options`. The file it gets is the root of a tree of its own: the
 * tree limits count the files inside it, and its deadline is the earlier of the context's and `limits.timeMs`.
 *
 * At depth 0 it treats the file as the upload: a limit gives a LIMIT finding and 'removed', and the source is closed
 * when the run ends. Deeper, a tree limit throws with the DEFUSE_LIMIT code, for the container to pass up.
 */
export function filePlugin(options: FileOptions = {}): ContainedFilePlugin {
  return {
    kind: 'file',
    name: 'file-defuse',
    accepts: file => new Tree(options, file.depth).accepts(file),
    async process(file, sink, context) {
      const tree = new Tree(options, context.depth, context.deadline);
      const fileSize = options.limits?.fileSize;
      // Like a package's own file size limit, this one has no code: the file goes and the run goes on.
      if (fileSize !== undefined && file.size > fileSize) return { result: 'removed', findings: [tree.factory.make(C.Limit, D.FileSize, { size: file.size })] };
      if (context.depth > 0) return tree.process(file, sink, context);
      try {
        const r = await tree.process(file, sink, context);
        r.findings ??= [];
        if (tree.settle(r.findings)) return { result: 'removed', findings: r.findings };
        return r;
      } catch (e) {
        return { result: 'removed', findings: atUpload(tree, e).findings };
      } finally {
        await closeSource(file.source);
      }
    },
  };
}
