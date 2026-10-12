import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import type { ByteSink, ByteSource } from './types';

/** How many bytes a spill keeps in memory before it moves to a temporary file, unless the options set another amount. */
export const DEFAULT_MEMORY_THRESHOLD = 8 * 1024 * 1024;

/**
 * A sink that holds what is written to it, in memory up to `threshold` bytes and in a temporary file in `tempDir`
 * past that, so the bytes can be read back before they go on. dispose() deletes the file.
 */
export class Spill implements ByteSink {
  private chunks: Buffer[] = [];
  private handle?: fsp.FileHandle;
  private dir?: string;
  private file?: string;
  size = 0;

  constructor(
    private readonly threshold = DEFAULT_MEMORY_THRESHOLD,
    private readonly tempDir?: string,
  ) {}

  async write(chunk: Uint8Array): Promise<void> {
    if (!chunk.length) return;
    this.size += chunk.length;
    if (!this.file && this.size <= this.threshold) {
      this.chunks.push(Buffer.from(chunk));
      return;
    }
    if (!this.file) {
      this.dir = await fsp.mkdtemp(path.join(this.tempDir ?? os.tmpdir(), 'file-defuse-'));
      this.file = path.join(this.dir, 'spill');
      this.handle = await fsp.open(this.file, 'w+');
      for (const c of this.chunks) await this.writeAll(c);
      this.chunks = [];
    }
    await this.writeAll(chunk);
  }

  private async writeAll(b: Uint8Array): Promise<void> {
    for (let at = 0; at < b.length; ) {
      const { bytesWritten } = await (this.handle as fsp.FileHandle).write(b, at, b.length - at, null);
      at += bytesWritten;
    }
  }

  async close(): Promise<void> {
    // The bytes stay readable until dispose().
  }

  async abort(): Promise<void> {
    await this.dispose();
  }

  /** The bytes written so far, as a source. */
  source(): ByteSource {
    return {
      size: async () => this.size,
      read: async (offset, length) => {
        const n = Math.max(0, Math.min(length, this.size - offset));
        if (!this.handle) {
          const out = Buffer.alloc(n);
          let at = 0;
          let pos = 0;
          for (const c of this.chunks) {
            if (at >= n) break;
            const end = pos + c.length;
            if (end > offset + at) {
              const from = offset + at - pos;
              at += c.copy(out, at, from, Math.min(c.length, from + n - at));
            }
            pos = end;
          }
          return out;
        }
        const out = Buffer.alloc(n);
        for (let at = 0; at < n; ) {
          const { bytesRead } = await this.handle.read(out, at, n - at, offset + at);
          if (bytesRead === 0) break;
          at += bytesRead;
        }
        return out;
      },
    };
  }

  /** Copies everything written to `sink`, without closing it, checking `onChunk` before each piece. */
  async copyTo(sink: ByteSink, onChunk?: () => void): Promise<void> {
    const src = this.source();
    const step = 262144;
    for (let pos = 0; pos < this.size; pos += step) {
      onChunk?.();
      await sink.write(await src.read(pos, Math.min(step, this.size - pos)));
    }
  }

  async dispose(): Promise<void> {
    this.chunks = [];
    const handle = this.handle;
    this.handle = undefined;
    try {
      await handle?.close();
    } finally {
      if (this.dir) await fsp.rm(this.dir, { recursive: true, force: true });
      this.dir = undefined;
      this.file = undefined;
    }
  }
}
