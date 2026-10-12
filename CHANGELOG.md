# Changelog

## 0.1.0 - 2026-10-11

First release.

### Library

- `inspectFile` and `disarmFile` take buffers. `inspectFileSource` and `disarmFileSource` take any random-access source and append-only sink. The buffer, file and stream sources and sinks come from pdf-defuse and are exported here too.
- `detectFile` and `detectFileSource` say what a file is: its MIME type, its usual extension, the family whose package reads it, and every signature found with its offset. The router uses the same detection.
- pdf-defuse reads PDFs. office-defuse reads Office Open XML, XPS and OpenDocument packages, flat OpenDocument and Flat OPC files, compound files and RTF. img-defuse reads PNG, JPEG, GIF, WebP, TIFF, BMP, ICO, CUR, JPEG 2000, JPEG XL, PSD and PSB, EMF and WMF. xml-defuse reads HTML, XHTML, SVG, XML, XSLT and MHT. archive-defuse reads ZIP, tar, gzip, bzip2, zstd, cabinet, 7z, xz and .lzma. file-defuse reads text itself.
- Detection also names RAR, ELF and Windows executables, Windows Installer packages, PostScript and SYLK. No package reads them, so they get TYPE/NO_PACKAGE.
- A ZIP archive is split by its central directory into Office Open XML formats, XPS, OpenDocument formats, EPUB and plain archives. A 7z archive is found after the program of a self-extracting archive, as archive-defuse finds one. A compound file is split by its root's streams into .doc, .xls, .ppt, .vsd, .msg, .pub, .mpp and encrypted Office Open XML. Reading a content type inflates at most 8 KiB of an entry.
- A name or declared type never chooses a family. It chooses a text subtype, and among the formats of a polyglot. `name` and `declaredType` give them for the upload, and a container gives them for the files inside it.
- Every file a package finds inside the upload comes back to file-defuse and goes to the package for its format, at any depth. A file no package takes goes by the container's own rule. At the upload, the detected family's package reads a file its plugin would not take, so its refusal names the problem.
- The report comes from the package that read the upload. It holds findings from every level, each marked with the files it sits in, and every finding carries a `weight`.
- An upload no package reads gets TYPE/NO_PACKAGE, which rejects it by default. An `info` override passes it through unchanged.
- `filePlugin(options)` is file-defuse as a contained file plugin, for a container outside it.

### Polyglots

- A file that matches more than one format is handled as the format its name, then its declared type, names, or as the format at its start without such a claim. The package of that format removes the other parts.
- TYPE/POLYGLOT, `strip` with weight 50, reports each other format, with its MIME type, its offset, the format the file was handled as and why. It rejects when the other part sits in data the chosen format needs, or when no package reads the chosen format. It adds nothing to the score when the package reports the same signature itself.
- The router detects every package's output again, and a second format still there rejects the file with PROCESSING/VERIFICATION_FAILED.

### Text

- Text is content that decodes as UTF-8, or as UTF-16 or UTF-32 behind a byte order mark, with no NUL and no control character but tab, carriage return, line feed and form feed. Bytes that are not UTF-8 and hold no other control character count as 8-bit text.
- TEXT/ENCODING, TEXT/CONTROL_CHARACTER and TEXT/BIDI_CONTROL strip what does not decode, control characters and bidirectional controls. TEXT/UNNAMED_ENCODING reports 8-bit text.
- For CSV and TSV, TEXT/FORMULA puts a single quote before each cell a spreadsheet runs as a formula, with pdf-defuse's reader, and TEXT/UNCLOSED_QUOTE rejects a file whose quoted cell never closes.
- For Markdown, LINK/SCRIPT_URL and LINK/DATA_URL neutralize links to `javascript:`, `vbscript:` and `data:` URLs.
- A text file goes through the tree's limits like any other, and its rewrite passes its own check before anything is written. The `text` section sets the rules' overrides, weights, bands and time limit.

### Options

- A section per package, `pdf`, `office`, `image`, `xml`, `archive` and `text`, holds that package's options for the upload and for every file of its format inside it.
- `password` takes one password or a list. `password`, `stripMetadata`, `tempDir` and `memoryThreshold` go to each package that takes them, unless its section sets its own.
- `limits` count across the whole tree: the upload's size, nesting depth, the number of files handed to a package, their decoded bytes, and time as one deadline for every level. `nestingDepth` defaults to 10, `files` to 10,000 and `decodedBytes` to 2 GiB. A file that holds itself stops at the nesting depth.
- Crossing a tree limit rejects the upload with LIMIT/NESTING_DEPTH, LIMIT/FILE_COUNT, LIMIT/DECODED_SIZE, LIMIT/TIME or LIMIT/FILE_SIZE. Inside the tree it throws with the family's `DEFUSE_LIMIT` code.

### Command line

- `file-defuse inspect`, `file-defuse defuse` and `file-defuse detect`, with `-` for stdin and stdout, `--config`, `--strip-metadata`, `--limit` and `--json`. The tool passes the input's base name as `name`. Passwords come from `--password-file`, one per line, or `FILE_DEFUSE_PASSWORD`, never from an argument. Exit codes are the same as pdf-defuse's.
