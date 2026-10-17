# Changelog

## 0.2.1 - 2026-10-17

- The JSON reader's flag for a backslash it just read is `escaped`, not `escape`. Security scanners match Node's global names in built code.
- Requires script-defuse 0.3.1, pdf-defuse 0.3.1, office-defuse 0.3.1, archive-defuse 0.2.1, xml-defuse 0.2.1 and img-defuse 0.3.1, which rename theirs the same way. Nothing else changes.

## 0.2.0 - 2026-10-17

- A script or file a plugin answered for scores what the plugin found in it, and nothing else, in every package. A PDF form whose scripts script-defuse keeps scored HIGH through 0.1.4, because pdf-defuse still weighed each kept script at its own 50 or 70. It scores 0 now when nothing else in it weighs anything, as the upload, inside an archive or another document, and as the defused output.
- Reports no longer list a package's own finding next to a plugin's answer, such as JAVASCRIPT/OPEN_ACTION beside JAVASCRIPT/PLUGIN_REMOVED, or EMBEDDED/PACKAGE and MACRO/VBA_PROJECT beside the plugin's.
- Requires script-defuse 0.3.0, pdf-defuse 0.3.0, office-defuse 0.3.0, archive-defuse 0.2.0, xml-defuse 0.2.0 and img-defuse 0.3.0.

## 0.1.4 - 2026-10-16

- PDF scripts go to script-defuse. Every PDF, the upload or one inside it, gets a `formScriptPlugin` of its own after the `pdf` section's `scriptPlugins`, so the AcroForm and XFA scripts that only format, check or calculate form fields stay. 0.1.3 removed every script.
- VBA goes to script-defuse too. Every Office file, the upload or one inside it, gets a `formScriptPlugin` of its own after the `office` section's `scriptPlugins`. A VBA project whose modules only work on their document stays, without its compiled code. 0.1.3 removed every VBA project.
- Excel 97 to 2003 workbooks, PowerPoint 97 to 2003 presentations and .ppa add-ins are written again where 0.1.3 rejected them, as office-defuse 0.2.4 rewrites their records. Forms 2.0 controls stay, and so do the buttons that run a macro of a VBA project that stays.
- Requires pdf-defuse 0.2.4, which keeps XFA forms and tells a script plugin each script's language and form, office-defuse 0.2.4, which shows script plugins VBA and rewrites binary Excel and PowerPoint files, and script-defuse 0.2.0, which reads VBA.

## 0.1.3 - 2026-10-13

- Requires xml-defuse 0.1.3 or later.

## 0.1.2 - 2026-10-12

- Text takes the control characters libmagic's text table allows: bell, backspace, vertical tab and escape. A log with colours, a man page with overstriking and a file with a bell used to get TYPE/NO_PACKAGE, and now get the text rules. C1 controls in Unicode text no longer make a file binary either, and the text rules still remove them.
- TEXT/TERMINAL_ESCAPE removes ANSI escape sequences whole, colours, window titles and OSC 52 clipboard writes among them. TEXT/CONTROL_CHARACTER used to remove the escape alone and leave `[32m` behind.
- TEXT/MARKUP puts a space after the `<` of a tag that runs script once a browser shows the text as HTML, in every subtype but JSON and JavaScript. TEXT/SCRIPT_URL reports a `javascript:` or `vbscript:` URL in plain text, for information.
- JSON and newline-delimited JSON are found by content, as libmagic finds them, and by name and declared type. Their rules remove duplicate and `__proto__` members, escape characters that can end a script element, replace lone surrogate escapes, report integers JavaScript rounds, and reject malformed JSON and nesting past `limits.depth`. A source map loses its script URLs.
- YAML, by name and declared type, is read with the `yaml` package. Tags outside the YAML schemas and `__proto__` keys are removed. Duplicate keys, aliases that expand past `limits.aliasExpansion`, nesting past `limits.depth` and YAML that does not parse are rejected.
- JavaScript, by name, declared type or a `node`, `deno` or `bun` shebang, gets the text rules and TEXT/JAVASCRIPT.
- A style sheet whose name or declared type says CSS goes to xml-defuse, which reads it with the rules a `style` element gets. The upload's declared type now reaches xml-defuse with its name.

## 0.1.1 - 2026-10-11

- Detection asks each package with its own detect function, `detectOffice`, `detectPdf`, `detectImage`, `detectXml` and `detectArchive`, and keeps no copy of their format rules. A package names only what it reads, so routing and reading cannot disagree. A format takes the name and MIME type its package gives it, such as `text-flat-xml` for a flat OpenDocument text, `multipart/related` for MHT and mail, and `text/html` for HTA and SHTML.
- A ZIP archive office-defuse cannot name goes to archive-defuse: an EPUB, a .zipx, a NuGet or StarOffice package, one cut short, and one with data in front. A compound file office-defuse cannot name, an installer included, has no family.
- A PDF without a header goes to pdf-defuse when its name or declared type says PDF and it opens as one. A Brotli stream goes to archive-defuse when its name or declared type says Brotli. XML in EBCDIC goes to xml-defuse, which refuses it.
- A ZIP archive behind other data starts at its first entry, where archive-defuse reads it, instead of at its end record.

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
