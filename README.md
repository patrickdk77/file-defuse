# file-defuse

Sanitize uploads with the defuse family of packages. file-defuse detects what a file is from its content, hands it to the package that reads that format, and routes every file found inside it back through itself. A PDF attached to a .docx attached to a PDF goes through the same router at each level. Text goes to file-defuse's own text rules. Limits count across the whole tree of files: the upload's size, how deep files sit, how many files there are, how many bytes they decode to, and how long the run takes.

```
npm install @patrickdk77/file-defuse
```

Node 18 or later.

| Section | Package | Reads |
|---|---|---|
| `pdf` | [@patrickdk77/pdf-defuse](https://www.npmjs.com/package/@patrickdk77/pdf-defuse) | PDF |
| `office` | [@patrickdk77/office-defuse](https://www.npmjs.com/package/@patrickdk77/office-defuse) | Office Open XML, XPS and OpenDocument packages, flat OpenDocument and Flat OPC files, compound files such as .doc, .xls, .ppt and .msg, and RTF |
| `image` | [@patrickdk77/img-defuse](https://www.npmjs.com/package/@patrickdk77/img-defuse) | PNG, JPEG, GIF, WebP, TIFF, BMP, ICO, CUR, JPEG 2000, JPEG XL, PSD and PSB, EMF and WMF |
| `xml` | [@patrickdk77/xml-defuse](https://www.npmjs.com/package/@patrickdk77/xml-defuse) | HTML, XHTML, SVG, XML, XSLT and MHT |
| `archive` | [@patrickdk77/archive-defuse](https://www.npmjs.com/package/@patrickdk77/archive-defuse) | ZIP, tar, gzip, bzip2, zstd, cabinet, 7z, xz and .lzma |
| `text` | file-defuse itself | Text, with rules for CSV, TSV and Markdown |

Detection also names RAR, ELF and Windows executables, Windows Installer packages, PostScript and SYLK, which no package reads. A file of those formats gets TYPE/NO_PACKAGE, described below.

## Quick start

```js
const { detectFile, inspectFile, disarmFile } = require('@patrickdk77/file-defuse');

const d = await detectFile(bytes, { name: 'upload.csv' });
d.family;        // 'text'
d.mimeType;      // 'text/csv'

const report = await inspectFile(bytes, { name: 'upload.csv', password: ['first password', 'second password'] });
report.status;   // 'clean', 'strippable' or 'rejected'
report.risk;     // 'NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL' or 'UNKNOWN'
report.score;    // 0 to 100, null when the file could not be inspected
report.package;  // 'pdf', 'office', 'image', 'xml', 'archive' or 'text', or undefined when no package reads the file
report.findings; // [{ category, detail, description, action, location, data, attachment, weight }]

const result = await disarmFile(bytes, { name: 'upload.csv' });
if (result.status !== 'rejected') save(result.bytes);
```

ES modules work too: `import { disarmFile } from '@patrickdk77/file-defuse'`.

### Files and S3

`inspectFileSource(source, options)`, `disarmFileSource(source, sink, options)` and `detectFileSource(source, hints)` take a source with `size()` and `read(offset, length)`, and the disarm function a sink with `write(chunk)` and `close()`, the same shapes pdf-defuse uses. `bufferSource`, `bufferSink`, `fileSource`, `fileSink` and `writableSink` come from pdf-defuse and are exported here as well. pdf-defuse's README shows a source and sink over S3.

All three functions close the source when they end. A rejected upload leaves the sink untouched. Nothing reaches the sink before the package's output has passed the package's own check and the router's check for a second format.

## Detection

`detectFile(bytes, hints)` and `detectFileSource(source, hints)` say what file-defuse makes of a file. The router calls the same code, so the result is what routing does. `hints` is `{ name, declaredType }`, both optional.

file-defuse does not keep its own copy of the packages' format rules. It reads the first 64 KiB once and asks each package with its own detect function, `detectOffice`, `detectPdf`, `detectImage`, `detectXml` and `detectArchive`, in that order. Each package names only the formats it reads, by the code its inspection uses, and says where in the file the format starts. Routing and reading cannot disagree.

```
$ file-defuse detect test/fixtures/jpeg-zip.bin
{
  "mimeType": "image/jpeg",
  "extension": "jpg",
  "signatures": [
    { "mimeType": "image/jpeg", "extension": "jpg", "family": "image", "offset": 0 },
    { "mimeType": "application/zip", "extension": "zip", "family": "archive", "offset": 153 }
  ],
  "sniffedType": "image/jpeg",
  "family": "image",
  "chosenBy": "firstSignature"
}
```

| Field | Holds |
|---|---|
| `mimeType`, `extension` | The format the file is handled as. `application/octet-stream` and `''` when nothing matched |
| `family` | `pdf`, `office`, `image`, `xml`, `archive` or `text`. Absent for a format no family package reads, such as RAR or an executable |
| `signatures` | Every format a package claims, with `family`, the `offset` where it starts, and `heuristic` when the claim rests on more than the content. A format no package reads at the start of the file is listed too, without a family. More than one makes the file a polyglot |
| `chosenBy` | For a polyglot, what chose the format: `name`, `declaredType` or `firstSignature` |
| `heuristic` | Set when the chosen format rests on a heuristic, saying what it rests on |
| `encoding` | For text: `utf-8`, `utf-16le`, `utf-16be`, `utf-32le`, `utf-32be`, or `8-bit` for text that is not UTF-8 and names no encoding |
| `textTypes` | For text, the subtypes the name and declared type give |
| `sniffedType` | The type the router gives the package as `ContainedFile.sniffedType`, the container format, such as `application/zip` for every Office Open XML package |

### Formats

Each package claims the formats its own README lists:

| Package | Claims |
|---|---|
| office-defuse | Office Open XML, XPS and OpenDocument packages whose format it can name, flat OpenDocument and Flat OPC files, compound files whose root names an Office format, encrypted Office Open XML packages, and RTF |
| pdf-defuse | A file with a PDF header in its first 1024 bytes, or one without a header whose name or declared type says PDF and which opens as a PDF |
| img-defuse | The image formats it reads, by their first 64 bytes |
| xml-defuse | HTML, XHTML, SVG, XSLT, XML and MHT, by the markup or MIME headers at the start, and XML in EBCDIC, which it refuses |
| archive-defuse | ZIP, tar, gzip, bzip2, zstd, cabinet, 7z, xz and .lzma files, a ZIP archive behind other data, a 7z archive after a program, and Brotli when the name or declared type says Brotli |

A package claims a file it can name even when the file is damaged further on, and its inspection then rejects the file. It claims nothing it cannot name. archive-defuse reads every ZIP archive, so its claim gives way when office-defuse names the same bytes. A ZIP archive office-defuse cannot name is archive-defuse's: a plain archive, an EPUB, a NuGet or StarOffice package, a package cut short, and a package with data in front, which office-defuse refuses.

file-defuse itself names a few formats no package reads, at the start of a file, so a report can say what the file is. They are RAR, ELF and Windows executables, PostScript, SYLK, and a compound file office-defuse cannot name, such as an installer. They have no family. Text, which no package claims, is the last guess.

**Text.** Content is text when it decodes cleanly, as UTF-8 or as UTF-16 or UTF-32 behind a byte order mark, and holds no NUL and no control character but tab, carriage return, line feed and form feed. Bytes that are not UTF-8, name no encoding, and hold no C0 control but those four and no DEL are text in an 8-bit encoding, which is a guess, since every 8-bit encoding fits. An empty file is text.

### Claims

A name and a declared type never overrule what the content shows. They do three things.

- They choose a text subtype: `.csv` or `text/csv`, `.tsv`, `.tab` or `text/tab-separated-values`, `.md`, `.markdown` or `text/markdown`, and `.txt` or `text/plain`. Both are read, the name first, and each subtype adds its rules. None removes a rule.
- They choose among the formats of a polyglot, described below.
- They let a package claim a format the content cannot show on its own. pdf-defuse claims a file without a PDF header when the claim says PDF and the file opens as one. archive-defuse claims a Brotli stream only when the claim says Brotli.

For the upload they come from the `name` and `declaredType` options. A file inside the upload uses what its container gives: the attachment's name and subtype in a PDF, the part name and content type in an Office package. img-defuse declares every image inside an image as `image/jpeg`.

### Heuristics and weak spots

- An old tar header has no magic, only a checksum.
- lzma-alone has no magic. archive-defuse uses liblzma's test, properties with lc + lp at most 4, a dictionary of 2^n or 2^n + 2^(n-1) bytes or 0, a size that is unknown or below 256 GiB, and a first byte of 0 in the range coder data, and tries it after every signature. Fourteen zero bytes pass it.
- 8-bit text is a guess, since every 8-bit encoding fits.
- Brotli has no signature, and a one-byte file can decode as a Brotli stream. archive-defuse claims Brotli only when the name or declared type says Brotli and the whole file decodes.
- A self-extracting archive starts with an executable, so file-defuse names the executable. archive-defuse finds a 7z archive after it within the first MiB, and a ZIP archive from its end record, and the claim chooses between them. A RAR archive after it is not looked for.
- A PDF whose header is missing, damaged or past the first 1024 bytes is a PDF only when its name or declared type says so and pdf-defuse opens it. Text with a PDF after it is text unless it claims to be a PDF.
- XML in UTF-32 without a byte order mark is a format no package reads.

## Routing

The router detects the file and calls the package that claims it, with `sniffedType` set to the container type. Each package's plugin takes exactly what its detect function claims, so the package that claims a file reads it, at the upload and inside a container. A file no package claims is not accepted, and the container's own rule decides it. That is EMBEDDED_FILE/NO_PLUGIN in pdf-defuse, the part's own finding in office-defuse, such as EMBEDDED/PACKAGE, EMBEDDED_IMAGE/NO_PLUGIN in img-defuse, EMBEDDED/NO_PLUGIN in xml-defuse and ENTRY/NO_PLUGIN in archive-defuse. Each removes the file by default.

The package that claims a file names the problem when it cannot read it. A .docx cut short is a ZIP archive to archive-defuse, which rejects it as unparseable, and a JPEG 2000 file of brand JPM gets img-defuse's FORMAT/UNSUPPORTED. An upload no package claims gets TYPE/NO_PACKAGE, described below.

Each package gets its section of the options, with file-defuse's router added after any file plugins the section lists. A package hands each file it finds to its plugins in order, so the caller's plugins see a file first and file-defuse sees the files they leave.

- pdf-defuse hands over attached files.
- office-defuse hands over the OLE parts, embedded packages and pictures of an Office Open XML or XPS package, the entries of an OpenDocument package that are not read as XML, the pictures and OLE objects a flat OpenDocument file holds as base64, the parts of a Flat OPC file, each embedded object of a compound file, as the file a Packager object holds or as a compound file of its own, Outlook attachments held in a stream, an Outlook message's RTF and HTML bodies, and an RTF object's data and each picture that is a whole file.
- img-defuse hands over EXIF, JFXX and Photoshop thumbnails, the secondary images of an MPF index, the thumbnails in a JPEG 2000 file's EXIF and Photoshop boxes, and a JPEG XL gain map.
- xml-defuse hands over data: URLs that load, the page in an `iframe` `srcdoc`, MHT parts that are not markup or CSS, and the base64 files of Word 2003 XML and Visio 2003 XML.
- archive-defuse hands over every file entry. A .tar.gz goes to archive-defuse as gzip, and the tar inside it comes back to the router and goes to archive-defuse again.

An inspection runs the packages on every file inside the upload too, because each package hands files to its plugins while it inspects.

## Polyglots

A polyglot is a file whose content matches more than one format the family detects, such as a JPEG with a ZIP archive after its end marker, or a PDF that is also a ZIP archive.

1. The claim chooses the format the file is handled as: the name's extension first, then the declared type. A claim chooses only among the formats the content matches. A file named .jpg whose content is a PDF and nothing else is not a polyglot, and routes as a PDF.
2. With no claim, or a claim that names none of the formats, the signature at the start wins. Without one at the start, the first signature wins.
3. The package of the chosen format handles the file, and its rewrite removes the other formats' parts.
4. The router adds TYPE/POLYGLOT for each other format, `strip` with weight 50. Its `data` has the other format's MIME type in `type`, the `offset` of its signature, the format the file was handled as in `handledAs`, and the `reason`, `name`, `declaredType` or `firstSignature`. Its description says the same in words, and what happens to the other part.
5. When the other part sits in data the chosen format needs, it cannot go without breaking the file, and the finding is `reject`. The router knows this when the package says so in its own POLYGLOT finding, such as img-defuse's POLYGLOT/IMAGE_DATA. When no package reads the chosen format, nothing can remove the other part, and the finding is `reject` as well.
6. After the package writes its output, the router detects the output again. A second format still in it rejects the file with PROCESSING/VERIFICATION_FAILED, whose `data.reasons` names it, whichever package wrote it. A rewrite can also make one. When xml-defuse removes a script, the text after it moves forward, and a `%PDF-` in that text can land in the first 1024 bytes, where PDF readers look for a header.

A package's own polyglot findings stay in the report. When one names an offset inside the part the router's finding names, from its start up to the next format's, the router's weighs 0, so one part never adds to the score twice. img-defuse names a ZIP archive at its end record, and the router at its first entry. Otherwise its weight adds to the package's score the way the family adds a kind of finding: the highest weight in full and a quarter of each other kind's.

An `info` override on TYPE/POLYGLOT keeps the other part, and the output check does not hold it against the file.

```
$ file-defuse inspect test/fixtures/jpeg-zip.bin
inspection: strippable, risk HIGH (score 73), read by image
  strip  TYPE/POLYGLOT [offset 153]: The file is also application/zip, at offset 153. It is handled as image/jpeg, chosen by the signature at its start, and the application/zip part is removed
  info   METADATA/COMMENT [COM segment at 2]: A comment
  strip  STRUCTURE/TRAILING_DATA [offset 153]: Data after the end of the image
  strip  POLYGLOT/ZIP [offset 279]: A ZIP directory sits where ZIP readers look for one, so the file also opens as an archive
```

## Text

Text goes to file-defuse's own rules, in the `text` section. Each rule decides its own action. A rule's rewrite applies only while its finding is `strip`.

| Finding | Action | Weight | When |
|---|---|---|---|
| TEXT/ENCODING | `strip` | 10 | Bytes that do not decode in the encoding a byte order mark names. The rewrite writes U+FFFD in their place |
| TEXT/UNNAMED_ENCODING | `info` | 0 | The text is not UTF-8 and has no byte order mark, so it is read as 8-bit text. The rewrite keeps its bytes |
| TEXT/CONTROL_CHARACTER | `strip` | 10 | A C0 control, DEL or a C1 control, other than tab, line feed, form feed and carriage return. The rewrite removes it |
| TEXT/BIDI_CONTROL | `strip` | 30 | U+202A to U+202E or U+2066 to U+2069, which can make text show in another order than it reads. The rewrite removes it |
| TEXT/FORMULA | `strip` | 50 | CSV and TSV. A cell that starts with `=`, `+`, `-`, `@`, tab or carriage return, which a spreadsheet runs as a formula. A plain number and a lone sign are left alone. The rewrite puts a single quote at the start of the cell, inside its quotes when it has them |
| TEXT/UNCLOSED_QUOTE | `reject` | 0 | CSV and TSV. A quoted cell that never closes, so the rest of the file reads as one cell. The file has no score |
| LINK/SCRIPT_URL | `strip` | 50 | Markdown. A link to a `javascript:` or `vbscript:` URL. The rewrite turns the scheme into `#` |
| LINK/DATA_URL | `strip` | 60 | Markdown. A link to a `data:` URL. The rewrite turns the scheme into `#` |

Detection checks the first 64 KiB, so a control character or a byte that does not decode there makes the file something other than text. The control and encoding rules find what comes after.

The CSV reader is pdf-defuse's. Quoting follows RFC 4180, a stray quote is text, and a TSV file is read with the same quoting, as pdf-defuse's TSV plugin reads one. The Markdown rule reads inline links and images, reference definitions, a destination on the line after its `](` or label, and autolinks. It skips fenced code blocks and code spans. It reads a scheme the way a browser does, after backslash escapes and character references, without tabs and line breaks, and without leading spaces and controls.

In 8-bit text, the bytes 0x80 to 0x9F stay, since Windows-1252 prints them. A reader that takes the file as ISO-8859-1 sees C1 controls there. The bidirectional controls and C1 controls written as UTF-8 are found and removed even in 8-bit text, since a reader may take the file for UTF-8.

`disarmFile` writes the rewrite to a temporary copy, kept in memory up to `memoryThreshold` and in `tempDir` past it, then inspects the copy with the same subtypes. A copy that still holds a finding that is not `info` is not written, and the file is rejected with PROCESSING/VERIFICATION_FAILED. A clean file comes out byte for byte.

The `text` section takes `actionOverrides` for TEXT, LINK and PROCESSING findings, `scoreWeights`, `scoreBands`, `limits.timeMs`, `tempDir` and `memoryThreshold`. The score is the family's: the highest weight in full and a quarter of each other kind's, capped at 100.

## The report

`status`, `score` and `risk` come from the package that read the upload, and `package` names its section. `findings` holds the router's polyglot findings first, then the upload's own findings, then those of the files inside it at every depth. Each package adds them as it adds any plugin's findings. `attachment` holds the names of the files the finding sits in, outermost first, joined with ` > `, and `location` starts with where that file sits. A `reject` inside a file becomes `strip` in the outer report, because the file goes and the upload stays.

`nested.pdf` in the fixtures is four PDFs deep, with a script in the innermost. The command-line tool prints each finding's action, kind and location:

```
$ file-defuse inspect test/fixtures/nested.pdf
inspection: strippable, risk HIGH (score 70), read by pdf
  info   EMBEDDED_FILE/PLUGIN_SCRUBBED [attachment "level1.pdf"]: Attached file cleaned and kept by plugin file-defuse
  info   EMBEDDED_FILE/PLUGIN_SCRUBBED [attachment "level1.pdf" > attachment "level2.pdf"]: Attached file cleaned and kept by plugin file-defuse
  info   EMBEDDED_FILE/PLUGIN_SCRUBBED [attachment "level1.pdf" > attachment "level2.pdf" > attachment "level3.pdf"]: Attached file cleaned and kept by plugin file-defuse
  info   EMBEDDED_FILE/PLUGIN_SCRUBBED [attachment "level1.pdf" > attachment "level2.pdf" > attachment "level3.pdf" > attachment "level4.pdf"]: Attached file cleaned and kept by plugin file-defuse
  strip  JAVASCRIPT/OPEN_ACTION [attachment "level1.pdf" > attachment "level2.pdf" > attachment "level3.pdf" > attachment "level4.pdf" > document open action]: JavaScript runs when the PDF opens
```

The script's finding has `attachment` set to `level1.pdf > level2.pdf > level3.pdf > level4.pdf`. The path crosses packages the same way. `embedded.docx` embeds a PDF that has a .docx attached, which embeds a PDF with a script, and that script's finding has `attachment` set to `word/embeddings/report.pdf > inner.docx > word/embeddings/final.pdf`. In `picture.docx`, img-defuse's STRUCTURE/TRAILING_DATA for the picture has `attachment` set to `word/media/image1.png`, and the rewritten .docx holds img-defuse's copy of the picture.

Every finding has a `weight`, the amount it adds to a score. A finding of the upload's own gets the weight its package gives that kind, after the section's `scoreWeights`. A finding from inside a file keeps the weight the package that made it gave it, as `pdfPlugin` does in pdf-defuse. A container in another package can score them all from that.

## A file no package reads

An upload whose format no package reads gets TYPE/NO_PACKAGE. Its `data.sniffed` holds the MIME type detection gave. The default action is `reject`, and the report has a null score and the UNKNOWN risk, since nothing inspected the file. That follows pdf-defuse, which removes an attached file no plugin takes and rejects an upload it cannot read.

`actionOverrides` changes it:

```js
await disarmFile(bytes, { actionOverrides: [{ category: 'TYPE', detail: 'NO_PACKAGE', action: 'info' }] });
```

With `info` the status is `clean` and the risk stays UNKNOWN. `disarmFile` then copies the bytes to the output unchanged. A `strip` override rejects the upload, because stripping the whole file would leave nothing to write. A polyglot whose chosen format no package reads is still rejected, since nothing can remove its other part, unless TYPE/POLYGLOT is `info` too.

The override applies to the upload only. A file inside the upload that no package reads goes by the container's rule, as described under Routing.

## Options

| Option | Default | Purpose |
|---|---|---|
| `pdf` | none | pdf-defuse's options, for the upload and for every PDF inside it at any depth |
| `office` | none | office-defuse's options, for the upload and for every Office file inside it at any depth |
| `image` | none | img-defuse's options, for the upload and for every image inside it at any depth |
| `xml` | none | xml-defuse's options, for the upload and for every HTML, XML, SVG or MHT file inside it at any depth |
| `archive` | none | archive-defuse's options, for the upload and for every archive or compressed file inside it at any depth |
| `text` | none | The text rules' options, for the upload and for every text file inside it at any depth. See Text |
| `name` | none | The upload's file name. See Claims |
| `declaredType` | none | The upload's declared MIME type. See Claims |
| `limits` | see Limits | `fileSize`, `nestingDepth`, `files`, `decodedBytes` and `timeMs`, counted across the whole tree |
| `password` | none | One password or a list. See Passwords |
| `stripMetadata` | none | Goes to each package that takes it |
| `tempDir` | none | Goes to each package that takes it, and to the router's copy of an output |
| `memoryThreshold` | none | Goes to each package that takes it, and to the router's copy of an output |
| `actionOverrides` | none | Changes the action of file-defuse's own findings, TYPE, LIMIT and PROCESSING |

`password`, `stripMetadata`, `tempDir` and `memoryThreshold` go to each package that takes them, unless that package's section sets its own. pdf-defuse and archive-defuse take all four. office-defuse takes `password`, `tempDir` and `memoryThreshold`. img-defuse and xml-defuse take `stripMetadata`, `tempDir` and `memoryThreshold`, and the text rules take `tempDir` and `memoryThreshold`. xml-defuse also gets the upload's `name`, for its `.hta` check. A section's own `actionOverrides`, `scoreWeights` and `limits` apply to that package's runs, for the upload and for every file of its format inside it.

The router keeps a package's output in a temporary copy, to check it for a second format before it goes on. The copy keeps to the `memoryThreshold` and `tempDir` the package uses, its section's or the top-level ones, and to 8 MiB and the system's temporary directory when neither sets them.

`images.pdf` in the fixtures has an Info dictionary and two attached images with metadata. With `stripMetadata: true`, pdf-defuse removes the Info dictionary and img-defuse removes the images' metadata. Adding `image: { stripMetadata: false }` keeps the images' metadata, and pdf-defuse still removes the Info dictionary.

```js
const { csvPlugin } = require('@patrickdk77/pdf-defuse');

await disarmFile(bytes, {
  name: 'report.pdf',
  password: process.env.UPLOAD_PASSWORD,
  stripMetadata: true,
  limits: { nestingDepth: 5, timeMs: 60_000 },
  pdf: {
    actionOverrides: [{ category: 'JAVASCRIPT', action: 'reject' }],
    filePlugins: [csvPlugin()],
  },
});
```

### Passwords

`password` takes one password or a list, because the files in one upload can have different passwords. A ZIP archive can have one and a PDF inside it another. Each package tries every entry in order on each encrypted file it meets. pdf-defuse tries each as the user password and then as the owner password, and the empty password after the list. office-defuse tries each on an encrypted Office Open XML package, an .xls workbook, a Word 97 to 2003 document and a PowerPoint 97 to 2003 presentation, and after the list the password the application tries on its own: VelvetSweatshop for Excel and Office Open XML, and PowerPoint's default for PowerPoint. Word has none. archive-defuse tries each on every encrypted ZIP entry, 7z folder and 7z header, and the empty password after the list.

`passwords.docx` in the fixtures is a .docx encrypted with one password that embeds a PDF encrypted with another. With both passwords, in either order, both files open. With the .docx password alone, the PDF goes, and its ENCRYPTED/PASSWORD_REQUIRED shows in the report as a `strip` inside `word/embeddings/secret.pdf`. `passwords.pdf` does the same with two PDFs.

### Limits

| Limit | Default | Counts |
|---|---|---|
| `fileSize` | none | Bytes in the upload |
| `nestingDepth` | 10 | The deepest a file may sit. The upload is at depth 0 and a file inside it at 1, whatever the formats |
| `files` | 10,000 | Files inside the upload, at every depth, that file-defuse hands to a package |
| `decodedBytes` | 2 GiB | The decoded sizes of those files added together |
| `timeMs` | none | Milliseconds for the upload and every file inside it |

A package's own limits cover one run of that package, and each file inside the upload starts a new run. A PDF that attaches a thousand PDFs gets a thousand runs, each with the section's full limits. file-defuse's limits count across all of them. The upload is counted in neither `files` nor `decodedBytes`. A file the container decides without file-defuse, such as an attached executable pdf-defuse removes, is not counted either. A text file is counted like any other.

A file can hold itself. `loop.pdf` in the fixtures is a PDF whose attached file inflates to the same PDF, so every level finds the same attachment again. Without `nestingDepth` or `timeMs`, nothing would end that run, so `nestingDepth` has a default.

`timeMs` becomes one deadline when the run starts. Every package call gets that deadline in its context, and the package that reads the upload gets what is left of it as its own `limits.timeMs`, or its section's `timeMs` when that is shorter.

A tree limit throws an error with `code: 'DEFUSE_LIMIT'` from inside the tree, and every package of the family passes it up to the upload. The upload is then rejected with a null score, the UNKNOWN risk and file-defuse's LIMIT finding: LIMIT/NESTING_DEPTH, LIMIT/FILE_COUNT, LIMIT/DECODED_SIZE or LIMIT/TIME. The packages know only the time and nesting limits and report any other as LIMIT/TIME, so file-defuse puts its own finding in place of the package's. Findings made before the limit stopped the run stay in the report. `fileSize` is checked before anything is read, and gives LIMIT/FILE_SIZE with the upload's `size`.

An I/O error fails the run instead of giving a verdict. `inspectFileSource` and `disarmFileSource` throw it.

## Inside another container

`filePlugin(options)` returns file-defuse as a contained file plugin, for a container that is not part of it, such as a pdf-defuse run of your own:

```js
const { inspectPdf } = require('@patrickdk77/pdf-defuse');
const { filePlugin } = require('@patrickdk77/file-defuse');

await inspectPdf(bytes, { filePlugins: [filePlugin({ password: ['a', 'b'] })] });
```

It accepts any file a package reads, by content, and routes it like an upload with `options`, the file's name and declared type acting as its claim. Each file it gets starts a tree of its own. The tree limits count the files inside that file, and its deadline is the earlier of the context's `deadline` and its own `limits.timeMs`. `nestingDepth` counts from the real upload, since the context gives the file's depth.

At depth 0 the plugin treats the file as the upload. A limit gives a LIMIT finding and the result `removed`, and the plugin closes the source when it is done. At depth 1 or more, a tree limit throws with the `DEFUSE_LIMIT` code and `limit` set to `'nesting'`, `'time'`, `'files'` or `'decodedBytes'`, for the container to pass up. An I/O error inside a file comes up with the `DEFUSE_IO` code. A file over `limits.fileSize` is removed with LIMIT/FILE_SIZE and no code, the way pdf-defuse removes a PDF over its own size limit.

## Command line

```
file-defuse inspect <file> [options]
file-defuse defuse <in> <out> [options]
file-defuse detect <file> [options]

--password-file <path>   read passwords from a file, one per line; FILE_DEFUSE_PASSWORD holds one
--config <module>        load a whole options object, repeatable; the other options apply on top
--strip-metadata
--limit <name>=<value>   fileSize, nestingDepth, files, decodedBytes, timeMs; sizes accept kb, mb, gb
--json                   print the result as JSON
```

`detect` prints the detection as JSON. The tool passes the input's base name as `name`, so a .csv gets the CSV rule, unless a `--config` module sets `name`. Input from stdin has no name.

Use `-` for stdin or stdout. The tool copies stdin to a temporary file in `tempDir`, which a `--config` module can set. The copy stops one byte past `limits.fileSize`, and the run then rejects the upload without reading the rest. The copy counts toward `limits.timeMs`, and stdin still open at the time limit fails the run with LIMIT/TIME. `inspect` prints its report to stdout. `defuse` does too, unless the output goes to stdout, and then the report goes to stderr. `defuse` refuses an output that is its input under any name, because a failed write deletes the partial output.

`--password-file` reads one password per line. The tool drops a carriage return at the end of a line and skips blank lines, since every package tries the empty password anyway. Spaces belong to the password. `FILE_DEFUSE_PASSWORD` holds one password, and a line break in it is part of that password. `--password-file` replaces it, and either one replaces a `password` that a `--config` module sets. There is no password flag, because other users can read command-line arguments from the process list. An unknown option shows in the error without the text after its `=`, in case that text is a password typed in the wrong place.

A `--config` module's default export is the options object. For CommonJS that is `module.exports`. Several `--config` modules combine. Their limits merge, and for any other option, a whole section included, the later module wins. `--limit` and `--strip-metadata` apply on top, wherever they sit on the command line.

`nestingDepth`, `files` and `timeMs` take whole numbers. `fileSize` and `decodedBytes` take sizes. Any other value is a usage error.

The text report shows each control character as an escape such as `\u001b`, since a file name from the upload could hold an escape sequence that rewrites what the terminal shows. The JSON report and `detect` escape DEL and the C1 range as well.

Exit codes are 0 for clean, 1 for stripped or strippable, 2 for rejected and 3 for a usage or I/O error. `detect` exits 0, or 3 for a usage or I/O error.

## What it does not check

- RAR archives, executables, Windows Installer packages, PostScript and SYLK files. No package reads them, so they get TYPE/NO_PACKAGE at the upload and the container's rule inside one.
- Raw HTML in Markdown, and markup further into a text file whose start is plain text. Such a file is text to detection, and the text rules do not read markup. A browser shown it as HTML would run its scripts.
- Formula rules for a CSV file that no name or declared type calls CSV. Its content alone does not make it CSV.

## Development

Development needs Node 22.12 or later, for mocha 12 and for the CommonJS test build, which loads chai 6 with `require()`. The published package runs on Node 18 or later.

```sh
npm install --ignore-scripts
npm run build
npm test
npm run lint
npm run format
```

`npm test` runs the lint, builds the package and the tests, then runs mocha.

`node scripts/make-fixtures.js` writes every file in `test/fixtures` from scratch, with no other tool. A second run on the same Node writes the same bytes. `manifest.json` in that folder gives each fixture's options and the verdicts and findings inspect and disarm must return, and `test/fixtures.test.ts` checks every entry. `formats/` holds one small sample of each format detection names, and `formats.json` the detection each must get. For a new case, add the file to the script and an entry to the manifest.

`test/siblings.test.ts` detects the test fixtures of the other family packages in the folders beside this one, `../pdf-defuse` and the rest, and checks that each routes to its own package's family, apart from a listed few built to be something else. It skips a package whose folder is not there.

`npx husky` turns on the pre-commit hook, which runs Biome on the staged files and then `npm audit`.

## License

MIT
