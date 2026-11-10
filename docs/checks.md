# Checks and sanitizers

This is the reference for every check and sanitizer: what it catches, which files it
applies to, every option with its default, and the violation codes it reports with
their `details`. To combine them into policies, see [Policies](https://github.com/IV1T3/uploadshield/blob/main/docs/policies.md). To write
your own, see [Writing a check](https://github.com/IV1T3/uploadshield/blob/main/docs/python-api.md#writing-a-check).

All checks and sanitizers are frozen dataclasses: you configure them with keyword
arguments, and they are hashable values like policies.

```python
from uploadshield.checks import ArchiveSafety, ClamAV, PdfActiveContent
from uploadshield.sanitizers import ReencodeImage, SafeFilename

ArchiveSafety(max_depth=1)
PdfActiveContent(allow_encrypted=True)
ReencodeImage(quality=85)
```

**On this page**

- [Overview](#overview)
- Basic checks: [FileSize](#filesize) · [FilenameCheck](#filenamecheck) ·
  [AllowedTypes](#allowedtypes) · [ExtensionMatchesType](#extensionmatchestype) ·
  [DeclaredTypeMatches](#declaredtypematches)
- Content checks: [ArchiveSafety](#archivesafety) · [OfficeMacros](#officemacros) ·
  [XmlSafety](#xmlsafety) · [PdfActiveContent](#pdfactivecontent) ·
  [SvgActiveContent](#svgactivecontent) · [EmbeddedContent](#embeddedcontent) ·
  [ImageIntegrity](#imageintegrity)
- Scanners: [ClamAV](#clamav) · [YaraRules](#yararules) · [MagikaCheck](#magikacheck)
- [Sanitizers](#sanitizers): [ReencodeImage](#reencodeimage) ·
  [RandomizeFilename](#randomizefilename) · [SafeFilename](#safefilename)
- [Constants](#constants)

## Overview

The `name` of a check appears in `ValidationResult.checks_run` and as the `check` of
each violation it reports.

| Check | `name` | Applies to | Codes |
|---|---|---|---|
| `FileSize` | `size` | every file | `file_empty`, `file_too_large` |
| `FilenameCheck` | `filename` | every file | `filename_invalid`, `filename_reserved`, `filename_hidden`, `filename_dangerous_extension`, `filename_too_long`, `filename_missing_extension` |
| `AllowedTypes` | `type` | every file | `type_unknown`, `type_not_allowed` |
| `ExtensionMatchesType` | `extension` | files with a known type and an extension | `extension_mismatch` |
| `DeclaredTypeMatches` | `declared_type` | files with a known type and a declared type | `declared_type_mismatch` |
| `ArchiveSafety` | `archive` | ZIP and ZIP-based formats; tar, plain or compressed; gzip, bzip2 and xz files | `archive_corrupt`, `archive_bomb`, `archive_unsafe_path`, `archive_dangerous_member`, `archive_encrypted` |
| `OfficeMacros` | `office` | OOXML, ODF, legacy OLE2, CSV | `office_macros`, `office_external_reference` |
| `XmlSafety` | `xml` | OOXML, ODF, EPUB, XML | `xml_dtd` |
| `PdfActiveContent` | `pdf` | PDF | `pdf_active_content` |
| `SvgActiveContent` | `svg` | SVG | `svg_active_content` |
| `EmbeddedContent` | `embedded` | images, audio, video; text | `embedded_code`, `polyglot` |
| `ImageIntegrity` | `image` | images Pillow can decode | `image_corrupt`, `image_too_large` |
| `ClamAV` | `clamav` | every file | `malware_detected`, `scanner_unavailable` |
| `YaraRules` | `yara` | every file | `signature_match` |
| `MagikaCheck` | `magika` | files with a known type | `content_mismatch` |

Any check can also produce `check_failed`. That happens when it crashes
(`details["reason"] == "crashed"`) or when a file exceeds its memory budget
(`details["reason"] == "too_large"`); see [Fail closed](https://github.com/IV1T3/uploadshield/blob/main/docs/concepts.md#fail-closed).

The first five checks are built from the policy's own fields (`max_size`, `filename`,
`allowed_types`, `match_extension`, `match_declared_type`). The content checks are
`DEFAULT_CONTENT_CHECKS`; the scanners are added through `checks=`.

## FileSize

Refuses empty files and files larger than the limit. Built from the policy's
`max_size` and `allow_empty`; you rarely create it yourself.

| Option | Type | Default | Description |
|---|---|---|---|
| `max_bytes` | `int \| None` | `None` | Largest accepted size in bytes; `None` for no limit. |
| `allow_empty` | `bool` | `False` | Accept zero-byte files. |

| Code | Details |
|---|---|
| `file_empty` | none |
| `file_too_large` | `size`, `limit` (bytes) |

## FilenameCheck

Judges the client's filename. Every rule is applied to the name as sent and to the
forms later layers may read: up to three rounds of percent-decoding (`shell%2ephp.png`,
`shell.php%00.png`, double encoding) and Unicode NFKC normalization (fullwidth
`ｐｈｐ`, superscript `COM¹`). A violation found only in such a form has a `read_as`
detail with that form.

Set it on a policy with `Policy(filename=FilenameCheck(...))`. It also judges names that
sanitizers produce.

| Option | Type | Default | Description |
|---|---|---|---|
| `max_length` | `int` | `255` | Maximum name length in UTF-8 bytes. |
| `allow_hidden` | `bool` | `False` | Allow names that start with a dot. |
| `require_extension` | `bool` | `True` | Require an extension. |
| `forbidden_extensions` | `frozenset[str]` | `DANGEROUS_EXTENSIONS` | Lowercase extensions without the dot, refused in **any** segment of the name: `shell.php.png`, `a.asp;.jpg`, `a.aspx::$DATA`. |
| `forbidden_names` | `frozenset[str]` | `DANGEROUS_NAMES` | Whole lowercase names to refuse. |
| `allow_leading_hyphen` | `bool` | `False` | Allow a leading `-` (a leading space is always refused). |
| `allow_consecutive_dots` | `bool` | `False` | Allow `..` inside a name. |
| `allow_short_names` | `bool` | `False` | Allow Windows 8.3 short names (`PROGRA~1`, `WEBCON~1.CON`). |

| Code | When | Details |
|---|---|---|
| `filename_invalid` | empty or blank name; control or bidi-override characters; `/`, `\` or `:`; `< > " \| ? *`; trailing dot or space; leading hyphen or space; consecutive dots | `read_as` if found after decoding |
| `filename_reserved` | a forbidden name; `.` or `..`; a Windows device name (`CON`, `NUL`, `COM1`, ... before the first dot); an 8.3 short name | `read_as` |
| `filename_hidden` | starts with a dot | `read_as` |
| `filename_dangerous_extension` | a forbidden extension in any segment | `extensions` (sorted list), `read_as` |
| `filename_too_long` | longer than `max_length` bytes | `limit` |
| `filename_missing_extension` | no extension and `require_extension` | none |

## AllowedTypes

Refuses files whose **content** is not on the allow-list. Built from the policy's
`allowed_types`.

| Option | Type | Default | Description |
|---|---|---|---|
| `types` | `frozenset[str]` | `frozenset()` | Canonical MIME types and `category/*` wildcards (normalized from the policy's `allowed_types`). Wildcards never match executables, `text/html`, `image/svg+xml`, `application/xml` or the [`UNINSPECTED_ARCHIVES`](#constants). |

| Code | When | Details |
|---|---|---|
| `type_unknown` | the content matches no registered type | `declared_type`, `extension` |
| `type_not_allowed` | the detected type is not allowed | `detected_type`, `declared_type` |

## ExtensionMatchesType

Requires the final extension of the name to be one of the detected type's
extensions. Added when the policy has `match_extension=True` (the default). It has no
options.

| Code | Details |
|---|---|
| `extension_mismatch` | `extension`, `detected_type`, `expected` (list of extensions) |

## DeclaredTypeMatches

Requires the client's `Content-Type` to match the detected type (or one of its
aliases, or its parent type). Added when the policy has `match_declared_type=True`.

| Option | Type | Default | Description |
|---|---|---|---|
| `ignored` | `frozenset[str]` | `{"application/octet-stream", "binary/octet-stream"}` | Declared types that mean "unknown" and are never compared. |

| Code | Details |
|---|---|
| `declared_type_mismatch` | `declared_type`, `detected_type` |

## ArchiveSafety

Inspects archives without extracting them:

- ZIP and every format built on ZIP: `.zip`, Word/Excel/PowerPoint (including
  macro-enabled), OpenDocument, EPUB, JAR and APK;
- tar archives, plain (`.tar`) or compressed with gzip, bzip2 or xz (`.tar.gz`, `.tgz`,
  `.tar.bz2`, `.tar.xz`);
- gzip, bzip2 and xz files that hold no archive (`data.csv.gz`): they are
  decompressed and measured like a member. Unless what it holds is a tar archive, a
  tar header anywhere in it is refused: `tar -xzf` skips data until it finds one and
  extracts what follows.

It measures every member (headers can lie about sizes; compressed tar archives are
measured while they decompress), walks archives inside archives (`site.zip` inside
`backup.tar.gz`), and refuses unsafe paths, links, and members with a dangerous
extension or a server configuration name. Tar members hidden after an end-of-archive
marker are judged too, because `tar --ignore-zeros` extracts them, and a damaged tar
header is refused rather than skipped. 7-Zip and RAR archives are not opened
([`UNINSPECTED_ARCHIVES`](#constants)).

| Option | Type | Default | Description |
|---|---|---|---|
| `max_entries` | `int` | `10_000` | Members allowed, counted across nested archives. |
| `max_uncompressed_bytes` | `int` | `1 GiB` | Total uncompressed size, declared and measured, shared across nesting levels. |
| `max_ratio` | `int` | `100` | Highest compression ratio... |
| `ratio_threshold_bytes` | `int` | `10 MiB` | ...enforced only once a level declares (ZIP) or decompresses (gzip, bzip2, xz) more than this many bytes. |
| `allow_encrypted` | `bool` | `False` | Allow encrypted ZIP members (they cannot be inspected). |
| `verify_sizes` | `bool` | `True` | Inflate every ZIP member to measure its real size and CRC. `False` trusts the ZIP headers. Tar archives keep their headers in the stream, so they are always read through. |
| `check_member_names` | `bool` | `True` | Refuse members whose name has an extension in `DANGEROUS_EXTENSIONS` (in any segment: `x.php.png`) or is in `DANGEROUS_NAMES` (`.htaccess`). The policy's own `FilenameCheck` is not applied to members. |
| `max_depth` | `int` | `3` | Levels of nested archives to open. |
| `max_nested_bytes` | `int` | `64 MiB` | Nested archives larger than this are refused as too large to inspect. A tar inside its gzip, bzip2 or xz stream is one archive, not a nested one. |

| Code | When | Details |
|---|---|---|
| `archive_corrupt` | the archive cannot be read consistently: a damaged ZIP, tar header or compressed stream, a truncated archive, a tar header hidden behind other data in a compressed stream, or a ZIP member whose local header names a different file than the central directory | `member` (when one member is at fault); `tar_header_at` (the offset of a hidden tar header) |
| `archive_bomb` | too many members, too large, too high a ratio, overlapping entries, a member inflating beyond its header, a compressed stream decompressing beyond the budget or ratio, nesting too deep or too large | `entries`, `uncompressed`, `ratio`, `overlapping`, `archive`; or `member`, `declared`, `measured_at_least`; or `archive`, `measured_at_least`; or `member` |
| `archive_unsafe_path` | absolute paths, drive letters, `..`, NUL bytes, symbolic links; in tar archives also hard links, device files and FIFOs | `paths` (up to 10) |
| `archive_dangerous_member` | members with a dangerous extension or a server configuration name | `members` (up to 10; nested ones as `outer.zip/inner.zip/x`) |
| `archive_encrypted` | an encrypted ZIP member | none |

Member **contents** are not validated against a policy; a script named `notes.txt`
inside the archive passes. When contents matter, add [`ClamAV`](#clamav), which unpacks
archives itself. 7-Zip and RAR archives are detected but not opened: wildcards never
match them, so a policy accepts one only by naming its type, and then accepts it
uninspected.

## OfficeMacros

Refuses Office documents that run code or load remote content: VBA macros, ActiveX
controls, ODF Basic and scripts, DDE fields in any Word part (body, headers, footers,
footnotes, comments), Excel DDE links and formulas, DDE cells in CSV files
(`=cmd|' /C calc'!A0`), VBA in legacy OLE2 files (`.doc`, `.xls`, `.ppt`), and remote
templates and objects.

Applies to Word, Excel and PowerPoint (OOXML and macro-enabled), OpenDocument text,
spreadsheet and presentation, OLE2 compound documents and `text/csv`.

| Option | Type | Default | Description |
|---|---|---|---|
| `block_external_references` | `bool` | `True` | Refuse relationships that load external content (attached templates, OLE objects, frames, sub-documents). Hyperlinks are fine. |
| `max_part_bytes` | `int` | `16 MiB` | Largest relationship part read into memory; larger ones make the file `check_failed` (too large). DDE fields are searched in parts of any size. |

| Code | When | Details |
|---|---|---|
| `office_macros` | macros, ActiveX, ODF scripts; DDE fields, links or formulas; a CSV DDE cell; a VBA project in OLE2 | `parts` (up to 10), when known |
| `office_external_reference` | a remote template or object | `targets` (up to 10) |

XLM (Excel 4.0) macros in legacy `.xls` files are not detected.

## XmlSafety

Refuses document type definitions (DTDs), which enable entity expansion ("billion
laughs") and external entities (XXE). Applies to XML files and to the XML parts
(`.xml`, `.rels`, `.vml`, `.xhtml`, `.htm`, `.html`, `.opf`, `.ncx`, `.svg`, `.rdf`,
`.xsl`) of OOXML, ODF and EPUB files.

| Option | Type | Default | Description |
|---|---|---|---|
| `head_bytes` | `int` | `64 KiB` | How far into each part to look for the prolog. A prolog longer than this is refused, because it cannot be decided. |

| Code | Details |
|---|---|
| `xml_dtd` | `parts` (up to 10) |

## PdfActiveContent

Refuses PDFs that can run code or carry payloads: JavaScript, launch actions, embedded
files, rich media, XFA forms, data import and form submission. Name objects are
matched exactly after decoding `#xx` obfuscation (`/J#61vaScript`), in the file itself
**and** inside object streams, where attackers hide them. Object streams are decoded
completely (Flate, ASCIIHex, ASCII85); one that cannot be decoded, or that sits
outside the file's object structure, makes the PDF uncheckable, which is a refusal.

`/OpenAction` and `/AA` are deliberately not refused: LaTeX and office suites use them
for harmless view settings, and the scripts they would trigger are caught as
`/JavaScript` and `/JS`.

| Option | Type | Default | Description |
|---|---|---|---|
| `forbidden` | `frozenset[str]` | `DEFAULT_PDF_KEYWORDS` | Name objects to refuse, without the slash. |
| `inspect_streams` | `bool` | `True` | Decode object streams and check the names inside them. |
| `allow_encrypted` | `bool` | `False` | Allow encrypted PDFs (they cannot be inspected). |
| `max_bytes` | `int` | `200 MiB` | Largest PDF read into memory; larger ones are `check_failed` (too large). |
| `max_inflated_bytes` | `int` | `64 MiB` | Total decoded size of all object streams; beyond it, `check_failed` (too large). |

| Code | Details |
|---|---|
| `pdf_active_content` | `reason`: `"active_content"` with `keywords` (sorted names found), `"encrypted"` with `keywords: ["Encrypt"]`, or `"uncheckable"` with `detail` (why the object streams could not be read) |

## SvgActiveContent

Refuses SVG images that can run script or load external resources: `<script>`
elements, the `<handler>` element, event-handler attributes (`onload=`, also after
attribute values containing `>`), `javascript:` and `data:text/html` URIs (also
entity-encoded or split by tabs and newlines), `foreignObject`, embedded documents
(`iframe`, `embed`, `object`), entity declarations, XSLT stylesheets, external
references (`href=`/`url(...)` with any scheme other than `data:`, a `#fragment` or a
relative path, and CSS `@import`), CSS `expression(...)`, and animations that set `href`
or an `on...` handler. The image is scanned both as-is and with CSS comments and
backslash escapes decoded, so neither `/* ... */` nor `expr/**/ession(` nor `@im\port`
hides anything. Applies to `image/svg+xml`, which no preset allows.

| Option | Type | Default | Description |
|---|---|---|---|
| `max_bytes` | `int` | `10 MiB` | Largest SVG read into memory; larger ones are `check_failed` (too large). |

| Code | Details |
|---|---|
| `svg_active_content` | `found`: labels of what was found, from `event handler attribute`, `script element`, `script URI`, `foreignObject`, `embedded document`, `entity declaration`, `XSLT stylesheet`, `external resource`, `handler element`, `CSS expression`, `animated attribute` |

## EmbeddedContent

Refuses files that smuggle server-side code or a second file format.

- **In images, audio and video** it scans the whole file for PHP open and short-echo
  tags, `<script>`, JSP and ASP directives, server-side includes and PHAR stubs (a web
  shell in EXIF metadata, or appended to the image data), and refuses polyglots: a
  ZIP archive appended to an image (GIFAR) or a PDF header near the start.
- **In text files** (`scan_text`) it refuses PHP tags anywhere, because PHP's
  `include` runs them from a `.txt` or `.csv` too.

| Option | Type | Default | Description |
|---|---|---|---|
| `categories` | `frozenset[str]` | `{"image", "audio", "video"}` | Media categories scanned for code and polyglots. |
| `scan_text` | `bool` | `True` | Also scan text types (for PHP tags only). |
| `max_scan_bytes` | `int` | `1 GiB` | Files larger than this are `check_failed` (too large) rather than scanned in part. |

| Code | When | Details |
|---|---|---|
| `embedded_code` | a code marker was found | `marker` (the text found, e.g. `<?php`) |
| `polyglot` | the file is also a ZIP or PDF | none |

## ImageIntegrity

Decodes images completely with Pillow, using only the format detected from the
content, and refuses corrupt images and decompression bombs. It checks the dimensions
from the header before decoding.

Applies to JPEG, PNG, GIF, WebP, BMP, TIFF, ICO, AVIF and HEIC when Pillow (and, for
AVIF/HEIC, its plugin) can decode them. **Without Pillow the check does nothing**:
install the `images` extra (`uv add "uploadshield[images]"`). Django's system check
`uploadshield.W002` and `uploadshield policies NAME` warn about this.

| Option | Type | Default | Description |
|---|---|---|---|
| `max_pixels` | `int` | `50_000_000` | Pixels per frame. |
| `max_frames` | `int` | `1_000` | Frames of an animation. |
| `max_total_pixels` | `int` | `100_000_000` | Pixels across all frames (a small animated GIF can need gigabytes to decode). |

| Code | Details |
|---|---|
| `image_too_large` | `width`, `height`, `frames`, `max_pixels`; or `error` (Pillow's bomb warning) |
| `image_corrupt` | `error` |

## ClamAV

Streams the file to a running `clamd` with the `INSTREAM` command; no Python package is
needed. **Fails closed**: when `clamd` is unreachable or answers with an error, the file
is refused with `scanner_unavailable`.

```python
from uploadshield import presets
from uploadshield.checks import ClamAV

SCANNED = presets.DOCUMENTS.extend(checks=[ClamAV(address="tcp://127.0.0.1:3310")], name="scanned")
```

| Option | Type | Default | Description |
|---|---|---|---|
| `address` | `str` | `"unix:///var/run/clamav/clamd.ctl"` | `unix:///path/to/socket`, a bare socket path, or `tcp://host:port`. |
| `timeout` | `float` | `30.0` | Socket timeout in seconds. |
| `fail_open` | `bool` | `False` | Accept files when `clamd` cannot be reached. Not recommended. |
| `chunk_size` | `int` | `262144` | Bytes per `INSTREAM` chunk. |

| Code | Details |
|---|---|
| `malware_detected` | `signature` (the name ClamAV reports) |
| `scanner_unavailable` | `error` |

`clamd` refuses streams larger than its `StreamMaxLength` setting (see your
`clamd.conf`; the default depends on the ClamAV version); those files become
`scanner_unavailable`. Raise it to at least your largest `max_size`. `uploadshield.checks.scanners.clamd_ping(address, *, timeout=5.0)` tells
whether a `clamd` answers. The command line uses it to fail before scanning.

## YaraRules

Matches the file against your YARA rules. Needs the `yara` extra
(`uv add "uploadshield[yara]"`). Rules are compiled once per process.

```python
from uploadshield.checks import YaraRules

YaraRules(rules=("/etc/yara",))  # every *.yar / *.yara in the folder
YaraRules(source='rule eicar { strings: $e = "EICAR" condition: $e }')
```

| Option | Type | Default | Description |
|---|---|---|---|
| `rules` | `tuple[str, ...]` | `()` | Rule files or directories (`*.yar`, `*.yara`). |
| `source` | `str \| None` | `None` | Rule text, instead of files. |
| `timeout` | `int` | `30` | Match timeout in seconds. |
| `max_bytes` | `int` | `256 MiB` | Largest file read into memory; larger ones are `check_failed` (too large). |

Passing neither `rules` nor `source` raises `ValueError`. `YaraRules(...).compile()`
compiles the rules (and raises on errors), which is how Django's system check
`uploadshield.E003` and the command line catch broken rules early.

| Code | Details |
|---|---|
| `signature_match` | `rules` (names of the matching rules, sorted) |

## MagikaCheck

A second opinion from [Google Magika](https://github.com/google/magika), a deep-learning
file-type classifier. Deterministic sniffing can prove that a file is *text*, but not
whether that text is CSV or a PowerShell dropper; Magika can. Needs the `magika` extra
(`uv add "uploadshield[magika]"`, not available on Python 3.15 yet because
`onnxruntime` has no wheels there).

```python
from uploadshield import presets
from uploadshield.checks import MagikaCheck

IMPORTS = presets.DOCUMENTS.extend(checks=[MagikaCheck()], name="imports")
```

A file is refused with `content_mismatch` when Magika labels it with a **forbidden**
label (scripts, executables, active markup; `DEFAULT_MAGIKA_FORBIDDEN`) with at least
`min_score` confidence, unless that label is the very type the policy accepted (an
HTML file under a policy that explicitly allows `text/html` is not refused for being
HTML).

| Option | Type | Default | Description |
|---|---|---|---|
| `forbidden` | `frozenset[str]` | `DEFAULT_MAGIKA_FORBIDDEN` | Magika labels to refuse. |
| `min_score` | `float` | `0.9` | Minimum confidence, between 0 and 1 (`ValueError` otherwise). |
| `prediction_mode` | `str` | `"high_confidence"` | Magika's mode: `"high_confidence"`, `"medium_confidence"` or `"best_guess"` (`ValueError` otherwise). |

| Code | Details |
|---|---|
| `content_mismatch` | `magika_label`, `score`, `group`, `mime_type`, `model`, `detected_type` |

`MagikaCheck` can **only veto**. Your allow-list and the deterministic checks still
decide what is accepted, because Magika:

- is a probabilistic classifier;
- sees only the first and last KiB of a file, so whoever writes those bytes steers it;
- changes its verdicts when its model is upgraded (the model name is in `details`).

At worst it causes a false positive, never a bypass. On 150 benign real-world files
(CSV, TXT, JSON, Markdown, images) it refused none. Measured costs (Apple Silicon,
Python 3.13): about 75 ms once per process for import and model load, about
40-60 MiB of memory per worker process, and about 4 ms per file, independent of
file size.

## Sanitizers

Sanitizers run in order after every check has passed. What they produce is checked
again (names against the filename rules, content against the content checks); a
sanitizer that fails or changes the file's type refuses the file with
`sanitization_failed`.

### ReencodeImage

Decodes and re-encodes JPEG, PNG, GIF and WebP images with the format detected from
the content. Drops EXIF (including GPS), XMP, comments and anything appended after the
image data; applies the EXIF orientation; keeps animation (all frames of animated GIF
and WebP), transparency, ICC profiles (optionally) and timing. Needs Pillow
(`uv add "uploadshield[images]"`). Its `name` is `reencode_image`.

| Option | Type | Default | Description |
|---|---|---|---|
| `quality` | `int` | `90` | JPEG and WebP quality. |
| `keep_icc_profile` | `bool` | `True` | Keep the color profile. |
| `max_bytes` | `int` | `100 MiB` | Largest image re-encoded. |
| `max_total_pixels` | `int` | `100_000_000` | Pixels across all frames; larger images are refused (`sanitization_failed`). |

### RandomizeFilename

Replaces the name with a random 32-character hex name and the canonical extension of
the detected type: `3ff7eff4b5b24b44aecc441e9d91ba60.jpg`. No options. Its `name` is
`randomize_filename`.

### SafeFilename

Keeps a readable name. It takes the part before the first dot, folds it to ASCII,
keeps only letters, digits, `_`, `-`, `.` and spaces, turns spaces into `_` and adds an
extension that belongs to the detected type: `Résumé (final).PDF` becomes
`Resume_final.pdf`, and a name with nothing left becomes `file.pdf`. A result that
would be a Windows device name gets a trailing underscore (`CÖN.pdf` becomes
`CON_.pdf`). Its `name` is `safe_filename`.

| Option | Type | Default | Description |
|---|---|---|---|
| `max_length` | `int` | `100` | Maximum length of the new name, extension included. |

## Constants

All importable from `uploadshield.checks`:

| Constant | Contents |
|---|---|
| `DEFAULT_CONTENT_CHECKS` | The default `Policy.content_checks`: `ArchiveSafety()`, `OfficeMacros()`, `XmlSafety()`, `PdfActiveContent()`, `SvgActiveContent()`, `EmbeddedContent()`, `ImageIntegrity()`, in this order. |
| `DANGEROUS_EXTENSIONS` | 105 extensions servers or clients execute: PHP variants (`php`, `php3`-`php8`, `phtml`, `phar`, `pgif`, ...), ASP/.NET (`asp`, `aspx`, `ashx`, `asmx`, `cer`, `cshtml`, `svc`, ...), JSP and ColdFusion, CGI, Perl, Python, Ruby and shell scripts, Windows executables and scripts (`exe`, `dll`, `msi`, `scr`, `bat`, `cmd`, `vbs`, `js`, `ps1`, `hta`, `lnk`, `reg`, `chm`, ...), `jar`, `swf`, `xap`, `settingcontent-ms`, `iqy`, `slk`, `xll`, `htaccess`, `htpasswd`. |
| `DANGEROUS_NAMES` | `.htaccess`, `.htpasswd`, `web.config`, `.user.ini`, `php.ini`, `crossdomain.xml`, `clientaccesspolicy.xml`. |
| `WINDOWS_RESERVED_NAMES` | Windows device names: `con`, `prn`, `aux`, `nul`, `conin$`, `conout$`, `com0`-`com9`, `lpt0`-`lpt9`. |
| `UNINSPECTED_ARCHIVES` | Archives no check opens: `application/x-7z-compressed`, `application/vnd.rar`. Wildcards (`application/*`) never match them, and `uploadshield scan` reports them as not verified. |
| `DEFAULT_PDF_KEYWORDS` | `JavaScript`, `JS`, `Launch`, `EmbeddedFile`, `EmbeddedFiles`, `RichMedia`, `XFA`, `ImportData`, `SubmitForm`, `GoToE`. |
| `DEFAULT_MAGIKA_FORBIDDEN` | 38 Magika labels: executables (`pebin`, `elf`, `macho`, `msi`, `apk`, `jar`, `dex`, `wasm`, ...), scripts (`shell`, `batch`, `powershell`, `vba`, `javascript`, `python`, `php`, `perl`, `ruby`, `lua`, ...), and `html`, `svg`, `mht`, `htaccess`, `lnk`, `winregistry`. |
| `MAGIKA_EQUIVALENTS` | Magika labels and the MIME type each means (`html` is `text/html`, `php` is `application/x-httpd-php`, ...). A label is not refused when it is the type the policy accepted. |

Extend a set rather than replacing it:

```python
from uploadshield.checks import DANGEROUS_EXTENSIONS, FilenameCheck

FilenameCheck(forbidden_extensions=DANGEROUS_EXTENSIONS | {"md"})
```
