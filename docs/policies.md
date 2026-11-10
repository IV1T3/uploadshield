# Policies

A **policy** says which uploads are acceptable: which file types, how large, which
filename rules, which content checks and scanners, and how accepted files are
sanitized. This page shows how to choose a built-in policy, write your own, tune
individual checks, and register policies with Django, Flask, FastAPI and the command
line.

**On this page**

- [Built-in policies](#built-in-policies)
- [Writing a policy](#writing-a-policy)
- [Choosing the allowed types](#choosing-the-allowed-types)
- [Size limits and empty files](#size-limits-and-empty-files)
- [Filename rules](#filename-rules)
- [Extension and declared type](#extension-and-declared-type)
- [Content checks](#content-checks)
- [Extra checks: scanners and your own](#extra-checks-scanners-and-your-own)
- [Sanitizers](#sanitizers)
- [Stopping at the first problem](#stopping-at-the-first-problem)
- [Deriving policies: replace and extend](#deriving-policies-replace-and-extend)
- [Registering and referring to policies](#registering-and-referring-to-policies)
- [Recipes](#recipes)
- [Policy reference](#policy-reference)
- [Registered file types](#registered-file-types)

## Built-in policies

| Name | Python | Allows | `max_size` | Sanitizers |
|---|---|---|---|---|
| `default` | `presets.DEFAULT` | everything in `images`, `documents` and `media` (22 types) | 50 MB | none |
| `images` | `presets.IMAGES` | JPEG, PNG, GIF, WebP | 10 MB | none |
| `sanitized_images` | `presets.SANITIZED_IMAGES` | JPEG, PNG, GIF, WebP | 10 MB | `ReencodeImage`, `RandomizeFilename` |
| `pdf` | `presets.PDF` | PDF | 25 MB | none |
| `documents` | `presets.DOCUMENTS` | PDF, Word, Excel, PowerPoint (OOXML), OpenDocument text/spreadsheet/presentation, plain text, CSV | 25 MB | none |
| `media` | `presets.MEDIA` | MP3, WAV, Ogg, FLAC, M4A, AAC, MP4, WebM, QuickTime | 500 MB | none |

Every preset runs all default [content checks](#content-checks) and refuses
everything else. No preset accepts an executable, a script, HTML, SVG or XML, and none
accepts macro-enabled Office formats (`.docm`, `.xlsm`, `.pptm`).

The type sets behind them are importable too: `presets.IMAGE_TYPES`,
`presets.OFFICE_TYPES`, `presets.TEXT_TYPES`, `presets.DOCUMENT_TYPES`,
`presets.AUDIO_TYPES`, `presets.VIDEO_TYPES`. `presets.BUILTIN_POLICIES` maps each
name to its policy.

Sizes use decimal units: `MB` is 1,000,000 bytes, `MiB` is 1,048,576.

## Writing a policy

```python
from uploadshield import MB, Policy
from uploadshield.checks import ClamAV
from uploadshield.sanitizers import RandomizeFilename

INVOICES = Policy(
    name="invoices",
    allowed_types={"application/pdf", "image/png", "image/jpeg"},
    max_size=5 * MB,
    checks=(ClamAV(address="tcp://clamav:3310"),),
    sanitizers=(RandomizeFilename(),),
)
```

`allowed_types` is the only required argument. Every other field has a safe default;
see the [Policy reference](#policy-reference).

Policies are frozen dataclasses: you cannot change one, you derive a new one
(`replace()`, `extend()`). They are hashable, so the adapters can cache results per
policy, and comparable, so two policies with the same settings are equal.

## Choosing the allowed types

`allowed_types` accepts:

- **canonical MIME types**: `"image/png"`, `"application/pdf"`;
- **common aliases**, which are resolved to the canonical type: `"image/jpg"` becomes
  `"image/jpeg"`, `"image/x-png"` becomes `"image/png"`; case does not matter;
- **wildcards** for a whole category: `"image/*"`, `"audio/*"`, `"video/*"`,
  `"text/*"`, `"application/*"`;
- **`FileType` objects**, for example a type you registered yourself.

A single string is one entry: `allowed_types="application/pdf"` works.

An unknown type raises `ValueError` when the policy is created ("Unknown file type
'foo/bar'. Use a canonical MIME type such as 'image/jpeg', a wildcard such as
'image/*', or register custom types with register_type()."), and so does a wildcard
for an unknown category (`"*/*"`).

**Wildcards never match dangerous formats.** `"image/*"` matches JPEG, PNG, GIF,
WebP, BMP, TIFF, ICO, AVIF and HEIC, but not SVG. Executables (shell scripts, PHP,
JAR, APK, Windows, ELF and Mach-O binaries, Java classes, WebAssembly) and the
formats browsers run script in (`text/html`, `image/svg+xml`, `application/xml`) are
only accepted when listed by their exact MIME type.

The type is always the one detected from the **content**. A PHP script named
`photo.png` is a PHP script and fails `type_not_allowed`. All 61 types uploadshield
knows are listed under [Registered file types](#registered-file-types); add your own
with [`register_type()`](python-api.md#registering-a-file-type).

## Size limits and empty files

| Field | Default | Meaning |
|---|---|---|
| `max_size` | `10 * MB` | The largest accepted file in bytes. `None` means no limit. Negative values raise `ValueError`. |
| `allow_empty` | `False` | Let the size check accept files with zero bytes. Empty content has no detectable type, so the type check still refuses them with `type_unknown`; accepting empty files also needs a [sniffer](python-api.md#types-and-sniffers) that identifies them. |

The limit applies per file. Request-wide limits belong to the framework or the web
server (`MAX_CONTENT_LENGTH` in Flask, the ASGI server for FastAPI, the web server in
front of Django; Django's `DATA_UPLOAD_MAX_MEMORY_SIZE` does not count files). Django
additionally has a per-file hard cap,
[`MAX_UPLOAD_SIZE`](django.md#settings-reference), that applies to every view.

## Filename rules

The client's filename is judged by a `FilenameCheck`. Replace it to change the rules:

```python
from uploadshield import Policy
from uploadshield.checks import FilenameCheck

LOGS = Policy(
    allowed_types={"text/plain"},
    filename=FilenameCheck(max_length=100, require_extension=False),
)
```

| Option | Default | Meaning |
|---|---|---|
| `max_length` | `255` | Maximum length in UTF-8 bytes (`filename_too_long`). |
| `allow_hidden` | `False` | Allow names starting with a dot (`filename_hidden`). |
| `require_extension` | `True` | Require an extension (`filename_missing_extension`). |
| `forbidden_extensions` | `DANGEROUS_EXTENSIONS` | Extensions refused anywhere in the name, so `shell.php.png` and `a.asp;.jpg` are caught (`filename_dangerous_extension`). |
| `forbidden_names` | `DANGEROUS_NAMES` | Whole names refused: `.htaccess`, `web.config`, `.user.ini`, `crossdomain.xml`, ... (`filename_reserved`). |
| `allow_leading_hyphen` | `False` | Allow names like `-rf.png` (`filename_invalid`). |
| `allow_consecutive_dots` | `False` | Allow `a..b.png` (`filename_invalid`). |
| `allow_short_names` | `False` | Allow Windows 8.3 aliases like `WEBCON~1.CON` (`filename_reserved`). |

Some rules cannot be switched off: path and drive separators (`../x.png`, `C:x.png`),
control and bidi-override characters, the characters Windows forbids (`<>"|?*`),
trailing dots and spaces, Windows device names (`CON`, `NUL`, `COM1`, ...) and the
names `.` and `..`. Every rule is applied to the name as sent **and** as later layers
may read it: percent-decoded (`shell%2ephp.png`, `shell.php%00.png`) and
Unicode-normalized (fullwidth `ｐｈｐ`).

To keep only safe characters in stored names, use the `SafeFilename` or
`RandomizeFilename` [sanitizer](#sanitizers) instead of relaxing the rules. All
options are described in [FilenameCheck](checks.md#filenamecheck).

## Extension and declared type

| Field | Default | Meaning |
|---|---|---|
| `match_extension` | `True` | The name's extension must belong to the detected type: a JPEG named `photo.png` fails `extension_mismatch`. Turn it off together with `SafeFilename()` or `RandomizeFilename()`, which give the stored file the right extension. |
| `match_declared_type` | `False` | The client's `Content-Type` must agree with the content (`declared_type_mismatch`). `application/octet-stream` is always accepted. Off by default because browsers and HTTP clients guess these headers. |

The declared type is never used to decide what a file *is*. The adapters replace it
with the detected type before your code sees the file (in Django unless
[`NORMALIZE_CONTENT_TYPE`](django.md#settings-reference) is `False`).

## Content checks

`content_checks` inspect the inside of formats. The default,
`DEFAULT_CONTENT_CHECKS`, runs these in order; each only applies to the formats it
understands:

| Check | Looks at | Catches |
|---|---|---|
| `ArchiveSafety` | ZIP and everything built on it (OOXML, ODF, EPUB, JAR, APK) | ZIP bombs, zip slip, symlinks, encrypted members, dangerous member names |
| `OfficeMacros` | Word, Excel, PowerPoint, OpenDocument, legacy OLE2, CSV | macros, ActiveX, DDE fields and formulas, remote templates |
| `XmlSafety` | XML files and the XML parts of OOXML, ODF, EPUB | DTDs (XXE, billion laughs) |
| `PdfActiveContent` | PDF | JavaScript, launch actions, embedded files, XFA forms and forms that submit or import data, encrypted PDFs |
| `SvgActiveContent` | SVG | scripts, event handlers, `javascript:` links, external references |
| `EmbeddedContent` | images, audio, video; text files | PHP, script and server-side-include code; polyglots (GIFAR) |
| `ImageIntegrity` | images Pillow can decode | corrupt images, decompression bombs |

All options of every check are in [Checks](checks.md).

**Tuning one check.** Replace it in the tuple and keep the others:

```python
from uploadshield import presets
from uploadshield.checks import DEFAULT_CONTENT_CHECKS, ArchiveSafety

STRICT_ZIPS = presets.DOCUMENTS.replace(
    name="strict_documents",
    content_checks=tuple(
        ArchiveSafety(max_entries=500, max_depth=1) if isinstance(check, ArchiveSafety) else check
        for check in DEFAULT_CONTENT_CHECKS
    ),
)
```

**Removing one.** Leave it out, for example to accept encrypted PDFs you inspect
elsewhere. Prefer an option (`PdfActiveContent(allow_encrypted=True)`) over removing a
whole check.

```python
from uploadshield import presets
from uploadshield.checks import DEFAULT_CONTENT_CHECKS, ImageIntegrity

NO_DECODING = presets.IMAGES.replace(
    name="images_without_decoding",
    content_checks=tuple(c for c in DEFAULT_CONTENT_CHECKS if not isinstance(c, ImageIntegrity)),
)
```

Content checks also run again on whatever a sanitizer produced, so a sanitizer cannot
introduce what they refuse.

## Extra checks: scanners and your own

`checks` run after the content checks. Use them for virus scanners, signatures, the
Magika classifier and your own rules:

```python
from uploadshield import presets
from uploadshield.checks import ClamAV, MagikaCheck, YaraRules

SCANNED = presets.DOCUMENTS.extend(
    name="scanned_documents",
    checks=[
        ClamAV(address="unix:///var/run/clamav/clamd.ctl"),
        YaraRules(rules=("/etc/yara",)),
        MagikaCheck(),
    ],
)
```

- [`ClamAV`](checks.md#clamav) streams the file to `clamd` and fails closed when it is
  unreachable.
- [`YaraRules`](checks.md#yararules) matches your YARA rules (`uv add "uploadshield[yara]"`).
- [`MagikaCheck`](checks.md#magikacheck) asks Google's Magika model whether text is
  really a script (`uv add "uploadshield[magika]"`). It can only refuse, never accept.
- Your own checks are small classes; see [Writing a check](python-api.md#writing-a-check).

## Sanitizers

`sanitizers` rewrite accepted files, in order. Each sees the previous one's output.

| Sanitizer | What it does |
|---|---|
| `ReencodeImage()` | Decodes and re-encodes JPEG, PNG, GIF and WebP: drops EXIF (including GPS), XMP, comments and anything appended, applies the orientation, keeps animation. Needs Pillow (`uv add "uploadshield[images]"`). |
| `RandomizeFilename()` | Replaces the name with a random hex name and the canonical extension of the detected type: `3f9c2e....jpg`. |
| `SafeFilename()` | Keeps a readable name made of `[A-Za-z0-9_.- ]`: `Résumé (final).PDF` becomes `Resume_final.pdf`. |

Their options are in [Checks: sanitizers](checks.md#sanitizers). What a sanitizer
produces is checked again: new names against the filename rules, new content against
the content checks. A sanitizer that fails, or changes the type, refuses the file
(`sanitization_failed`).

## Stopping at the first problem

| Field | Default | Meaning |
|---|---|---|
| `fail_fast` | `True` | Stop after the first check that finds a problem. Cheap checks run first, so expensive parsers only see files that passed them. Set `False` to collect every problem, e.g. for a detailed report. |

## Deriving policies: replace and extend

```python
from uploadshield import MB, presets

AVATARS = presets.SANITIZED_IMAGES.replace(name="avatars", max_size=2 * MB)
SCANS = presets.PDF.extend(allowed_types=["image/png", "image/jpeg"], name="scans")
```

- `policy.replace(**changes)` returns a copy with some fields changed. The new policy
  is validated like a new one.
- `policy.extend(*, allowed_types=(), checks=(), sanitizers=(), name=None)` returns a
  copy that **adds** types, checks (appended to `checks`) and sanitizers (appended).
  It never changes `content_checks`. `name=None` keeps the current name.

Give derived policies a new `name`: it appears in logs, in the CLI, and in Django's and
Flask's policy registries.

## Registering and referring to policies

Anywhere a policy is expected you can pass:

- a **`Policy` object**;
- a **name** of a built-in or registered policy: `"images"`;
- a **dotted path** to a module-level `Policy`: `"myproject.uploads.INVOICES"`.

Register your own policies by name:

| Integration | Where |
|---|---|
| Django | `UPLOADSHIELD = {"POLICIES": {"invoices": INVOICES}}` in settings; see [Django](django.md#settings-reference). |
| Flask | `app.config["UPLOADSHIELD"] = {"POLICIES": {"invoices": INVOICES}}`; see [Flask](flask.md#configuration-reference). |
| FastAPI | `UploadShield(policies={"invoices": INVOICES})`; see [FastAPI](fastapi.md#uploadshield). |
| CLI | `uploadshield validate FILE --policy myproject.uploads.INVOICES`, or `--django` for Django's settings; see [CLI](cli.md#choosing-the-policy). |

Registered policies are added to the built-in ones. A registered policy with a
built-in name (for example `"default"`) replaces the built-in one.

In Django model fields, refer to policies by **name**
(`FileValidator(policy="invoices")`): migrations then store the name instead of a
frozen copy of the policy.

## Recipes

**User avatars**: re-encoded, renamed, small.

```python
from uploadshield import MB, presets

AVATARS = presets.SANITIZED_IMAGES.replace(name="avatars", max_size=2 * MB)
```

**Documents from the public**, scanned for malware:

```python
from uploadshield import presets
from uploadshield.checks import ClamAV

APPLICATIONS = presets.DOCUMENTS.extend(
    name="applications", checks=[ClamAV(address="tcp://clamav:3310")]
)
```

**CSV imports**: only CSV, and Magika refuses scripts saved as `.csv`:

```python
from uploadshield import MB, Policy
from uploadshield.checks import MagikaCheck

IMPORTS = Policy(
    name="imports",
    allowed_types={"text/csv"},
    max_size=20 * MB,
    checks=(MagikaCheck(),),
)
```

`OfficeMacros` refuses CSV cells that start a DDE command (`=cmd|' /C calc'!A0`).

**ZIP uploads** with tighter archive limits:

```python
from uploadshield import MB, MiB, Policy
from uploadshield.checks import DEFAULT_CONTENT_CHECKS, ArchiveSafety

BUNDLES = Policy(
    name="bundles",
    allowed_types={"application/zip"},
    max_size=50 * MB,
    content_checks=tuple(
        ArchiveSafety(max_entries=1_000, max_uncompressed_bytes=500 * MiB, max_depth=1)
        if isinstance(check, ArchiveSafety)
        else check
        for check in DEFAULT_CONTENT_CHECKS
    ),
)
```

Every member is measured by inflating it, and members with a dangerous extension or a
server configuration name (`shell.php`, `x.php.png`, `.htaccess`) are refused. Member **contents** are not validated
against a policy: a script named `notes.txt` inside the ZIP passes. Validate extracted
files on their own if you extract them.

**Large media**:

```python
from uploadshield import GB, presets

VIDEOS = presets.MEDIA.replace(name="videos", max_size=2 * GB)
```

In Django oversized files are refused while they stream in; in Flask and FastAPI cap
the request size in front of the application as well.

**Readable stored names** instead of random ones:

```python
from uploadshield import presets
from uploadshield.sanitizers import SafeFilename

REPORTS = presets.PDF.replace(name="reports", sanitizers=(SafeFilename(),))
```

**SVG.** Avoid accepting SVG from users: served from your domain it runs script in
your users' browsers. Rasterize it instead. If you must accept it, list it explicitly;
`SvgActiveContent` then refuses scripts, event handlers, `javascript:` links,
`foreignObject`, entities and external references:

```python
from uploadshield import Policy

LOGOS = Policy(name="logos", allowed_types={"image/svg+xml", "image/png"})
```

## Policy reference

`Policy(*, allowed_types, ...)` takes keyword arguments only.

| Field | Type | Default | Description |
|---|---|---|---|
| `allowed_types` | collection of `str` or `FileType` | required | MIME types, aliases or `category/*` wildcards; see [Choosing the allowed types](#choosing-the-allowed-types). |
| `max_size` | `int \| None` | `10 * MB` | Largest accepted file in bytes; `None` for no limit. |
| `allow_empty` | `bool` | `False` | Accept zero-byte files. |
| `filename` | `FilenameCheck` | `FilenameCheck()` | Filename rules; also applied to names produced by sanitizers. |
| `match_extension` | `bool` | `True` | Require the extension to match the detected type. |
| `match_declared_type` | `bool` | `False` | Require the client's `Content-Type` to match the detected type. |
| `content_checks` | `tuple[Check, ...]` | `DEFAULT_CONTENT_CHECKS` | Format-specific checks; also applied to sanitized output. |
| `checks` | `tuple[Check, ...]` | `()` | Additional checks run after the content checks (scanners, custom). |
| `sanitizers` | `tuple[Sanitizer, ...]` | `()` | Applied in order to files that passed every check. |
| `sniffer` | `Sniffer` | `BuiltinSniffer()` | Detects the type from content; see [Types and sniffers](python-api.md#types-and-sniffers). |
| `fail_fast` | `bool` | `True` | Stop at the first check that finds a problem. |
| `name` | `str` | `""` | Shown in logs and the CLI; the key in registries. |

Attributes and methods:

| Name | Description |
|---|---|
| `policy.pipeline` | The checks in the order they run: size, filename, type, extension (if `match_extension`), declared type (if `match_declared_type`), `content_checks`, `checks`. |
| `policy.types` | The normalized allow-list, a `frozenset` of MIME types and wildcards. |
| `policy.allows(file_type)` | Whether a `FileType` passes the allow-list. |
| `policy.allows_mime(mime)` | The same for a MIME string; unknown types are `False`. |
| `policy.replace(**changes)` | A validated copy with fields changed. |
| `policy.extend(*, allowed_types, checks, sanitizers, name)` | A copy that adds types, checks and sanitizers. |
| `policy.deconstruct()` | `(path, args, kwargs)` for Django migrations; only fields that differ from the defaults. |

Passing something that is not a `Check` in `content_checks` or `checks`, or not a
`Sanitizer` in `sanitizers`, raises `TypeError`.

## Registered file types

These are the formats uploadshield can detect and allow. "Narrows" types cannot be
proven by content alone; they are refined from their parent by the file's extension.

| MIME type | Label | Extensions | Notes |
|---|---|---|---|
| `image/jpeg` | JPEG image | `.jpg` `.jpeg` `.jpe` `.jfif` |  |
| `image/png` | PNG image | `.png` |  |
| `image/gif` | GIF image | `.gif` |  |
| `image/webp` | WebP image | `.webp` |  |
| `image/bmp` | BMP image | `.bmp` `.dib` |  |
| `image/tiff` | TIFF image | `.tif` `.tiff` |  |
| `image/vnd.microsoft.icon` | ICO icon | `.ico` |  |
| `image/avif` | AVIF image | `.avif` |  |
| `image/heic` | HEIC image | `.heic` `.heif` |  |
| `image/svg+xml` | SVG image | `.svg` | runs script in browsers |
| `text/plain` | Plain text | `.txt` `.text` `.log` |  |
| `text/csv` | CSV | `.csv` | narrows `text/plain` |
| `text/tab-separated-values` | TSV | `.tsv` | narrows `text/plain` |
| `text/markdown` | Markdown | `.md` `.markdown` | narrows `text/plain` |
| `text/html` | HTML document | `.html` `.htm` `.xhtml` | runs script in browsers |
| `audio/mpeg` | MP3 audio | `.mp3` |  |
| `audio/wav` | WAV audio | `.wav` |  |
| `audio/ogg` | Ogg audio | `.ogg` `.oga` `.opus` |  |
| `audio/flac` | FLAC audio | `.flac` |  |
| `audio/mp4` | MPEG-4 audio | `.m4a` |  |
| `audio/aac` | AAC audio | `.aac` |  |
| `video/mp4` | MPEG-4 video | `.mp4` `.m4v` |  |
| `video/quicktime` | QuickTime video | `.mov` `.qt` |  |
| `video/webm` | WebM video | `.webm` |  |
| `video/x-matroska` | Matroska video | `.mkv` |  |
| `video/x-msvideo` | AVI video | `.avi` |  |
| `video/mpeg` | MPEG video | `.mpeg` `.mpg` |  |
| `video/3gpp` | 3GPP video | `.3gp` |  |
| `application/pdf` | PDF document | `.pdf` |  |
| `application/vnd.openxmlformats-officedocument.wordprocessingml.document` | Word document | `.docx` | zip container |
| `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` | Excel workbook | `.xlsx` | zip container |
| `application/vnd.openxmlformats-officedocument.presentationml.presentation` | PowerPoint presentation | `.pptx` | zip container |
| `application/vnd.ms-word.document.macroenabled.12` | Word macro-enabled document | `.docm` | zip container |
| `application/vnd.ms-excel.sheet.macroenabled.12` | Excel macro-enabled workbook | `.xlsm` | zip container |
| `application/vnd.ms-powerpoint.presentation.macroenabled.12` | PowerPoint macro-enabled presentation | `.pptm` | zip container |
| `application/vnd.oasis.opendocument.text` | OpenDocument text | `.odt` | zip container |
| `application/vnd.oasis.opendocument.spreadsheet` | OpenDocument spreadsheet | `.ods` | zip container |
| `application/vnd.oasis.opendocument.presentation` | OpenDocument presentation | `.odp` | zip container |
| `application/epub+zip` | EPUB e-book | `.epub` | zip container |
| `application/x-ole-storage` | OLE2 compound document (legacy Office) | `.doc` `.xls` `.ppt` `.msg` | ole container |
| `application/rtf` | Rich Text Format | `.rtf` |  |
| `application/postscript` | PostScript | `.ps` `.eps` |  |
| `application/json` | JSON | `.json` | narrows `text/plain` |
| `application/xml` | XML document | `.xml` | runs script in browsers |
| `application/x-sh` | Shell script | `.sh` | executable |
| `application/x-httpd-php` | PHP script | `.php` | executable |
| `application/zip` | ZIP archive | `.zip` | zip container |
| `application/gzip` | gzip archive | `.gz` `.tgz` |  |
| `application/x-tar` | tar archive | `.tar` |  |
| `application/x-bzip2` | bzip2 archive | `.bz2` |  |
| `application/x-xz` | xz archive | `.xz` |  |
| `application/x-7z-compressed` | 7-Zip archive | `.7z` |  |
| `application/vnd.rar` | RAR archive | `.rar` |  |
| `application/java-archive` | Java archive | `.jar` | executable, zip container |
| `application/vnd.android.package-archive` | Android package | `.apk` | executable, zip container |
| `application/vnd.microsoft.portable-executable` | Windows executable | `.exe` `.dll` `.sys` `.scr` | executable |
| `application/x-elf` | ELF executable | `.elf` `.so` | executable |
| `application/x-mach-binary` | Mach-O executable | `.dylib` | executable |
| `application/java-vm` | Java class file | `.class` | executable |
| `application/wasm` | WebAssembly module | `.wasm` | executable |
| `application/vnd.sqlite3` | SQLite database | `.sqlite` `.sqlite3` `.db` |  |

Only ZIP containers are opened. gzip, tar, bzip2, xz, 7-Zip and RAR archives are
detected but their contents are not inspected.
