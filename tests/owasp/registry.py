"""The OWASP documents on file uploads, every recommendation in them, and its coverage.

* The File Upload Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
* The Unrestricted File Upload vulnerability page, with its test cases:
  https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload

This registry is the single source of truth for ``docs/OWASP.md`` (each document's
matrix is rendered from here) and for traceability: tests verify an item with
``@pytest.mark.owasp("<id>")``, and ``tests/meta/test_owasp_matrix.py`` fails when an
item the library covers has no test, or when the document drifts.

Coverage levels:

* ``enforced`` - on by default, in every policy and adapter;
* ``available`` - a built-in feature to switch on (a sanitizer, check or option);
* ``partial`` - covered in part; the document says what remains for the application;
* ``guidance`` - belongs to the application or the deployment; the document says how.

An item may instead point to another one (``see=``) that covers the same ground.

Update the document after editing: ``uv run python -m tests.owasp.registry --write``.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Coverage = Literal["enforced", "available", "partial", "guidance"]
LEVELS: tuple[Coverage, ...] = ("enforced", "available", "partial", "guidance")
#: Levels that need at least one test carrying ``@pytest.mark.owasp(id)``.
TESTED: frozenset[Coverage] = frozenset({"enforced", "available", "partial"})
DOC = Path(__file__).parents[2] / "docs" / "OWASP.md"


@dataclass(frozen=True)
class Item:
    id: str
    recommendation: str
    coverage: Coverage | None = None
    how: str = ""
    see: str | None = None  # the item this one repeats


@dataclass(frozen=True)
class Section:
    title: str
    items: tuple[Item, ...]


@dataclass(frozen=True)
class Source:
    key: str  # names the matrix block in docs/OWASP.md
    title: str
    url: str
    prefixes: frozenset[str]  # the first part of every item id of this source
    sections: tuple[Section, ...]


CHEAT_SHEET_SECTIONS: tuple[Section, ...] = (
    Section(
        "Introduction (core principles)",
        (
            Item(
                "intro.allowlist",
                "Allow only safe, business-critical extensions.",
                see="extension.allowlist",
            ),
            Item(
                "intro.input-first",
                "Apply input validation before validating extensions.",
                "enforced",
                "Checks run cheapest first: the name before a byte of content is "
                "inspected; Django refuses a bad name before a byte is stored.",
            ),
            Item(
                "intro.file-type",
                "Validate the file type; don't trust the Content-Type header.",
                see="content-type.untrusted",
            ),
            Item(
                "intro.generated-name",
                "Change the filename to one the application generates.",
                see="filename.generated",
            ),
            Item(
                "intro.filename-limits",
                "Set a filename length limit; restrict characters.",
                see="filename.max-length",
            ),
            Item("intro.size-limit", "Set a file size limit.", see="limits.upload-size"),
            Item(
                "intro.authorized-users",
                "Only allow authorized users to upload files.",
                see="permissions.authentication",
            ),
            Item(
                "intro.storage",
                "Store files on a different server, or outside the webroot.",
                see="storage.separate-host",
            ),
            Item(
                "intro.id-mapping",
                "Serve public files through a handler that maps IDs to files.",
                "guidance",
                "A download view looks files up by ID; `RandomizeFilename` keeps "
                "stored names unguessable.",
            ),
            Item(
                "intro.antivirus",
                "Run files through an antivirus or a sandbox.",
                see="content.malware-scan",
            ),
            Item("intro.cdr", "Run applicable files (PDF, DOCX) through CDR.", see="content.cdr"),
            Item(
                "intro.libraries",
                "Keep libraries securely configured and up to date.",
                "guidance",
                "Minimum dependency versions; Django system checks report missing "
                "optional dependencies (e.g. Pillow) instead of silently skipping checks.",
            ),
            Item(
                "intro.csrf",
                "Protect the file upload from CSRF attacks.",
                "guidance",
                "The framework's CSRF protection stays in charge: Django's runs before any file "
                "is inspected; nothing in uploadshield exempts a view.",
            ),
        ),
    ),
    Section(
        "File upload threats",
        (
            Item(
                "threat.parser-exploit",
                "Malicious files exploiting the parser (ImageTragick, XXE).",
                "enforced",
                "Only the format proven by the bytes reaches a decoder (Pillow is "
                "restricted to it); MVG, EPS & co. are never decoded; parser crashes are "
                "refusals; XML DTDs are refused.",
            ),
            Item(
                "threat.phishing",
                "Files used for phishing (e.g. via a careers form).",
                "partial",
                "Executables, scripts, HTML and macro documents are refused; social-engineering "
                "content in an allowed format cannot be detected.",
            ),
            Item(
                "threat.zip-bomb",
                "ZIP bombs filling storage or memory.",
                see="limits.decompressed-size",
            ),
            Item(
                "threat.xml-bomb",
                "XML bombs (billion laughs).",
                "enforced",
                "DTDs - which entity expansion needs - are refused in SVG, Office, ODF, EPUB and "
                "XML uploads; nothing is ever expanded.",
            ),
            Item("threat.huge-files", "Huge files filling storage.", see="limits.upload-size"),
            Item("threat.overwrite", "Overwriting an existing file.", see="filename.overwrite"),
            Item(
                "threat.client-side",
                "Client-side active content (XSS, CSRF) in public files.",
                "enforced",
                "HTML, SVG scripts, script polyglots and content under misleading "
                "extensions are refused; views receive the detected content type. Serve uploads "
                "with `nosniff` and `Content-Disposition` (see "
                "[What your application must do](#what-your-application-must-do)).",
            ),
            Item(
                "threat.disclosure",
                "Public retrieval: disclosure of other files.",
                "guidance",
                "Authorize downloads per file; random stored names are not guessable.",
            ),
            Item(
                "threat.download-dos",
                "Public retrieval: DoS by requesting many files.",
                see="limits.download-rate",
            ),
            Item(
                "threat.illegal-content",
                "Public retrieval: hosting illegal or copyrighted files.",
                see="content.reporting",
            ),
        ),
    ),
    Section(
        "Extension validation",
        (
            Item(
                "extension.decode-first",
                "Validate after decoding the filename.",
                "enforced",
                "Names are also judged percent-decoded (repeatedly) and NFKC-normalised, as "
                "storage, servers and Windows' best-fit mapping may read them.",
            ),
            Item(
                "extension.double",
                "Double extensions: `.jpg.php`.",
                "enforced",
                "Executable extensions are refused in any position, not only the last.",
            ),
            Item(
                "extension.null-byte",
                "Null bytes: `.php%00.jpg`.",
                "enforced",
                "Control characters are refused, also after percent-decoding.",
            ),
            Item(
                "extension.case",
                "Case manipulation: `.pHp`.",
                "enforced",
                "Extensions are compared case-insensitively.",
            ),
            Item(
                "extension.alternative",
                "Alternative extensions: `.phtml`, `.php5`, `.aspx`, `.jspx`.",
                "enforced",
                "`DANGEROUS_EXTENSIONS`: PHP, ASP/.NET, JSP, ColdFusion, SSI, CGI "
                "and Windows-executable extensions.",
            ),
            Item(
                "extension.ntfs-ads",
                "NTFS alternate data streams: `shell.asp:.jpg`; reject `:`.",
                "enforced",
                "Names containing `:` are refused.",
            ),
            Item(
                "extension.vetted-logic",
                "Avoid self-written regex; use vetted logic.",
                "enforced",
                "One maintained, property-tested implementation for every framework.",
            ),
            Item(
                "extension.allowlist",
                "List allowed extensions; only business-critical types.",
                "enforced",
                "Policies are allow-lists of content types; the extension must "
                "belong to the detected type; no preset contains executable or scriptable types.",
            ),
            Item(
                "extension.blocklist",
                "Blocklists are weak on their own; at most defense in depth.",
                "enforced",
                "The blocklist only complements the content allow-list, which decides.",
            ),
        ),
    ),
    Section(
        "Content-Type validation",
        (
            Item(
                "content-type.untrusted",
                "The Content-Type is user-supplied and cannot be trusted.",
                "enforced",
                "It is ignored; views receive the content type detected from the bytes.",
            ),
            Item(
                "content-type.quick-check",
                "Check it as a quick, allow-listed filter.",
                "available",
                "`Policy(match_declared_type=True)` refuses headers that contradict the content.",
            ),
        ),
    ),
    Section(
        "File signature validation",
        (
            Item(
                "signature.check",
                "Check the file signature against the expected type.",
                "enforced",
                "The built-in sniffer identifies formats by their structure.",
            ),
            Item(
                "signature.not-alone",
                "Don't rely on the signature alone; it is easy to fake.",
                "enforced",
                "Formats are decoded or parsed completely; valid headers on hostile "
                "bodies and polyglots are refused.",
            ),
        ),
    ),
    Section(
        "Filename safety",
        (
            Item(
                "filename.generated",
                "Generate the stored name (random string, UUID).",
                "available",
                "`RandomizeFilename` (part of `sanitized_images`) - recommended wherever possible.",
            ),
            Item(
                "filename.max-length",
                "Set a maximum name length.",
                "enforced",
                "255 bytes (UTF-8) by default, configurable.",
            ),
            Item(
                "filename.charset",
                "Restrict characters to e.g. alphanumerics, hyphen, space, period.",
                "available",
                "`SafeFilename` rewrites names to `[A-Za-z0-9_.- ]` with one "
                "extension matching the content.",
            ),
            Item(
                "filename.inform-users",
                "Tell users what an acceptable name looks like.",
                "enforced",
                "Every refusal carries a user-facing message (overridable per code).",
            ),
            Item(
                "filename.leading-period",
                "Refuse leading periods (hidden files).",
                "enforced",
                "Hidden names and server configuration files are refused.",
            ),
            Item(
                "filename.sequential-periods",
                "Refuse sequential periods (traversal).",
                "enforced",
                "`..` anywhere in a name is refused (`allow_consecutive_dots=True` to relax).",
            ),
            Item(
                "filename.leading-hyphen-space",
                "Refuse leading hyphens or spaces.",
                "enforced",
                "Protects shell-based processing from argument injection (`-rf.png`).",
            ),
            Item(
                "filename.dangerous-chars",
                "Otherwise blocklist characters that endanger the system.",
                "enforced",
                "Control and bidi characters, `/ \\ :` and the rest of Windows' "
                'forbidden `< > " | ? *`.',
            ),
            Item(
                "filename.reserved-names",
                "Respect platform naming rules (MSDN, Wikipedia).",
                "enforced",
                "Windows device names (`CON`, `COM1`, `COM\u00b9`), trailing dots "
                "and spaces, `.` and `..`.",
            ),
            Item(
                "filename.short-names",
                "Windows 8.3 short names can alias other files.",
                "enforced",
                "Names shaped like `WEBCON~1.CON` are refused; generated names "
                "remove the risk entirely.",
            ),
            Item(
                "filename.overwrite",
                "Generated names prevent overwriting existing files.",
                "available",
                "`RandomizeFilename`; Django storages never overwrite.",
            ),
        ),
    ),
    Section(
        "File content validation",
        (
            Item(
                "content.image-rewrite",
                "Rewrite images (decode and re-encode).",
                "available",
                "`ReencodeImage` (part of `sanitized_images`) destroys hidden payloads.",
            ),
            Item(
                "content.image-metadata",
                "Strip image metadata.",
                "available",
                "`ReencodeImage` drops EXIF (incl. GPS), XMP, comments and trailing bytes.",
            ),
            Item(
                "content.image-library",
                "Use an up-to-date library with restricted formats and resource limits.",
                "enforced",
                "Pillow decodes only the sniffed format, within pixel, frame and "
                "total-pixel limits, after checking the header.",
            ),
            Item(
                "content.office",
                "Validate Microsoft documents (e.g. with Apache POI).",
                "enforced",
                "OOXML/ODF/OLE2: macros, ActiveX, DDE, remote templates, XML DTDs, and archive "
                "safety of the container.",
            ),
            Item(
                "content.zip",
                "ZIP files are not recommended.",
                "enforced",
                "No preset accepts ZIP; policies that do get `ArchiveSafety`.",
            ),
            Item(
                "content.malware-scan",
                "Scan files for malware (e.g. hash services).",
                "available",
                "`ClamAV` (fails closed) and `YaraRules`; hash look-ups fit a custom `Check`.",
            ),
            Item(
                "content.scanner-leakage",
                "Beware of data leakage to public scanning services.",
                "guidance",
                "The built-in scanners run on your infrastructure.",
            ),
            Item(
                "content.sandbox-review",
                "Review files manually in a sandbox before release.",
                "guidance",
                "Signals and logs carry the SHA-256 and verdict for review queues.",
            ),
            Item(
                "content.reporting",
                "Let users report illegal content and abuse.",
                "guidance",
                "An application feature.",
            ),
            Item(
                "content.cdr",
                "Content Disarm & Reconstruct for PDF and DOCX.",
                "partial",
                "Images are reconstructed; PDF and Office files with active content are refused, "
                "not disarmed.",
            ),
        ),
    ),
    Section(
        "File storage location",
        (
            Item(
                "storage.separate-host",
                "Store files on a different host.",
                "guidance",
                "`ValidatingStorage` wraps any Django storage backend (S3, GCS, ...).",
            ),
            Item(
                "storage.outside-webroot",
                "Otherwise store them outside the webroot.",
                "guidance",
                "Keep `MEDIA_ROOT` / upload folders out of the web server's document root.",
            ),
            Item(
                "storage.write-only",
                "Inside the webroot: write-only, with controlled reads.",
                "guidance",
                "Serve through an authorizing view, not the static file server.",
            ),
            Item(
                "storage.database",
                "Databases only with a clear benefit and DBA support.",
                "guidance",
                "Out of scope.",
            ),
            Item(
                "storage.config-overrides",
                "Disable per-directory config (`.htaccess`, `web.config`).",
                "partial",
                "Configuration files are refused by name as a second layer; "
                "`AllowOverride None` is server configuration.",
            ),
            Item(
                "storage.unstored",
                "Files that are only processed (e.g. emailed) need the same checks.",
                "available",
                "`validate()` works without a framework; `ValidatingStorage` covers "
                "tasks and commands.",
            ),
        ),
    ),
    Section(
        "User permissions",
        (
            Item(
                "permissions.authentication",
                "Authenticate users before they can upload.",
                "guidance",
                "Authenticate first: Django's `LoginRequiredMiddleware` (after "
                "`AuthenticationMiddleware`) before `CsrfViewMiddleware`, Flask hooks before "
                "`UploadShield(app)`, FastAPI auth "
                "dependencies before `shield.all_files()` - then anonymous requests are never "
                "parsed or validated.",
            ),
            Item(
                "permissions.authorization",
                "Check that users may access or modify the files.",
                "guidance",
                "An application decision.",
            ),
        ),
    ),
    Section(
        "Filesystem permissions",
        (
            Item(
                "filesystem.least-privilege",
                "Least privilege: only allowed readers, minimal modes.",
                "guidance",
                "e.g. Django's `FILE_UPLOAD_PERMISSIONS = 0o640`; never executable.",
            ),
            Item(
                "filesystem.scan-before-execute",
                "Scan files for macros or scripts before any execution.",
                "enforced",
                "Executables, scripts, macros and embedded code are refused.",
            ),
        ),
    ),
    Section(
        "Upload and download limits",
        (
            Item(
                "limits.upload-size",
                "Set an upload size limit.",
                "enforced",
                "Per policy; Django aborts while streaming, plus `MAX_UPLOAD_SIZE` as a hard cap.",
            ),
            Item(
                "limits.decompressed-size",
                "Measure the size after decompression (secure ZIP size calculation).",
                "enforced",
                "ZIP members are inflated as streams and must match their declared size "
                "and CRC; compressed tar archives are measured while they decompress; "
                "nested archives share one budget.",
            ),
            Item(
                "limits.safe-extraction",
                "Extract safely (CERT IDS04-J).",
                "enforced",
                "Entry count, total size, zip slip, absolute paths, links, device files and "
                "encrypted members, in ZIP and tar archives.",
            ),
            Item(
                "limits.download-rate",
                "Rate-limit the download service.",
                "guidance",
                "Server, proxy or CDN configuration.",
            ),
        ),
    ),
)


UNRESTRICTED_UPLOAD_SECTIONS: tuple[Section, ...] = (
    Section(
        "Risk factors",
        (
            Item(
                "ufu.risk.web-shell",
                "A web shell uploaded and run on the server.",
                "enforced",
                "Scripts are refused by their content, executable extensions anywhere in the "
                "name, server configuration files by name.",
            ),
            Item(
                "ufu.risk.client-side",
                "Client-side attacks: XSS and cross-site content hijacking.",
                "enforced",
                "HTML, script SVG and polyglots are refused; so are Flash and "
                "Silverlight content, `.swf`/`.xap` names and `crossdomain.xml`/"
                "`clientaccesspolicy.xml`.",
            ),
            Item(
                "ufu.risk.library-flaws",
                "Flaws in libraries that process uploads (LibTIFF, "
                "ImageMagick, antivirus unpackers).",
                see="threat.parser-exploit",
            ),
            Item(
                "ufu.risk.admin-machines",
                "Malicious files run later on an administrator's "
                "machine (scripts, viruses, Excel formulas).",
                "enforced",
                "Executables and scripts are refused, and so are DDE links and formulas in Excel "
                "and CSV files; `ClamAV` scans for viruses.",
            ),
            Item(
                "ufu.risk.phishing",
                "Phishing pages or defacement planted on the site.",
                see="threat.phishing",
            ),
            Item(
                "ufu.risk.hosting",
                "The server hosts malware or illegal content.",
                see="content.malware-scan",
            ),
            Item(
                "ufu.risk.disclosure",
                "Sensitive uploads reachable by unauthorized people.",
                see="threat.disclosure",
            ),
            Item(
                "ufu.risk.error-messages",
                "Error messages reveal internal information such as server paths.",
                "enforced",
                "Clients get stable codes and fixed messages; "
                "exception texts and paths stay in the logs unless `EXPOSE_DETAILS` is on.",
            ),
            Item(
                "ufu.risk.access-control",
                "Examine the access controls of the upload module.",
                see="permissions.authentication",
            ),
        ),
    ),
    Section(
        "Examples",
        (
            Item(
                "ufu.example.jsp",
                "A `.jsp` file in the web tree runs as the web user.",
                "enforced",
                "Refused by its name and by its content: no allow-list contains "
                "server-side scripts.",
            ),
            Item(
                "ufu.example.image-resize",
                "A `.gif` sent for resizing exploits the image library.",
                see="content.image-library",
            ),
            Item("ufu.example.huge-file", "Huge files fill the disk.", see="limits.upload-size"),
            Item(
                "ufu.example.overwrite",
                "A malicious path or name overwrites a critical file.",
                "enforced",
                "Path and drive separators, `..`, reserved and configuration names and "
                "8.3 aliases are refused; `RandomizeFilename` replaces names entirely.",
            ),
            Item(
                "ufu.example.personal-data",
                "Personal data uploaded where other users can read it.",
                "guidance",
                "Authorize downloads; `ReencodeImage` strips EXIF and GPS data from images.",
            ),
            Item(
                "ufu.example.included-tags",
                "Tags that run when the file is included in a page (PHP `include`, SSI).",
                "enforced",
                "PHP, SSI, JSP and script markers are refused inside media, and PHP tags "
                "anywhere in text files (`include` runs them whatever the extension); PHP and "
                "HTML files are refused by type. (JSP, ASP and SSI source is accepted as plain "
                "text: no server runs it under a `.txt` name.)",
            ),
            Item(
                "ufu.example.antivirus-exploit",
                "A `.rar` that exploits the server's antivirus.",
                "enforced",
                "Types outside the allow-list are refused before any scanner sees them; "
                "no preset accepts archives.",
            ),
            Item(
                "ufu.example.trojan",
                "A trojaned `.exe` for visitors to download.",
                "enforced",
                "Executables are refused by content and by name.",
            ),
            Item("ufu.example.virus", "A virus-infected file.", see="content.malware-scan"),
            Item(
                "ufu.example.html-xss",
                "A `.html` file with script (XSS).",
                "enforced",
                "No preset allows HTML, and it is detected under any extension.",
            ),
            Item(
                "ufu.example.flash-in-jpg",
                "A `.jpg` that is a Flash object (content hijacking).",
                "enforced",
                "Formats are identified by their bytes, so Flash under an image name is refused.",
            ),
            Item(
                "ufu.example.client-antivirus",
                "A `.rar` that exploits visitors' antivirus.",
                see="content.zip",
            ),
        ),
    ),
    Section(
        "Weak protections: deny-listing extensions",
        (
            Item(
                "ufu.bypass.missed-extensions",
                "Missed extensions: `.php5`, `.pht`, `.phtml`, "
                "`.shtml`, `.asa`, `.cer`, `.asax`, `.swf`, `.xap`.",
                "enforced",
                "All are in `DANGEROUS_EXTENSIONS`; the content allow-list decides first anyway.",
            ),
            Item(
                "ufu.bypass.double-extension",
                "Double extensions and delimiters: `file.php.jpg`, `/file.jpg/index.php`.",
                "enforced",
                "Executable extensions are refused in any position; separators are refused.",
            ),
            Item(
                "ufu.bypass.iis-semicolon",
                "IIS: `file.asp;.jpg`, `folder.asp\\file.txt`.",
                "enforced",
                "`;` ends an extension segment; backslashes are refused.",
            ),
            Item(
                "ufu.bypass.ntfs-index",
                "NTFS `::$Index_Allocation` creates directories.",
                "enforced",
                "`:` is refused.",
            ),
            Item(
                "ufu.bypass.case",
                "Changed case: `file.aSp`, `file.PHp3`.",
                "enforced",
                "Extensions are compared case-insensitively.",
            ),
            Item(
                "ufu.bypass.short-names",
                "8.3 short names: `web~1.con`, `HTACCE~1`.",
                "enforced",
                "Names shaped like short-name aliases are refused.",
            ),
            Item(
                "ufu.bypass.wildcards",
                '`>`, `<` and `"` become wildcards on PHP/IIS.',
                "enforced",
                "All characters Windows forbids are refused.",
            ),
            Item(
                "ufu.bypass.trailing",
                "Trailing dots, spaces and slashes: `file.asp.`, `test.php/`.",
                "enforced",
                "Trailing dots and spaces and all slashes are refused.",
            ),
            Item(
                "ufu.bypass.multiple-dots",
                "Multiple dots: `file.txt.jpg.php`.",
                "enforced",
                "Every segment of the name is checked.",
            ),
            Item(
                "ufu.bypass.null-byte",
                "A null byte between extensions, raw or URL-encoded.",
                "enforced",
                "Control characters are refused, also after percent-decoding.",
            ),
            Item(
                "ufu.bypass.ads",
                "Alternate data streams: `file.asax:.jpg`, `file.asp::$data.`.",
                "enforced",
                "`:` is refused.",
            ),
            Item(
                "ufu.bypass.replacement",
                "Filters that delete strings: `file.p.phphp` becomes `file.php`.",
                "enforced",
                "Names are refused, never rewritten, and the extension must belong to the content.",
            ),
            Item(
                "ufu.bypass.later-use",
                "How the file is used later, e.g. PHP `include` of an image.",
                "enforced",
                "Code inside images is refused.",
            ),
            Item(
                "ufu.bypass.combined",
                "Combinations of these techniques.",
                "enforced",
                "Property-based tests combine extensions, case and percent-encoding.",
            ),
        ),
    ),
    Section(
        "Weak protections: getimagesize(), allow-lists, Content-Type, type detectors",
        (
            Item(
                "ufu.getimagesize.comment",
                "Code in the comment or metadata of a valid image (gifsicle).",
                "enforced",
                "`EmbeddedContent` scans media for code; "
                "`ReencodeImage` drops comments and metadata.",
            ),
            Item(
                "ufu.getimagesize.filesmatch",
                "An unanchored `FilesMatch` runs `output.php.gif` as PHP.",
                "enforced",
                "`.php` is refused in any position.",
            ),
            Item(
                "ufu.allowlist.dangerous-types",
                "Dangerous types on the allow-list (`.shtml` enables SSI).",
                "enforced",
                "Presets contain no script-capable types; `.shtml` is refused anywhere.",
            ),
            Item(
                "ufu.allowlist.full-name",
                "Validate the full name, not one extension.",
                "enforced",
                "Every segment of the name is checked.",
            ),
            Item(
                "ufu.content-type.proxy",
                "The Content-Type is changed with a proxy.",
                see="content-type.untrusted",
            ),
            Item(
                "ufu.detector.after-header",
                "Code after a valid header.",
                "enforced",
                "Formats are parsed completely; media and text are scanned to the end.",
            ),
            Item(
                "ufu.detector.comments",
                "Code in comments or other unused sections.",
                "enforced",
                "Media are scanned for code everywhere, not only where it would render.",
            ),
            Item(
                "ufu.detector.obfuscation",
                "Obfuscated or encoded payloads.",
                "partial",
                "In text, PHP open tags - including the short `<?` tag when code follows - are "
                "found in any case and with any whitespace; in media the short tag is left out "
                "(its bytes occur by chance in binary), and images can be rebuilt. A payload "
                "with no opening tag at all is not code by itself and is not flagged.",
            ),
            Item(
                "ufu.detector.decompression",
                "Files that produce code once decompressed or processed.",
                "enforced",
                "Archive members are measured and their names checked, PDF object streams "
                "are decoded (or refused when they cannot be), and sanitized output - content "
                "and name - is checked again.",
            ),
        ),
    ),
    Section(
        "Other test cases",
        (
            Item(
                "ufu.case.existing-names",
                "An existing file or folder name; watch the error messages.",
                "enforced",
                "Error responses carry no paths or exception texts; generated names never collide.",
            ),
            Item("ufu.case.long-names", "Very long names.", "enforced", "255 bytes at most."),
            Item(
                "ufu.case.concurrent",
                "The same file uploaded concurrently.",
                "enforced",
                "Validation is stateless and thread-safe.",
            ),
            Item(
                "ufu.case.compressed-xml",
                "Compressed or XML files that probe server-side processing.",
                "enforced",
                "No preset accepts archives or XML; where a policy does, "
                "bombs and DTDs are refused.",
            ),
            Item(
                "ufu.case.dot-names",
                "`.`, `..` and `...` as names.",
                "enforced",
                "Refused as reserved, hidden or ending in a dot.",
            ),
            Item(
                "ufu.case.ntfs-names",
                "NTFS names that are hard to delete, like `...:.jpg`.",
                "enforced",
                "Refused (`:`, leading dots).",
            ),
            Item(
                "ufu.case.windows-characters",
                'Characters Windows forbids: `|<>*?"`.',
                "enforced",
                "All are refused.",
            ),
            Item(
                "ufu.case.reserved-names",
                "Reserved names: CON, PRN, AUX, NUL, COM1-COM9, LPT1-LPT9.",
                "enforced",
                "All are refused, with any extension.",
            ),
            Item(
                "ufu.case.content-hijacking",
                "Flash, PDF or Silverlight content under an allowed extension.",
                "enforced",
                "Content must match the extension and the allow-list.",
            ),
            Item(
                "ufu.case.policy-files",
                "Uploading `crossdomain.xml` or `clientaccesspolicy.xml`.",
                "enforced",
                "Both names are refused under every policy.",
            ),
        ),
    ),
    Section(
        "Prevention methods",
        (
            Item(
                "ufu.prevent.necessary-types",
                "Allow only business-necessary file types.",
                see="extension.allowlist",
            ),
            Item(
                "ufu.prevent.validate-first",
                "Validate every file before it is available; discard it if in doubt.",
                "enforced",
                "Views and storage only receive files that "
                "passed; crashing checks and unreachable scanners are refusals.",
            ),
            Item(
                "ufu.prevent.extension-from-list",
                "Pick the extension from a list, not from the user.",
                "available",
                "`RandomizeFilename` and `SafeFilename` use an extension of the detected type.",
            ),
            Item(
                "ufu.prevent.strict-names",
                "Only alphanumerics and one dot (`^[a-zA-Z0-9]{1,200}\\.[a-zA-Z0-9]{1,10}$`).",
                "available",
                "`SafeFilename` keeps one extension and `[A-Za-z0-9_.- ]`; dangerous characters "
                "are refused outright.",
            ),
            Item("ufu.prevent.name-length", "Limit the name length.", see="filename.max-length"),
            Item(
                "ufu.prevent.generated-names",
                "Generate names (e.g. a hash).",
                see="filename.generated",
            ),
            Item(
                "ufu.prevent.no-execute",
                "Remove execute permission and script handlers from upload folders.",
                see="filesystem.least-privilege",
            ),
            Item(
                "ufu.prevent.size-limits",
                "Limit the maximum size, and consider a minimum.",
                "partial",
                "A maximum per policy; empty files are refused, but there is no larger minimum.",
            ),
            Item("ufu.prevent.csrf", "Use CSRF protection.", see="intro.csrf"),
            Item(
                "ufu.prevent.same-hash",
                "Prevent overwriting files that have the same hash.",
                "guidance",
                "Results, logs and signals carry the SHA-256 to deduplicate on.",
            ),
            Item(
                "ufu.prevent.virus-scan",
                "Scan uploads with a virus scanner.",
                see="content.malware-scan",
            ),
            Item(
                "ufu.prevent.post-only",
                "Use POST rather than PUT or GET.",
                "guidance",
                "Restrict the methods of your routes; uploadshield validates multipart bodies of "
                "any method.",
            ),
            Item(
                "ufu.prevent.logging",
                "Log activity; protect the logs against forgery and injection.",
                "enforced",
                "Every refusal is logged with structured data; field and file names are "
                "logged escaped, so control characters cannot forge log lines.",
            ),
            Item(
                "ufu.prevent.archive-members",
                "Check each file inside an archive individually.",
                "partial",
                "Every member's size, path and name (and CRC in ZIP) is checked, in ZIP and "
                "tar archives and in nested ones; member contents are not validated against "
                "a policy.",
            ),
            Item(
                "ufu.prevent.database",
                "Consider storing files in a database.",
                see="storage.database",
            ),
            Item(
                "ufu.prevent.separate-domain",
                "Serve uploads from an isolated server on a separate domain.",
                "guidance",
                "Deployment.",
            ),
            Item(
                "ufu.prevent.authorized-uploaders",
                "Only authenticated, authorized users upload.",
                see="permissions.authentication",
            ),
            Item(
                "ufu.prevent.write-permissions",
                "Remove write permissions from other folders.",
                see="filesystem.least-privilege",
            ),
            Item(
                "ufu.prevent.config-files",
                "Keep `.htaccess` and `web.config` from being replaced, and ignore them.",
                see="storage.config-overrides",
            ),
            Item(
                "ufu.prevent.double-extensions",
                "Prevent execution of double-extension files (Apache).",
                see="extension.double",
            ),
            Item(
                "ufu.prevent.access",
                "Keep uploads away from unauthorized users.",
                see="permissions.authorization",
            ),
            Item(
                "ufu.prevent.download-headers",
                "Send `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.",
                "guidance",
                "See [What your application must do](#what-your-application-must-do).",
            ),
            Item(
                "ufu.prevent.policy-files",
                "Remove unused `crossdomain.xml`/"
                "`clientaccesspolicy.xml`, and don't let browsers cache them.",
                "partial",
                "Uploads under these names are refused; existing files and caching are server "
                "configuration.",
            ),
            Item(
                "ufu.prevent.cors",
                "Allow only authorized origins in CORS headers.",
                "guidance",
                "Server or framework configuration.",
            ),
            Item(
                "ufu.prevent.iis",
                "Follow Microsoft's IIS hardening guidance.",
                "guidance",
                "Server configuration.",
            ),
        ),
    ),
)

CHEAT_SHEET = Source(
    "cheat-sheet",
    "OWASP File Upload Cheat Sheet",
    "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
    frozenset(
        {
            "intro",
            "threat",
            "extension",
            "content-type",
            "signature",
            "filename",
            "content",
            "storage",
            "permissions",
            "filesystem",
            "limits",
        }
    ),
    CHEAT_SHEET_SECTIONS,
)
UNRESTRICTED_UPLOAD = Source(
    "unrestricted-upload",
    "OWASP Unrestricted File Upload",
    "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
    frozenset({"ufu"}),
    UNRESTRICTED_UPLOAD_SECTIONS,
)
SOURCES: tuple[Source, ...] = (CHEAT_SHEET, UNRESTRICTED_UPLOAD)
ITEMS: dict[str, Item] = {
    item.id: item for source in SOURCES for section in source.sections for item in section.items
}


def coverage(item_id: str) -> Coverage:
    """The coverage of an item, following ``see`` references."""
    item = ITEMS[item_id]
    while item.see is not None:
        item = ITEMS[item.see]
    assert item.coverage is not None, item.id
    return item.coverage


def _cell(text: str) -> str:
    return text.replace("|", "\\|")  # GitHub splits table cells at "|", even in code spans


def render(source: Source) -> str:
    """The coverage matrix of one source, as it appears in ``docs/OWASP.md``."""
    out: list[str] = []
    for section in source.sections:
        out += [f"### {section.title}", "", "| ID | OWASP | Coverage | uploadshield |",
                "|---|---|---|---|"]  # fmt: skip
        for item in section.items:
            level = f"see `{item.see}`" if item.see else f"**{item.coverage}**"
            out.append(
                f"| `{item.id}` | {_cell(item.recommendation)} | {level} | {_cell(item.how)} |"
            )
        out.append("")
    items = [item for section in source.sections for item in section.items]
    totals = dict.fromkeys(LEVELS, 0)
    for item in items:
        if item.see is None:
            totals[coverage(item.id)] += 1
    summary = ", ".join(f"{count} {level}" for level, count in totals.items())
    shared = sum(1 for item in items if item.see is not None)
    out.append(f"*{len(items)} items: {summary}; {shared} covered by another item.*")
    return "\n".join(out)


def _markers(source: Source) -> tuple[str, str]:
    return f"<!-- matrix:{source.key}:start -->", f"<!-- matrix:{source.key}:end -->"


def documented(source: Source) -> str:
    start, end = _markers(source)
    match = re.search(f"{re.escape(start)}\n(.*)\n{re.escape(end)}", DOC.read_text(), re.DOTALL)
    return match.group(1) if match else ""


def write() -> None:
    text = DOC.read_text()
    for source in SOURCES:
        start, end = _markers(source)
        before, rest = text.split(start, 1)
        _, after = rest.split(end, 1)
        text = f"{before}{start}\n{render(source)}\n{end}{after}"
    DOC.write_text(text)


if __name__ == "__main__":
    if "--write" in sys.argv:
        write()
    else:
        for source in SOURCES:
            print(f"## {source.title}\n\n{render(source)}\n")
