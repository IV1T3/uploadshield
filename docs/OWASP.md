# OWASP coverage

This document maps OWASP's two documents on file uploads to what uploadshield does
about them:

- the [File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html),
  OWASP's recommendations for building upload features; and
- the [Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
  vulnerability page, with its attack examples, ways around weak protections, and test
  cases.

Every recommendation and test case has a stable ID you can refer to, a coverage level
and, where the library covers it, tests that prove it.

Last checked against both documents on 2026-11-09.

| Coverage | Meaning |
|---|---|
| **enforced** | On by default, in every policy and in the Django, Flask and FastAPI adapters. |
| **available** | A built-in feature you switch on: a sanitizer, a check or an option. |
| **partial** | Covered in part. The matrix says what remains for the application. |
| **guidance** | Belongs to the application or the deployment. See [What your application must do](#what-your-application-must-do). |
| see `<id>` | Covered by another item, usually one of the cheat sheet's. |

## What your application must do

An upload library cannot do the following for you:

- **Authenticate first.** Then anonymous requests are never parsed or validated:
  - Django: put `LoginRequiredMiddleware` (5.1+) or your own before `CsrfViewMiddleware`,
    with `AuthenticationMiddleware` above both.
  - Flask: register authentication `before_request` hooks before `UploadShield(app)`.
  - FastAPI: list the authentication dependency first, app-wide
    (`FastAPI(dependencies=[Depends(auth), Depends(shield.all_files())])`) and in each
    endpoint's signature, before its `shield.file()` parameter. FastAPI parses the form
    before any dependency runs, so cap request sizes at the server.
- **Authorize** every download and modification per file.
- **Accept uploads with `POST` only.** uploadshield validates multipart bodies of any
  method, but routes should not offer more than they need.
- **Store uploads away from the web root**, ideally on another host. `ValidatingStorage`
  wraps any Django storage backend (S3, GCS, ...). Never let the web server execute or
  configure anything in an upload directory (`AllowOverride None`, no handler mappings).
- **Serve uploads defensively.** Use a view that maps IDs to files, with
  `Content-Disposition: attachment` for anything that is not an image or PDF meant for
  display, `X-Content-Type-Options: nosniff`, and the detected content type. A separate
  domain for user content is better still.
- **Review cross-origin settings.** Allow only the origins you need in CORS headers, and
  remove unused `crossdomain.xml` and `clientaccesspolicy.xml` files.
- **Generate stored names.** Use `RandomizeFilename` (part of `sanitized_images`)
  wherever users do not need their own names back. To avoid storing the same file
  twice, deduplicate on the SHA-256 that results and signals carry.
- **Least privilege on disk.** For example `FILE_UPLOAD_PERMISSIONS = 0o640`; uploads are
  never executable, and no other folder is writable.
- **Rate-limit downloads** at the server, proxy or CDN, and set request size limits in
  front of Flask and FastAPI, which receive the whole body before validating.
- **Let users report abuse**, and route suspicious files to review. Signals and logs
  carry the SHA-256 and the verdict.
- **Keep dependencies current** (Pillow above all). Django's system checks report missing
  optional dependencies instead of silently skipping checks.
- **Disarm documents** with a dedicated CDR product if you must accept active PDF or
  Office content. uploadshield refuses such content instead.

## Beyond the OWASP documents

uploadshield also covers threats neither document names: polyglots (GIFAR,
PDF-in-JPEG), PDF JavaScript, launch actions and embedded files (including `#xx`
obfuscation and compressed object streams), SVG scripts and external references, bidi
override names, macro-enabled Office types disguised as plain ones, encrypted archives
and PDFs (which cannot be inspected), and scripts disguised as CSV (opt-in
`MagikaCheck`). A report mode lets you roll all of it out without blocking anyone.

## File Upload Cheat Sheet

<!-- matrix:cheat-sheet:start -->
### Introduction (core principles)

| ID | OWASP | Coverage | uploadshield |
|---|---|---|---|
| `intro.allowlist` | Allow only safe, business-critical extensions. | see `extension.allowlist` |  |
| `intro.input-first` | Apply input validation before validating extensions. | **enforced** | Checks run cheapest first: the name before a byte of content is inspected; Django refuses a bad name before a byte is stored. |
| `intro.file-type` | Validate the file type; don't trust the Content-Type header. | see `content-type.untrusted` |  |
| `intro.generated-name` | Change the filename to one the application generates. | see `filename.generated` |  |
| `intro.filename-limits` | Set a filename length limit; restrict characters. | see `filename.max-length` |  |
| `intro.size-limit` | Set a file size limit. | see `limits.upload-size` |  |
| `intro.authorized-users` | Only allow authorized users to upload files. | see `permissions.authentication` |  |
| `intro.storage` | Store files on a different server, or outside the webroot. | see `storage.separate-host` |  |
| `intro.id-mapping` | Serve public files through a handler that maps IDs to files. | **guidance** | A download view looks files up by ID; `RandomizeFilename` keeps stored names unguessable. |
| `intro.antivirus` | Run files through an antivirus or a sandbox. | see `content.malware-scan` |  |
| `intro.cdr` | Run applicable files (PDF, DOCX) through CDR. | see `content.cdr` |  |
| `intro.libraries` | Keep libraries securely configured and up to date. | **guidance** | Minimum dependency versions; Django system checks report missing optional dependencies (e.g. Pillow) instead of silently skipping checks. |
| `intro.csrf` | Protect the file upload from CSRF attacks. | **guidance** | The framework's CSRF protection stays in charge: Django's runs before any file is inspected; nothing in uploadshield exempts a view. |

### File upload threats

| ID | OWASP | Coverage | uploadshield |
|---|---|---|---|
| `threat.parser-exploit` | Malicious files exploiting the parser (ImageTragick, XXE). | **enforced** | Only the format proven by the bytes reaches a decoder (Pillow is restricted to it); MVG, EPS & co. are never decoded; parser crashes are refusals; XML DTDs are refused. |
| `threat.phishing` | Files used for phishing (e.g. via a careers form). | **partial** | Executables, scripts, HTML and macro documents are refused; social-engineering content in an allowed format cannot be detected. |
| `threat.zip-bomb` | ZIP bombs filling storage or memory. | see `limits.decompressed-size` |  |
| `threat.xml-bomb` | XML bombs (billion laughs). | **enforced** | DTDs - which entity expansion needs - are refused in SVG, Office, ODF, EPUB and XML uploads; nothing is ever expanded. |
| `threat.huge-files` | Huge files filling storage. | see `limits.upload-size` |  |
| `threat.overwrite` | Overwriting an existing file. | see `filename.overwrite` |  |
| `threat.client-side` | Client-side active content (XSS, CSRF) in public files. | **enforced** | HTML, SVG scripts, script polyglots and content under misleading extensions are refused; views receive the detected content type. Serve uploads with `nosniff` and `Content-Disposition` (see [What your application must do](#what-your-application-must-do)). |
| `threat.disclosure` | Public retrieval: disclosure of other files. | **guidance** | Authorize downloads per file; random stored names are not guessable. |
| `threat.download-dos` | Public retrieval: DoS by requesting many files. | see `limits.download-rate` |  |
| `threat.illegal-content` | Public retrieval: hosting illegal or copyrighted files. | see `content.reporting` |  |

### Extension validation

| ID | OWASP | Coverage | uploadshield |
|---|---|---|---|
| `extension.decode-first` | Validate after decoding the filename. | **enforced** | Names are also judged percent-decoded (repeatedly) and NFKC-normalised, as storage, servers and Windows' best-fit mapping may read them. |
| `extension.double` | Double extensions: `.jpg.php`. | **enforced** | Executable extensions are refused in any position, not only the last. |
| `extension.null-byte` | Null bytes: `.php%00.jpg`. | **enforced** | Control characters are refused, also after percent-decoding. |
| `extension.case` | Case manipulation: `.pHp`. | **enforced** | Extensions are compared case-insensitively. |
| `extension.alternative` | Alternative extensions: `.phtml`, `.php5`, `.aspx`, `.jspx`. | **enforced** | `DANGEROUS_EXTENSIONS`: PHP, ASP/.NET, JSP, ColdFusion, SSI, CGI and Windows-executable extensions. |
| `extension.ntfs-ads` | NTFS alternate data streams: `shell.asp:.jpg`; reject `:`. | **enforced** | Names containing `:` are refused. |
| `extension.vetted-logic` | Avoid self-written regex; use vetted logic. | **enforced** | One maintained, property-tested implementation for every framework. |
| `extension.allowlist` | List allowed extensions; only business-critical types. | **enforced** | Policies are allow-lists of content types; the extension must belong to the detected type; no preset contains executable or scriptable types. |
| `extension.blocklist` | Blocklists are weak on their own; at most defense in depth. | **enforced** | The blocklist only complements the content allow-list, which decides. |

### Content-Type validation

| ID | OWASP | Coverage | uploadshield |
|---|---|---|---|
| `content-type.untrusted` | The Content-Type is user-supplied and cannot be trusted. | **enforced** | It is ignored; views receive the content type detected from the bytes. |
| `content-type.quick-check` | Check it as a quick, allow-listed filter. | **available** | `Policy(match_declared_type=True)` refuses headers that contradict the content. |

### File signature validation

| ID | OWASP | Coverage | uploadshield |
|---|---|---|---|
| `signature.check` | Check the file signature against the expected type. | **enforced** | The built-in sniffer identifies formats by their structure. |
| `signature.not-alone` | Don't rely on the signature alone; it is easy to fake. | **enforced** | Formats are decoded or parsed completely; valid headers on hostile bodies and polyglots are refused. |

### Filename safety

| ID | OWASP | Coverage | uploadshield |
|---|---|---|---|
| `filename.generated` | Generate the stored name (random string, UUID). | **available** | `RandomizeFilename` (part of `sanitized_images`) - recommended wherever possible. |
| `filename.max-length` | Set a maximum name length. | **enforced** | 255 bytes (UTF-8) by default, configurable. |
| `filename.charset` | Restrict characters to e.g. alphanumerics, hyphen, space, period. | **available** | `SafeFilename` rewrites names to `[A-Za-z0-9_.- ]` with one extension matching the content. |
| `filename.inform-users` | Tell users what an acceptable name looks like. | **enforced** | Every refusal carries a user-facing message (overridable per code). |
| `filename.leading-period` | Refuse leading periods (hidden files). | **enforced** | Hidden names and server configuration files are refused. |
| `filename.sequential-periods` | Refuse sequential periods (traversal). | **enforced** | `..` anywhere in a name is refused (`allow_consecutive_dots=True` to relax). |
| `filename.leading-hyphen-space` | Refuse leading hyphens or spaces. | **enforced** | Protects shell-based processing from argument injection (`-rf.png`). |
| `filename.dangerous-chars` | Otherwise blocklist characters that endanger the system. | **enforced** | Control and bidi characters, `/ \ :` and the rest of Windows' forbidden `< > " \| ? *`. |
| `filename.reserved-names` | Respect platform naming rules (MSDN, Wikipedia). | **enforced** | Windows device names (`CON`, `COM1`, `COM¹`), trailing dots and spaces, `.` and `..`. |
| `filename.short-names` | Windows 8.3 short names can alias other files. | **enforced** | Names shaped like `WEBCON~1.CON` are refused; generated names remove the risk entirely. |
| `filename.overwrite` | Generated names prevent overwriting existing files. | **available** | `RandomizeFilename`; Django storages never overwrite. |

### File content validation

| ID | OWASP | Coverage | uploadshield |
|---|---|---|---|
| `content.image-rewrite` | Rewrite images (decode and re-encode). | **available** | `ReencodeImage` (part of `sanitized_images`) destroys hidden payloads. |
| `content.image-metadata` | Strip image metadata. | **available** | `ReencodeImage` drops EXIF (incl. GPS), XMP, comments and trailing bytes. |
| `content.image-library` | Use an up-to-date library with restricted formats and resource limits. | **enforced** | Pillow decodes only the sniffed format, within pixel, frame and total-pixel limits, after checking the header. |
| `content.office` | Validate Microsoft documents (e.g. with Apache POI). | **enforced** | OOXML/ODF/OLE2: macros, ActiveX, DDE, remote templates, XML DTDs, and archive safety of the container. |
| `content.zip` | ZIP files are not recommended. | **enforced** | No preset accepts ZIP; policies that do get `ArchiveSafety`. |
| `content.malware-scan` | Scan files for malware (e.g. hash services). | **available** | `ClamAV` (fails closed) and `YaraRules`; hash look-ups fit a custom `Check`. |
| `content.scanner-leakage` | Beware of data leakage to public scanning services. | **guidance** | The built-in scanners run on your infrastructure. |
| `content.sandbox-review` | Review files manually in a sandbox before release. | **guidance** | Signals and logs carry the SHA-256 and verdict for review queues. |
| `content.reporting` | Let users report illegal content and abuse. | **guidance** | An application feature. |
| `content.cdr` | Content Disarm & Reconstruct for PDF and DOCX. | **partial** | Images are reconstructed; PDF and Office files with active content are refused, not disarmed. |

### File storage location

| ID | OWASP | Coverage | uploadshield |
|---|---|---|---|
| `storage.separate-host` | Store files on a different host. | **guidance** | `ValidatingStorage` wraps any Django storage backend (S3, GCS, ...). |
| `storage.outside-webroot` | Otherwise store them outside the webroot. | **guidance** | Keep `MEDIA_ROOT` / upload folders out of the web server's document root. |
| `storage.write-only` | Inside the webroot: write-only, with controlled reads. | **guidance** | Serve through an authorizing view, not the static file server. |
| `storage.database` | Databases only with a clear benefit and DBA support. | **guidance** | Out of scope. |
| `storage.config-overrides` | Disable per-directory config (`.htaccess`, `web.config`). | **partial** | Configuration files are refused by name as a second layer; `AllowOverride None` is server configuration. |
| `storage.unstored` | Files that are only processed (e.g. emailed) need the same checks. | **available** | `validate()` works without a framework; `ValidatingStorage` covers tasks and commands. |

### User permissions

| ID | OWASP | Coverage | uploadshield |
|---|---|---|---|
| `permissions.authentication` | Authenticate users before they can upload. | **guidance** | Authenticate first: Django's `LoginRequiredMiddleware` (after `AuthenticationMiddleware`) before `CsrfViewMiddleware`, Flask hooks before `UploadShield(app)`, FastAPI auth dependencies before `shield.all_files()` - then anonymous requests are never parsed or validated. |
| `permissions.authorization` | Check that users may access or modify the files. | **guidance** | An application decision. |

### Filesystem permissions

| ID | OWASP | Coverage | uploadshield |
|---|---|---|---|
| `filesystem.least-privilege` | Least privilege: only allowed readers, minimal modes. | **guidance** | e.g. Django's `FILE_UPLOAD_PERMISSIONS = 0o640`; never executable. |
| `filesystem.scan-before-execute` | Scan files for macros or scripts before any execution. | **enforced** | Executables, scripts, macros and embedded code are refused. |

### Upload and download limits

| ID | OWASP | Coverage | uploadshield |
|---|---|---|---|
| `limits.upload-size` | Set an upload size limit. | **enforced** | Per policy; Django aborts while streaming, plus `MAX_UPLOAD_SIZE` as a hard cap. |
| `limits.decompressed-size` | Measure the size after decompression (secure ZIP size calculation). | **enforced** | ZIP members are inflated as streams and must match their declared size and CRC; compressed tar archives are measured while they decompress; nested archives share one budget. |
| `limits.safe-extraction` | Extract safely (CERT IDS04-J). | **enforced** | Entry count, total size, zip slip, absolute paths, links, device files and encrypted members, in ZIP and tar archives. |
| `limits.download-rate` | Rate-limit the download service. | **guidance** | Server, proxy or CDN configuration. |

*71 items: 31 enforced, 8 available, 3 partial, 15 guidance; 14 covered by another item.*
<!-- matrix:cheat-sheet:end -->

## Unrestricted File Upload

The page lists risks, attack examples, ways around weak protections such as extension
deny-lists, `getimagesize()` and type detectors, further test cases, and prevention
methods. Every test case it names is attempted, with the page's own file names and
payloads, against the engine and against Django, Flask and FastAPI.

<!-- matrix:unrestricted-upload:start -->
### Risk factors

| ID | OWASP | Coverage | uploadshield |
|---|---|---|---|
| `ufu.risk.web-shell` | A web shell uploaded and run on the server. | **enforced** | Scripts are refused by their content, executable extensions anywhere in the name, server configuration files by name. |
| `ufu.risk.client-side` | Client-side attacks: XSS and cross-site content hijacking. | **enforced** | HTML, script SVG and polyglots are refused; so are Flash and Silverlight content, `.swf`/`.xap` names and `crossdomain.xml`/`clientaccesspolicy.xml`. |
| `ufu.risk.library-flaws` | Flaws in libraries that process uploads (LibTIFF, ImageMagick, antivirus unpackers). | see `threat.parser-exploit` |  |
| `ufu.risk.admin-machines` | Malicious files run later on an administrator's machine (scripts, viruses, Excel formulas). | **enforced** | Executables and scripts are refused, and so are DDE links and formulas in Excel and CSV files; `ClamAV` scans for viruses. |
| `ufu.risk.phishing` | Phishing pages or defacement planted on the site. | see `threat.phishing` |  |
| `ufu.risk.hosting` | The server hosts malware or illegal content. | see `content.malware-scan` |  |
| `ufu.risk.disclosure` | Sensitive uploads reachable by unauthorized people. | see `threat.disclosure` |  |
| `ufu.risk.error-messages` | Error messages reveal internal information such as server paths. | **enforced** | Clients get stable codes and fixed messages; exception texts and paths stay in the logs unless `EXPOSE_DETAILS` is on. |
| `ufu.risk.access-control` | Examine the access controls of the upload module. | see `permissions.authentication` |  |

### Examples

| ID | OWASP | Coverage | uploadshield |
|---|---|---|---|
| `ufu.example.jsp` | A `.jsp` file in the web tree runs as the web user. | **enforced** | Refused by its name and by its content: no allow-list contains server-side scripts. |
| `ufu.example.image-resize` | A `.gif` sent for resizing exploits the image library. | see `content.image-library` |  |
| `ufu.example.huge-file` | Huge files fill the disk. | see `limits.upload-size` |  |
| `ufu.example.overwrite` | A malicious path or name overwrites a critical file. | **enforced** | Path and drive separators, `..`, reserved and configuration names and 8.3 aliases are refused; `RandomizeFilename` replaces names entirely. |
| `ufu.example.personal-data` | Personal data uploaded where other users can read it. | **guidance** | Authorize downloads; `ReencodeImage` strips EXIF and GPS data from images. |
| `ufu.example.included-tags` | Tags that run when the file is included in a page (PHP `include`, SSI). | **enforced** | PHP, SSI, JSP and script markers are refused inside media, and PHP tags anywhere in text files (`include` runs them whatever the extension); PHP and HTML files are refused by type. (JSP, ASP and SSI source is accepted as plain text: no server runs it under a `.txt` name.) |
| `ufu.example.antivirus-exploit` | A `.rar` that exploits the server's antivirus. | **enforced** | Types outside the allow-list are refused before any scanner sees them; no preset accepts archives. |
| `ufu.example.trojan` | A trojaned `.exe` for visitors to download. | **enforced** | Executables are refused by content and by name. |
| `ufu.example.virus` | A virus-infected file. | see `content.malware-scan` |  |
| `ufu.example.html-xss` | A `.html` file with script (XSS). | **enforced** | No preset allows HTML, and it is detected under any extension. |
| `ufu.example.flash-in-jpg` | A `.jpg` that is a Flash object (content hijacking). | **enforced** | Formats are identified by their bytes, so Flash under an image name is refused. |
| `ufu.example.client-antivirus` | A `.rar` that exploits visitors' antivirus. | see `content.zip` |  |

### Weak protections: deny-listing extensions

| ID | OWASP | Coverage | uploadshield |
|---|---|---|---|
| `ufu.bypass.missed-extensions` | Missed extensions: `.php5`, `.pht`, `.phtml`, `.shtml`, `.asa`, `.cer`, `.asax`, `.swf`, `.xap`. | **enforced** | All are in `DANGEROUS_EXTENSIONS`; the content allow-list decides first anyway. |
| `ufu.bypass.double-extension` | Double extensions and delimiters: `file.php.jpg`, `/file.jpg/index.php`. | **enforced** | Executable extensions are refused in any position; separators are refused. |
| `ufu.bypass.iis-semicolon` | IIS: `file.asp;.jpg`, `folder.asp\file.txt`. | **enforced** | `;` ends an extension segment; backslashes are refused. |
| `ufu.bypass.ntfs-index` | NTFS `::$Index_Allocation` creates directories. | **enforced** | `:` is refused. |
| `ufu.bypass.case` | Changed case: `file.aSp`, `file.PHp3`. | **enforced** | Extensions are compared case-insensitively. |
| `ufu.bypass.short-names` | 8.3 short names: `web~1.con`, `HTACCE~1`. | **enforced** | Names shaped like short-name aliases are refused. |
| `ufu.bypass.wildcards` | `>`, `<` and `"` become wildcards on PHP/IIS. | **enforced** | All characters Windows forbids are refused. |
| `ufu.bypass.trailing` | Trailing dots, spaces and slashes: `file.asp.`, `test.php/`. | **enforced** | Trailing dots and spaces and all slashes are refused. |
| `ufu.bypass.multiple-dots` | Multiple dots: `file.txt.jpg.php`. | **enforced** | Every segment of the name is checked. |
| `ufu.bypass.null-byte` | A null byte between extensions, raw or URL-encoded. | **enforced** | Control characters are refused, also after percent-decoding. |
| `ufu.bypass.ads` | Alternate data streams: `file.asax:.jpg`, `file.asp::$data.`. | **enforced** | `:` is refused. |
| `ufu.bypass.replacement` | Filters that delete strings: `file.p.phphp` becomes `file.php`. | **enforced** | Names are refused, never rewritten, and the extension must belong to the content. |
| `ufu.bypass.later-use` | How the file is used later, e.g. PHP `include` of an image. | **enforced** | Code inside images is refused. |
| `ufu.bypass.combined` | Combinations of these techniques. | **enforced** | Property-based tests combine extensions, case and percent-encoding. |

### Weak protections: getimagesize(), allow-lists, Content-Type, type detectors

| ID | OWASP | Coverage | uploadshield |
|---|---|---|---|
| `ufu.getimagesize.comment` | Code in the comment or metadata of a valid image (gifsicle). | **enforced** | `EmbeddedContent` scans media for code; `ReencodeImage` drops comments and metadata. |
| `ufu.getimagesize.filesmatch` | An unanchored `FilesMatch` runs `output.php.gif` as PHP. | **enforced** | `.php` is refused in any position. |
| `ufu.allowlist.dangerous-types` | Dangerous types on the allow-list (`.shtml` enables SSI). | **enforced** | Presets contain no script-capable types; `.shtml` is refused anywhere. |
| `ufu.allowlist.full-name` | Validate the full name, not one extension. | **enforced** | Every segment of the name is checked. |
| `ufu.content-type.proxy` | The Content-Type is changed with a proxy. | see `content-type.untrusted` |  |
| `ufu.detector.after-header` | Code after a valid header. | **enforced** | Formats are parsed completely; media and text are scanned to the end. |
| `ufu.detector.comments` | Code in comments or other unused sections. | **enforced** | Media are scanned for code everywhere, not only where it would render. |
| `ufu.detector.obfuscation` | Obfuscated or encoded payloads. | **partial** | In text, PHP open tags - including the short `<?` tag when code follows - are found in any case and with any whitespace; in media the short tag is left out (its bytes occur by chance in binary), and images can be rebuilt. A payload with no opening tag at all is not code by itself and is not flagged. |
| `ufu.detector.decompression` | Files that produce code once decompressed or processed. | **enforced** | Archive members are measured and their names checked, PDF object streams are decoded (or refused when they cannot be), and sanitized output - content and name - is checked again. |

### Other test cases

| ID | OWASP | Coverage | uploadshield |
|---|---|---|---|
| `ufu.case.existing-names` | An existing file or folder name; watch the error messages. | **enforced** | Error responses carry no paths or exception texts; generated names never collide. |
| `ufu.case.long-names` | Very long names. | **enforced** | 255 bytes at most. |
| `ufu.case.concurrent` | The same file uploaded concurrently. | **enforced** | Validation is stateless and thread-safe. |
| `ufu.case.compressed-xml` | Compressed or XML files that probe server-side processing. | **enforced** | No preset accepts archives or XML; where a policy does, bombs and DTDs are refused. |
| `ufu.case.dot-names` | `.`, `..` and `...` as names. | **enforced** | Refused as reserved, hidden or ending in a dot. |
| `ufu.case.ntfs-names` | NTFS names that are hard to delete, like `...:.jpg`. | **enforced** | Refused (`:`, leading dots). |
| `ufu.case.windows-characters` | Characters Windows forbids: `\|<>*?"`. | **enforced** | All are refused. |
| `ufu.case.reserved-names` | Reserved names: CON, PRN, AUX, NUL, COM1-COM9, LPT1-LPT9. | **enforced** | All are refused, with any extension. |
| `ufu.case.content-hijacking` | Flash, PDF or Silverlight content under an allowed extension. | **enforced** | Content must match the extension and the allow-list. |
| `ufu.case.policy-files` | Uploading `crossdomain.xml` or `clientaccesspolicy.xml`. | **enforced** | Both names are refused under every policy. |

### Prevention methods

| ID | OWASP | Coverage | uploadshield |
|---|---|---|---|
| `ufu.prevent.necessary-types` | Allow only business-necessary file types. | see `extension.allowlist` |  |
| `ufu.prevent.validate-first` | Validate every file before it is available; discard it if in doubt. | **enforced** | Views and storage only receive files that passed; crashing checks and unreachable scanners are refusals. |
| `ufu.prevent.extension-from-list` | Pick the extension from a list, not from the user. | **available** | `RandomizeFilename` and `SafeFilename` use an extension of the detected type. |
| `ufu.prevent.strict-names` | Only alphanumerics and one dot (`^[a-zA-Z0-9]{1,200}\.[a-zA-Z0-9]{1,10}$`). | **available** | `SafeFilename` keeps one extension and `[A-Za-z0-9_.- ]`; dangerous characters are refused outright. |
| `ufu.prevent.name-length` | Limit the name length. | see `filename.max-length` |  |
| `ufu.prevent.generated-names` | Generate names (e.g. a hash). | see `filename.generated` |  |
| `ufu.prevent.no-execute` | Remove execute permission and script handlers from upload folders. | see `filesystem.least-privilege` |  |
| `ufu.prevent.size-limits` | Limit the maximum size, and consider a minimum. | **partial** | A maximum per policy; empty files are refused, but there is no larger minimum. |
| `ufu.prevent.csrf` | Use CSRF protection. | see `intro.csrf` |  |
| `ufu.prevent.same-hash` | Prevent overwriting files that have the same hash. | **guidance** | Results, logs and signals carry the SHA-256 to deduplicate on. |
| `ufu.prevent.virus-scan` | Scan uploads with a virus scanner. | see `content.malware-scan` |  |
| `ufu.prevent.post-only` | Use POST rather than PUT or GET. | **guidance** | Restrict the methods of your routes; uploadshield validates multipart bodies of any method. |
| `ufu.prevent.logging` | Log activity; protect the logs against forgery and injection. | **enforced** | Every refusal is logged with structured data; field and file names are logged escaped, so control characters cannot forge log lines. |
| `ufu.prevent.archive-members` | Check each file inside an archive individually. | **partial** | Every member's size, path and name (and CRC in ZIP) is checked, in ZIP and tar archives and in nested ones; member contents are not validated against a policy. |
| `ufu.prevent.database` | Consider storing files in a database. | see `storage.database` |  |
| `ufu.prevent.separate-domain` | Serve uploads from an isolated server on a separate domain. | **guidance** | Deployment. |
| `ufu.prevent.authorized-uploaders` | Only authenticated, authorized users upload. | see `permissions.authentication` |  |
| `ufu.prevent.write-permissions` | Remove write permissions from other folders. | see `filesystem.least-privilege` |  |
| `ufu.prevent.config-files` | Keep `.htaccess` and `web.config` from being replaced, and ignore them. | see `storage.config-overrides` |  |
| `ufu.prevent.double-extensions` | Prevent execution of double-extension files (Apache). | see `extension.double` |  |
| `ufu.prevent.access` | Keep uploads away from unauthorized users. | see `permissions.authorization` |  |
| `ufu.prevent.download-headers` | Send `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`. | **guidance** | See [What your application must do](#what-your-application-must-do). |
| `ufu.prevent.policy-files` | Remove unused `crossdomain.xml`/`clientaccesspolicy.xml`, and don't let browsers cache them. | **partial** | Uploads under these names are refused; existing files and caching are server configuration. |
| `ufu.prevent.cors` | Allow only authorized origins in CORS headers. | **guidance** | Server or framework configuration. |
| `ufu.prevent.iis` | Follow Microsoft's IIS hardening guidance. | **guidance** | Server configuration. |

*79 items: 44 enforced, 2 available, 4 partial, 7 guidance; 22 covered by another item.*
<!-- matrix:unrestricted-upload:end -->

## How this is verified

Every **enforced**, **available** and **partial** item has tests:

- `tests/owasp/cheat_sheet/` and `tests/owasp/unrestricted_upload/` have one test module
  per section of each document. Attacks are sent to Django (WSGI and ASGI), Flask and
  FastAPI as raw multipart requests, through each framework's own request parsing, and
  checked against the engine directly.
- Tests link themselves to an item with `@pytest.mark.owasp("<id>")`. Some live next to
  the adapter they exercise.
- `tests/meta/test_owasp_matrix.py` fails if a covered item has no test, if a marker
  names an unknown ID, or if a matrix above no longer matches its source,
  `tests/owasp/registry.py`.

```bash
uv run pytest -m owasp                          # run every test linked to OWASP
uv run python -m tests.owasp.registry --write   # contributors: re-render the matrices
```
