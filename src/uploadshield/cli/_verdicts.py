"""What each violation means for a person: verdicts, explanations, per-file outcomes."""

from __future__ import annotations

import enum
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from uploadshield.core.violations import Code

if TYPE_CHECKING:
    from uploadshield.core.result import ValidationResult
    from uploadshield.core.violations import Violation

__all__ = ["CODE_INFO", "CONDITIONS", "CodeInfo", "Outcome", "Summary", "Verdict", "judge"]


class Verdict(enum.StrEnum):
    """Ordered from best to worst: a file takes the worst verdict of its violations."""

    CLEAN = "clean"
    REFUSED = "refused"
    NOT_VERIFIED = "not_verified"
    DANGEROUS = "dangerous"

    @property
    def rank(self) -> int:
        return list(Verdict).index(self)

    @property
    def label(self) -> str:
        return self.value.replace("_", " ")


D, U, R = Verdict.DANGEROUS, Verdict.NOT_VERIFIED, Verdict.REFUSED


@dataclass(frozen=True, slots=True)
class CodeInfo:
    verdict: Verdict
    title: str
    meaning: str
    cause: str
    relax: str


CODE_INFO: dict[Code, CodeInfo] = {
    Code.FILE_EMPTY: CodeInfo(
        R,
        "empty file",
        "The file has no content.",
        "An empty upload, or a client that failed to read the file.",
        "Policy(allow_empty=True)",
    ),
    Code.FILE_TOO_LARGE: CodeInfo(
        R,
        "file too large",
        "The file is larger than the policy's max_size.",
        "A large file, or one meant to fill the disk.",
        "Policy(max_size=...), or max_size=None for no limit",
    ),
    Code.FILENAME_INVALID: CodeInfo(
        D,
        "invalid file name",
        "The name contains path separators, '..', control or bidi characters, or "
        "characters Windows forbids.",
        "Path traversal (../../etc/cron.d/x), NUL bytes, or a U+202E override that shows "
        "'gpj.exe' as 'exe.jpg'.",
        "FilenameCheck(allow_leading_hyphen=True, allow_consecutive_dots=True) for those "
        "two; SafeFilename() or RandomizeFilename() replace names instead",
    ),
    Code.FILENAME_TOO_LONG: CodeInfo(
        R,
        "file name too long",
        "The name is longer than FilenameCheck.max_length bytes (UTF-8).",
        "Very long names break filesystems and databases.",
        "FilenameCheck(max_length=...)",
    ),
    Code.FILENAME_HIDDEN: CodeInfo(
        R,
        "hidden file name",
        "The name starts with a dot.",
        "Dotfiles are hidden and often read as configuration.",
        "FilenameCheck(allow_hidden=True)",
    ),
    Code.FILENAME_RESERVED: CodeInfo(
        D,
        "reserved file name",
        "The name is a Windows device name (CON, NUL, COM1, ...), a server configuration "
        "file (.htaccess, web.config) or an 8.3 short name (PROGRA~1).",
        "Configuration files change how a web server treats the upload directory.",
        "FilenameCheck(forbidden_names=..., allow_short_names=True)",
    ),
    Code.FILENAME_DANGEROUS_EXTENSION: CodeInfo(
        D,
        "dangerous extension",
        "An extension in the name makes servers or clients run the file (.php, .jsp, .exe, "
        ".bat, ...), wherever it appears (shell.php.png).",
        "A web shell or executable named to be run where it is stored.",
        "FilenameCheck(forbidden_extensions=...)",
    ),
    Code.FILENAME_MISSING_EXTENSION: CodeInfo(
        R,
        "no extension",
        "The name has no extension.",
        "Files without an extension are served with a guessed type.",
        "FilenameCheck(require_extension=False)",
    ),
    Code.TYPE_UNKNOWN: CodeInfo(
        U,
        "unknown format",
        "The content matches no file format uploadshield knows.",
        "A format it does not know, or random or encrypted data.",
        "register_type(FileType(...)) for your format, or Policy(sniffer=MagicSniffer())",
    ),
    Code.TYPE_NOT_ALLOWED: CodeInfo(
        R,
        "format not allowed",
        "The format detected from the content is not in the policy's allowed_types.",
        "The content is not what the name says (a PHP script named .png), or the format "
        "is simply not accepted here.",
        "policy.extend(allowed_types={'<mime type>'})",
    ),
    Code.EXTENSION_MISMATCH: CodeInfo(
        R,
        "extension does not match the content",
        "The name's extension does not belong to the format detected from the content.",
        "A renamed file, e.g. a JPEG named .png - or a disguise.",
        "Policy(match_extension=False) with SafeFilename() or RandomizeFilename(), which "
        "give the file the right extension",
    ),
    Code.CONTENT_MISMATCH: CodeInfo(
        D,
        "content is a different format",
        "Magika's model identifies the content as a forbidden format.",
        "Code or an executable inside a file of an allowed format.",
        "MagikaCheck(forbidden=..., min_score=...)",
    ),
    Code.DECLARED_TYPE_MISMATCH: CodeInfo(
        R,
        "declared type does not match",
        "The client's Content-Type header contradicts the content.",
        "A client that guessed wrong, or one that lies.",
        "Policy(match_declared_type=False), the default",
    ),
    Code.IMAGE_CORRUPT: CodeInfo(
        R,
        "corrupt image",
        "Pillow cannot decode the image completely.",
        "A truncated or damaged file, or one crafted against image libraries.",
        "none: re-save the image",
    ),
    Code.IMAGE_TOO_LARGE: CodeInfo(
        D,
        "decompression bomb",
        "The image's dimensions, frame count or total pixels exceed the limits.",
        "A small file that needs gigabytes of memory to decode.",
        "ImageIntegrity(max_pixels=..., max_frames=..., max_total_pixels=...)",
    ),
    Code.PDF_ACTIVE_CONTENT: CodeInfo(
        D,
        "active PDF content",
        "The PDF contains JavaScript, launch actions, embedded files or forms that submit "
        "data - or it is encrypted, or stores objects in a form that cannot be checked.",
        "Malicious PDFs run scripts or drop files when opened.",
        "PdfActiveContent(forbidden=..., allow_encrypted=True)",
    ),
    Code.ARCHIVE_CORRUPT: CodeInfo(
        R,
        "corrupt archive",
        "The archive (ZIP, tar or a compressed stream) cannot be read consistently.",
        "A damaged file, or one built so that tools disagree about its contents.",
        "none",
    ),
    Code.ARCHIVE_UNSAFE_PATH: CodeInfo(
        D,
        "unsafe archive path (zip slip)",
        "A member would be extracted outside the target directory (../, absolute paths, "
        "drive letters) or is a link, device file or FIFO.",
        "Extracting it overwrites files elsewhere.",
        "none",
    ),
    Code.ARCHIVE_BOMB: CodeInfo(
        D,
        "archive bomb",
        "The archive expands far beyond its size, has too many members, overlapping "
        "entries or too deep nesting.",
        "A small file that fills the disk or memory when extracted.",
        "ArchiveSafety(max_ratio=..., max_uncompressed_bytes=..., max_entries=..., max_depth=...)",
    ),
    Code.ARCHIVE_ENCRYPTED: CodeInfo(
        U,
        "encrypted archive",
        "Encrypted members cannot be inspected.",
        "Encryption hides malware from scanners.",
        "ArchiveSafety(allow_encrypted=True)",
    ),
    Code.ARCHIVE_DANGEROUS_MEMBER: CodeInfo(
        D,
        "dangerous archive member",
        "A member has a dangerous extension or a server configuration name (shell.php, "
        ".htaccess, ...).",
        "Archives that are extracted on the server deliver what the upload check refused.",
        "ArchiveSafety(check_member_names=False)",
    ),
    Code.OFFICE_MACROS: CodeInfo(
        D,
        "macros",
        "The document contains macros, ActiveX controls or DDE fields that run commands.",
        "The classic malicious-attachment payload.",
        "remove OfficeMacros() from content_checks (not recommended)",
    ),
    Code.OFFICE_EXTERNAL_REFERENCE: CodeInfo(
        D,
        "remote template",
        "The document loads a remote template or object when it is opened.",
        "Used to fetch macros later and to leak Windows credentials.",
        "OfficeMacros(block_external_references=False)",
    ),
    Code.SVG_ACTIVE_CONTENT: CodeInfo(
        D,
        "scripted SVG",
        "The SVG contains scripts, event handlers, javascript: links, foreignObject, "
        "entities or external references.",
        "Served from your domain, it runs script in your users' browsers (stored XSS).",
        "none: rasterize SVG uploads instead",
    ),
    Code.XML_DTD: CodeInfo(
        D,
        "XML DTD",
        "The XML declares a DTD, which enables entity expansion and external entities.",
        "Billion-laughs denial of service and XXE file disclosure.",
        "none",
    ),
    Code.EMBEDDED_CODE: CodeInfo(
        D,
        "embedded code",
        "Code (PHP, script tags, JSP, SSI) is hidden inside the file.",
        "A web shell in image metadata, or PHP tags in a text file that include() runs.",
        "EmbeddedContent(categories=..., scan_text=False)",
    ),
    Code.POLYGLOT: CodeInfo(
        D,
        "polyglot",
        "The file is also a valid ZIP archive or PDF document.",
        "One file that different programs read as different formats (GIFAR).",
        "EmbeddedContent(categories=...)",
    ),
    Code.MALWARE_DETECTED: CodeInfo(
        D,
        "malware",
        "ClamAV found a malware signature.",
        "Known malware.",
        "none",
    ),
    Code.SIGNATURE_MATCH: CodeInfo(
        D,
        "YARA match",
        "One of your YARA rules matched.",
        "Whatever the rule describes.",
        "adjust the rules",
    ),
    Code.SCANNER_UNAVAILABLE: CodeInfo(
        U,
        "scanner unavailable",
        "An external scanner could not be reached or refused the file.",
        "clamd is down, or the file exceeds clamd's StreamMaxLength.",
        "ClamAV(fail_open=True) (not recommended)",
    ),
    Code.SANITIZATION_FAILED: CodeInfo(
        U,
        "sanitizing failed",
        "A sanitizer could not process the file, or what it produced failed the checks.",
        "Pillow is missing or cannot re-encode the image.",
        "uv add 'uploadshield[images]'",
    ),
    Code.CHECK_FAILED: CodeInfo(
        U,
        "check failed",
        "A check could not finish: the file needs more memory than it may use, or the "
        "check crashed.",
        "A very large file - or a bug, which you are welcome to report.",
        "raise the check's limit, e.g. PdfActiveContent(max_bytes=...)",
    ),
}

#: Codes whose verdict depends on the file (see :func:`verdict_for`).
CONDITIONS: dict[Code, str] = {
    Code.TYPE_NOT_ALLOWED: "dangerous when the content is an executable or HTML; in a scan, "
    "not verified for archives it cannot open",
    Code.PDF_ACTIVE_CONTENT: "not verified when the PDF is encrypted or cannot be decoded",
}

#: Formats that are dangerous to accept as uploads whatever their content.
_ACTIVE_TYPES = frozenset({"text/html"})


def verdict_for(violation: Violation, result: ValidationResult, *, scan: bool) -> Verdict:
    code = violation.code
    if scan and code == Code.TYPE_UNKNOWN and result.size == 0:
        return Verdict.CLEAN  # nothing to inspect (its name is still judged)
    if code == Code.TYPE_NOT_ALLOWED:
        detected = result.file_type
        if detected is not None and (detected.executable or detected.mime in _ACTIVE_TYPES):
            return D
        return U if scan else R  # in a scan: a format it cannot look into
    if code == Code.PDF_ACTIVE_CONTENT and violation.details.get("reason") in (
        "encrypted",
        "uncheckable",
    ):
        return U
    info = CODE_INFO.get(code) if isinstance(code, Code) else None
    return info.verdict if info is not None else R


def judge(result: ValidationResult, *, scan: bool) -> tuple[Verdict, tuple[Verdict, ...]]:
    """The verdict of each violation and of the file (the worst one)."""
    each = tuple(verdict_for(v, result, scan=scan) for v in result.violations)
    return max(each, key=lambda v: v.rank, default=Verdict.CLEAN), each


@dataclass(slots=True)
class Outcome:
    """What happened to one path."""

    display: str
    result: ValidationResult | None = None
    verdict: Verdict = Verdict.CLEAN
    verdicts: tuple[Verdict, ...] = ()
    sha256: str | None = None
    error: str | None = None  # could not be read: counts as not verified
    skipped: str | None = None  # deliberately not inspected (symbolic link, device)
    saved: str | None = None
    save_error: str | None = None
    #: Where a file found in a directory is shown: under ``root``, as ``label``.
    root: str | None = None
    label: str = ""


@dataclass(slots=True)
class Summary:
    counts: Counter[Verdict] = field(default_factory=Counter)
    skipped: Counter[str] = field(default_factory=Counter)
    save_errors: int = 0
    seconds: float = 0.0

    def add(self, outcome: Outcome) -> None:
        if outcome.skipped is not None:
            self.skipped[outcome.skipped] += 1
            return
        self.counts[outcome.verdict] += 1
        self.save_errors += outcome.save_error is not None

    @property
    def files(self) -> int:
        return sum(self.counts.values())

    @property
    def exit_code(self) -> int:
        if self.save_errors:
            return 2
        return 0 if self.files == self.counts[Verdict.CLEAN] else 1
