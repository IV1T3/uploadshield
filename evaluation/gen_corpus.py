"""Generate a frozen, labelled upload-validation corpus.

Run once in a full environment (Pillow present); the bytes and labels are written to
disk so every Python/extra combination later scores the identical dataset.

Every label is assigned by CONSTRUCTION, never by asking uploadshield, so the
evaluation is not circular. Each case carries:

  expected        "accept" | "refuse"   - the correct decision for this (file, policy)
  category        security | clean | policy_enforcement
  attack_class    the threat it represents (clean for benign)
  requires_extra  None | images | magika | yara
                  None  -> purely structural: MUST be caught in every environment;
                           a false negative here is a real bypass.
                  other -> capability that needs that extra; a miss without it is
                           expected, not a bypass.

All malicious samples are inert: placeholder scripts, the standard EICAR test
string, and structural tricks whose contents are harmless.

Usage: python gen_corpus.py OUTPUT_DIR [--real-root DIR ...] [--max-real-per-ext N]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
REPO = Path(__file__).resolve().parents[1]  # evaluation/ sits at the repo root
for p in (str(REPO), str(REPO / "src")):
    if p not in sys.path:
        sys.path.insert(0, p)

from eval_policies import POLICIES  # noqa: E402
from tests.support import corpus as c  # noqa: E402

BIDI_RLO = "‮"


@dataclass(frozen=True)
class Case:
    id: str
    file: str
    name: str
    policy: str
    expected: str
    category: str
    attack_class: str
    requires_extra: str | None
    declared_type: str | None
    template: str
    note: str


class Corpus:
    def __init__(self, out: Path) -> None:
        self.out = out
        self.files = out / "files"
        self.files.mkdir(parents=True, exist_ok=True)
        self.cases: list[Case] = []
        self._by_hash: dict[str, str] = {}

    def _store(self, content: bytes) -> str:
        digest = hashlib.sha256(content).hexdigest()[:16]
        if digest not in self._by_hash:
            (self.files / f"{digest}.bin").write_bytes(content)
            self._by_hash[digest] = digest
        return digest

    def add(
        self,
        content: bytes,
        *,
        name: str,
        policy: str,
        expected: str,
        category: str,
        attack_class: str,
        template: str,
        requires_extra: str | None = None,
        declared_type: str | None = None,
        note: str = "",
    ) -> None:
        assert policy in POLICIES, policy
        assert expected in ("accept", "refuse")
        digest = self._store(content)
        cid = f"{len(self.cases):06d}"
        self.cases.append(
            Case(
                id=cid,
                file=f"files/{digest}.bin",
                name=name,
                policy=policy,
                expected=expected,
                category=category,
                attack_class=attack_class,
                requires_extra=requires_extra,
                declared_type=declared_type,
                template=template,
                note=note,
            )
        )

    def write(self) -> None:
        with (self.out / "manifest.jsonl").open("w", encoding="utf-8") as fh:
            for case in self.cases:
                fh.write(json.dumps(asdict(case), ensure_ascii=True) + "\n")


# --------------------------------------------------------------------------- #
# Filename variants: a clean stem/ext, and the dangerous rewrites of it.
# Each dangerous variant makes the upload refusable on its name alone.
# --------------------------------------------------------------------------- #
def dangerous_names(stem: str, ext: str) -> list[tuple[str, str]]:
    """(filename, label) pairs; every one must be refused by the filename rules."""
    base = f"{stem}{ext}"
    return [
        (f"../../{base}", "traversal"),
        (f"..\\..\\{base}", "traversal_backslash"),
        (f"..%2f..%2f{base}", "traversal_percent"),
        (f"{stem}.php{ext}", "double_extension"),
        (f"{stem}.pHp5{ext}", "double_extension_mixed"),
        (f"CON{ext}", "reserved_device"),
        (f"nul{ext}", "reserved_device_lower"),
        (f"{stem}{BIDI_RLO}gpj.exe", "bidi_override"),
        (f"-{stem}{ext}", "leading_dash"),
        (f"{base}.", "trailing_dot"),
        (f"{'a' * 300}{ext}", "overlong"),
        (f".{stem}{ext}", "hidden_dotfile"),
    ]


def clean_name(stem: str, ext: str) -> str:
    return f"{stem}{ext}"


# --------------------------------------------------------------------------- #
# Builders grouped by the true content type they produce.
# --------------------------------------------------------------------------- #
def clean_samples() -> dict[str, tuple[bytes, str]]:
    """true_mime -> (bytes, extension) for a VALID, benign file of that type."""
    return {
        "image/png": (c.png(), ".png"),
        "image/jpeg": (c.image("JPEG"), ".jpg"),
        "image/gif": (c.animated_gif(), ".gif"),
        "image/bmp": (c.image("BMP"), ".bmp"),
        "image/tiff": (c.image("TIFF"), ".tiff"),
        "image/webp": (c.image("WEBP"), ".webp"),
        "application/pdf": (c.pdf(), ".pdf"),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": (
            c.ooxml("docx"),
            ".docx",
        ),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": (
            c.ooxml("xlsx"),
            ".xlsx",
        ),
        "application/vnd.oasis.opendocument.text": (c.odt(), ".odt"),
        "application/epub+zip": (c.epub(), ".epub"),
        "text/plain": (b"Just some meeting notes.\nNothing to see here.\n", ".txt"),
        "application/json": (b'{"ok": true, "items": [1, 2, 3]}', ".json"),
        "text/csv": (b"name,amount\nAda,10\nGrace,20\n", ".csv"),
        "audio/mpeg": (c.mp3(), ".mp3"),
        "audio/wav": (c.wav(), ".wav"),
        "video/mp4": (c.mp4(), ".mp4"),
        "video/webm": (c.webm(), ".webm"),
        "application/zip": (c.build_zip({"docs/readme.txt": b"hello"}), ".zip"),
        "application/x-tar": (c.build_tar({"docs/readme.txt": b"hello"}), ".tar"),
        "application/gzip": (
            c.build_tar({"docs/readme.txt": b"hello"}, compression="gz"),
            ".tar.gz",
        ),
    }


def policies_allowing(true_mime: str) -> list[str]:
    """Eval policies whose allow-list accepts a benign file of ``true_mime``."""
    out = []
    for name, policy in POLICIES.items():
        try:
            if policy.allows_mime(true_mime):
                out.append(name)
        except Exception:
            pass
    return out


def policies_rejecting(true_mime: str) -> list[str]:
    return [n for n in POLICIES if n not in set(policies_allowing(true_mime))]


# --------------------------------------------------------------------------- #
# Attack builders: content that must be refused, with the policy it targets and
# the class/extra it exercises. (bytes, ext, true-or-claimed mime, class, extra).
# --------------------------------------------------------------------------- #
def disguise_cases() -> list[tuple[bytes, str, str, str]]:
    """Code wearing a benign extension. (bytes, worn_ext, worn_mime, note)."""
    return [
        (c.PHP_SHELL, ".png", "image/png", "php_as_png"),
        (c.PHP_SHELL, ".jpg", "image/jpeg", "php_as_jpeg"),
        (c.PHP_SHELL, ".pdf", "application/pdf", "php_as_pdf"),
        (c.ELF, ".png", "image/png", "elf_as_png"),
        (c.pe_executable(), ".jpg", "image/jpeg", "pe_as_jpeg"),
        (c.SHELL_SCRIPT, ".txt", "text/plain", "shell_as_txt"),
        (c.HTML, ".txt", "text/plain", "html_as_txt"),
        (c.HTML, ".png", "image/png", "html_as_png"),
        (c.svg(), ".png", "image/png", "svg_as_png"),
    ]


def active_document_cases() -> list[tuple[bytes, str, str, str, str]]:
    """(bytes, ext, policy, class, note) - active content in an allowed format."""
    return [
        (c.pdf_with_javascript(), ".pdf", "pdf", "active_document", "pdf_js"),
        (c.pdf_with_obfuscated_javascript(), ".pdf", "pdf", "active_document", "pdf_js_obfuscated"),
        (c.pdf_with_javascript_in_object_stream(), ".pdf", "pdf", "active_document", "pdf_js_objstm"),
        (c.ole(macros=True), ".doc", "documents", "active_document", "ole_macros"),
        (c.docx_with_dde(), ".docx", "documents", "active_document", "docx_dde"),
        (c.docx_with_remote_template(), ".docx", "documents", "active_document", "docx_remote_tpl"),
        (c.xlsx_with_dde_formula(), ".xlsx", "documents", "active_document", "xlsx_dde_formula"),
        (c.xlsx_with_dde_link(), ".xlsx", "documents", "active_document", "xlsx_dde_link"),
        (c.svg('<script>alert(1)</script>'), ".svg", "markup", "active_document", "svg_script"),
        (c.svg('<rect onload="x()"/>'), ".svg", "markup", "active_document", "svg_onload"),
        (c.docx_with_dtd(), ".docx", "documents", "active_document", "docx_dtd"),
        (c.odt_with_dtd(), ".odt", "documents", "active_document", "odt_dtd"),
        (c.xml(c.XXE_DTD), ".xml", "markup", "active_document", "xml_xxe"),
        (c.xml(c.BILLION_LAUGHS_DTD, root=b"<lolz>&lol9;</lolz>"), ".xml", "markup",
         "active_document", "xml_billion_laughs"),
    ]


def archive_cases() -> list[tuple[bytes, str, str, str]]:
    """(bytes, ext, class, note) - targeted at the archives policy."""
    php = c.PHP_SHELL
    out = [
        (c.zip_with_member_name("../../etc/passwd"), ".zip", "archive", "zip_slip"),
        (c.zip_with_member_name("/etc/cron.d/x"), ".zip", "archive", "zip_absolute"),
        (c.zip_with_symlink(), ".zip", "archive", "zip_symlink"),
        (c.zip_encrypted_flag(), ".zip", "archive", "zip_encrypted"),
        (c.zip_bomb_ratio(), ".zip", "archive", "zip_bomb_ratio"),
        (c.zip_bomb_overlapping(), ".zip", "archive", "zip_bomb_overlap"),
        (c.build_zip({"shell.php": php}), ".zip", "archive", "zip_dangerous_member"),
        (c.build_zip({".htaccess": b"x"}), ".zip", "archive", "zip_htaccess"),
        (c.zip_lying_about_size(), ".zip", "archive", "zip_lies_about_size"),
        (c.zip_with_bad_crc(), ".zip", "archive", "zip_bad_crc"),
        (c.build_tar({"../../etc/passwd": b"x"}), ".tar", "archive", "tar_slip"),
        (c.build_tar({"../../etc/passwd": b"x"}, compression="gz"), ".tar.gz", "archive", "targz_slip"),
        (c.build_tar({"../../etc/passwd": b"x"}, compression="bz2"), ".tar.bz2", "archive", "tarbz2_slip"),
        (c.build_tar({"../../etc/passwd": b"x"}, compression="xz"), ".tar.xz", "archive", "tarxz_slip"),
        (c.build_tar(links={"www": "/var/www"}), ".tar", "archive", "tar_symlink"),
        (c.build_tar(hardlinks={"p": "../../etc/passwd"}), ".tar", "archive", "tar_hardlink"),
        (c.build_tar(devices=("dev/sda",)), ".tar", "archive", "tar_device"),
        (c.build_tar({"shell.php": php}, compression="gz"), ".tar.gz", "archive", "targz_dangerous"),
        (c.tar_gz_bomb(400), ".tar.gz", "archive", "targz_bomb"),
        (c.tar_with_negative_size(), ".tar", "archive", "tar_negative_size"),
        (c.build_tar({"shell.php/": php}), ".tar", "archive", "tar_trailing_slash"),
    ]
    return out


def polyglot_cases() -> list[tuple[bytes, str, str, str, str]]:
    """(bytes, ext, policy, class, note)."""
    gifar = c.animated_gif() + c.build_zip({"shell.php": c.PHP_SHELL})
    return [
        (gifar, ".gif", "images", "polyglot", "gifar"),
        (c.jpeg_with_metadata() + c.PHP_SHELL, ".jpg", "images", "embedded_code", "php_in_jpeg_tail"),
    ]


def oversize_empty_cases() -> list[tuple[bytes, str, str, str, str]]:
    return [
        (b"", ".txt", "documents", "empty", "empty_file"),
        (b"", ".png", "images", "empty", "empty_png"),
        (c.image("PNG", size=(4000, 4000)) + b"\x00" * (11 * 1024 * 1024), ".png", "images",
         "oversize", "over_images_cap"),
    ]


def image_integrity_cases() -> list[tuple[bytes, str, str, str, str]]:
    """Need Pillow to catch; requires_extra=images."""
    return [
        (c.png_huge_dimensions(), ".png", "images", "image_bomb", "png_decompression_bomb"),
        (c.png()[:40], ".png", "images", "image_corrupt", "truncated_png"),
        (c.image("PNG")[:-20] + b"\x00" * 20, ".png", "images", "image_corrupt", "damaged_png"),
    ]


def magika_cases() -> list[tuple[bytes, str, str, str]]:
    """Disguised scripts/executables a veto-only Magika should flag. (bytes, ext, worn_mime, note)."""
    return [
        (c.PHP_SHELL, ".txt", "text/plain", "php_as_txt"),
        (c.SHELL_SCRIPT, ".txt", "text/plain", "shell_as_txt"),
        (b"#!/usr/bin/env python\nimport os\nos.system('id')\n", ".txt", "text/plain", "python_as_txt"),
        (b"<%@ page import=\"java.io.*\" %><% Runtime.getRuntime().exec(request.getParameter(\"c\")); %>",
         ".txt", "text/plain", "jsp_as_txt"),
    ]


def build(out: Path, real_roots: list[Path], max_real_per_ext: int) -> Corpus:
    cp = Corpus(out)
    cleans = clean_samples()

    # 1. CLEAN, ALLOWED (expect accept): valid files to policies that allow their type.
    #    The sanitized_images preset re-encodes through Pillow, so accepting an image
    #    there needs the images extra: tag it, or a base env records a false positive
    #    for a fail-closed sanitizer, not a real misclassification.
    for true_mime, (content, ext) in cleans.items():
        stem = true_mime.split("/")[-1].replace("+", "_")[:20]
        for policy in policies_allowing(true_mime):
            req = "images" if policy == "sanitized_images" else None
            cp.add(content, name=clean_name(stem, ext), policy=policy, expected="accept",
                   category="clean", attack_class="clean", template="clean_allowed",
                   requires_extra=req, note=true_mime)

    # 2. CLEAN but DISALLOWED (expect refuse): valid file to a policy that forbids its type.
    for true_mime, (content, ext) in cleans.items():
        stem = true_mime.split("/")[-1].replace("+", "_")[:20]
        for policy in policies_rejecting(true_mime)[:3]:
            cp.add(content, name=clean_name(stem, ext), policy=policy, expected="refuse",
                   category="policy_enforcement", attack_class="disallowed_type",
                   template="clean_disallowed", note=true_mime)

    # 3. DANGEROUS NAMES (expect refuse): a valid, allowed file with a hostile name,
    #    across several carrier types and the policies that allow each carrier.
    name_carriers = [
        ("image/png", "photo", ".png"),
        ("application/pdf", "report", ".pdf"),
        ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "memo", ".docx"),
        ("text/plain", "notes", ".txt"),
    ]
    for true_mime, stem, ext in name_carriers:
        content = cleans[true_mime][0]
        for policy in policies_allowing(true_mime)[:3]:
            for fname, label in dangerous_names(stem, ext):
                cp.add(content, name=fname, policy=policy, expected="refuse",
                       category="security", attack_class="dangerous_name",
                       template="dangerous_name", note=f"{label}:{ext}")

    # 4. DISGUISE (expect refuse): code worn as an allowed extension.
    for content, ext, worn_mime, note in disguise_cases():
        for policy in policies_allowing(worn_mime)[:3]:
            stem = "upload"
            cp.add(content, name=clean_name(stem, ext), policy=policy, expected="refuse",
                   category="security", attack_class="disguise", template="disguise", note=note)
            # And the same disguise under a hostile name (still refuse).
            cp.add(content, name=f"{stem}.php{ext}", policy=policy, expected="refuse",
                   category="security", attack_class="disguise", template="disguise_badname",
                   note=f"{note}+double_ext")

    # 5. DECLARED-TYPE LIES (expect refuse): truthful content, lying Content-Type header,
    #    against a policy that opts into declared-type matching (off by default, so this
    #    tests the DeclaredTypeMatches check, not the default stance of ignoring the header).
    for true_mime, (content, ext) in cleans.items():
        stem = true_mime.split("/")[-1].replace("+", "_")[:20]
        lie = "application/pdf" if true_mime != "application/pdf" else "image/png"
        cp.add(content, name=clean_name(stem, ext), policy="strict_declared", expected="refuse",
               category="security", attack_class="declared_type_lie", template="declared_lie",
               declared_type=lie, note=f"{true_mime} declared as {lie}")

    # 6. ACTIVE DOCUMENTS (expect refuse): structural, no extra needed.
    for content, ext, policy, klass, note in active_document_cases():
        cp.add(content, name=clean_name("doc", ext), policy=policy, expected="refuse",
               category="security", attack_class=klass, template="active_document", note=note)

    # 7. ARCHIVES (expect refuse): to the archives policy.
    for content, ext, klass, note in archive_cases():
        cp.add(content, name=clean_name("bundle", ext), policy="archives", expected="refuse",
               category="security", attack_class=klass, template="archive", note=note)

    # 8. POLYGLOT / EMBEDDED (expect refuse).
    for content, ext, policy, klass, note in polyglot_cases():
        cp.add(content, name=clean_name("pic", ext), policy=policy, expected="refuse",
               category="security", attack_class=klass, template="polyglot", note=note)

    # 9. OVERSIZE / EMPTY (expect refuse).
    for content, ext, policy, klass, note in oversize_empty_cases():
        cp.add(content, name=clean_name("f", ext), policy=policy, expected="refuse",
               category="security", attack_class=klass, template="size", note=note)

    # 10. IMAGE INTEGRITY (expect refuse, requires Pillow).
    for content, ext, policy, klass, note in image_integrity_cases():
        cp.add(content, name=clean_name("img", ext), policy=policy, expected="refuse",
               category="security", attack_class=klass, template="image_integrity",
               requires_extra="images", note=note)

    # 11. MAGIKA (expect refuse, requires magika): disguised scripts to a text policy.
    for content, ext, worn_mime, note in magika_cases():
        cp.add(content, name=clean_name("note", ext), policy="markup", expected="refuse",
               category="probe", attack_class="magika_script", template="magika",
               requires_extra="magika", note=note)

    # 12. YARA / EICAR (expect refuse, requires yara): the standard antivirus test string.
    for ext, policy in ((".txt", "markup"), (".com", "documents")):
        cp.add(c.EICAR, name=clean_name("sample", ext), policy=policy, expected="refuse",
               category="security", attack_class="eicar_signature", template="yara",
               requires_extra="yara", note="eicar")

    # 14. ADVERSARIAL (out-of-the-box): code-in-text edges, polyglots, PDF actions,
    #     SVG vectors, office internals, archive differentials, name tricks, bombs.
    import adversarial

    for case in adversarial.all_cases():
        cp.add(case["content"], name=case["name"], policy=case["policy"],
               expected=case["expected"], category=case["category"],
               attack_class=case["attack_class"], template=case["template"],
               requires_extra=case["requires_extra"], declared_type=case["declared_type"],
               note=case["note"])

    # 13. REAL FILES from the machine (expect accept): the true false-positive test.
    _add_real_files(cp, real_roots, max_real_per_ext)
    return cp


EXT_MIME = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
    ".tiff": "image/tiff", ".tif": "image/tiff", ".bmp": "image/bmp", ".webp": "image/webp",
    ".heic": "image/heic", ".ico": "image/vnd.microsoft.icon", ".svg": "image/svg+xml",
    ".pdf": "application/pdf", ".txt": "text/plain", ".md": "text/markdown",
    ".json": "application/json", ".csv": "text/csv", ".xml": "application/xml",
    ".html": "text/html", ".rtf": "application/rtf", ".mp3": "audio/mpeg",
    ".m4a": "audio/mp4", ".wav": "audio/wav", ".aiff": "audio/x-aiff", ".mp4": "video/mp4",
    ".mov": "video/quicktime", ".zip": "application/zip", ".gz": "application/gzip",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".odt": "application/vnd.oasis.opendocument.text", ".epub": "application/epub+zip",
}


# Formats that cannot carry active content under uploadshield's checks: a real file
# of one of these is genuinely clean, so a refusal is a true false positive. The
# others (pdf, html, svg, office, xml, epub) can legitimately be refused for active
# content, so real ones go to an observational bucket, out of the confusion matrix.
CLEAN_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".tiff", ".tif", ".bmp", ".webp", ".ico",
    ".txt", ".md", ".json", ".csv", ".mp3", ".m4a", ".wav", ".aiff", ".mp4", ".mov",
}
# Decoding these needs a Pillow plugin (pillow-heif); whether a clean file is accepted
# then depends on the host's Pillow build, not on uploadshield, so observe, don't score.
PLUGIN_EXTS = {".heic", ".avif"}


def _oracle_mime(path: Path) -> str | None:
    """libmagic's view of a file, via /usr/bin/file - an oracle independent of
    uploadshield, used to confirm a sampled file really is its extension's type."""
    import subprocess

    try:
        out = subprocess.run(["/usr/bin/file", "--mime-type", "-b", str(path)],
                             capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def _add_real_files(cp: Corpus, roots: list[Path], per_ext: int) -> None:
    seen: dict[str, int] = {}
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            ext = path.suffix.lower()
            mime = EXT_MIME.get(ext)
            if mime is None or not path.is_file():
                continue
            if seen.get(ext, 0) >= per_ext:
                continue
            try:
                size = path.stat().st_size
                if size == 0 or size > 20 * 1024 * 1024 or path.is_symlink():
                    continue  # empty files are a size-policy choice, not a detection test
                content = path.read_bytes()
            except OSError:
                continue
            allowed = policies_allowing(mime)
            if not allowed:
                continue
            seen[ext] = seen.get(ext, 0) + 1
            name = f"real_{seen[ext]:03d}{ext}"
            note = f"{mime} from {root.name}"
            # Confirm the bytes match the extension with an independent oracle; a file
            # whose top-level type disagrees is mislabelled on disk, so observe it.
            oracle = _oracle_mime(path)
            agrees = oracle is not None and oracle.split("/")[0] == mime.split("/")[0]
            if ext in PLUGIN_EXTS:
                cp.add(content, name=name, policy=allowed[0], expected="accept",
                       category="observational", attack_class="plugin_dependent",
                       template="real_file_plugin", note=note)
            elif ext in CLEAN_EXTS and agrees:
                cp.add(content, name=name, policy=allowed[0], expected="accept",
                       category="clean", attack_class="clean", template="real_file", note=note)
            else:
                # Active-capable, or bytes disagree with the name: observe, do not score.
                cp.add(content, name=name, policy=allowed[0], expected="accept",
                       category="observational", attack_class="real_active_capable",
                       template="real_file_active", note=f"{note} (oracle={oracle})")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=Path)
    ap.add_argument("--real-root", action="append", default=[], type=Path)
    ap.add_argument("--max-real-per-ext", type=int, default=25)
    ap.add_argument("--fresh", action="store_true")
    args = ap.parse_args()
    if args.fresh and args.out.exists():
        shutil.rmtree(args.out)
    cp = build(args.out, args.real_root, args.max_real_per_ext)
    cp.write()
    by_cat: dict[str, int] = {}
    by_exp: dict[str, int] = {}
    for case in cp.cases:
        by_cat[case.category] = by_cat.get(case.category, 0) + 1
        by_exp[case.expected] = by_exp.get(case.expected, 0) + 1
    print(f"{len(cp.cases)} cases, {len(cp._by_hash)} unique files")
    print("by category:", by_cat)
    print("by expected:", by_exp)


if __name__ == "__main__":
    main()
