"""OWASP Unrestricted File Upload - Weak Protections and Bypassing Methods.

Every bypass the page lists, with its own example names and payloads: against an
extension deny-list, getimagesize(), an extension allow-list, the Content-Type header and
file type detectors.
"""

from __future__ import annotations

import string
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from PIL import PngImagePlugin

from tests.owasp.unrestricted_upload.payloads import PNG, blocked
from tests.support import corpus
from tests.support.engine import codes
from uploadshield import InspectedFile, Policy, Upload, presets, validate
from uploadshield.checks import DANGEROUS_EXTENSIONS
from uploadshield.core.check import Replacement, Sanitizer
from uploadshield.presets import BUILTIN_POLICIES

if TYPE_CHECKING:
    from tests.support.harness import App

owasp = pytest.mark.owasp
DANGEROUS = "filename_dangerous_extension"
INVALID = "filename_invalid"
RESERVED = "filename_reserved"


def refused_with(name: str, code: str, data: bytes = PNG) -> None:
    assert code in codes(data, name), (name, codes(data, name))


# --------------------------------------------------------------------------- #
# Deny-listing file extensions: the page's bypasses, one by one
# --------------------------------------------------------------------------- #

BYPASSES: dict[str, tuple[str, list[str]]] = {
    "ufu.bypass.missed-extensions": (
        DANGEROUS,
        [
            "file.php5",
            "file.pht",
            "file.phtml",
            "file.shtml",
            "file.asa",
            "file.cer",
            "file.asax",
            "file.swf",
            "file.xap",
            "file.swf.png",
            "file.xap.jpg",
        ],
    ),
    "ufu.bypass.double-extension": (DANGEROUS, ["file.php.jpg", "/file.jpg/index.php"]),
    "ufu.bypass.iis-semicolon": (DANGEROUS, ["file.asp;.jpg", "file.asp;x.jpg"]),
    "ufu.bypass.ntfs-index": (INVALID, ["folder::$Index_Allocation", "a.php::$INDEX_ALLOCATION"]),
    "ufu.bypass.case": (DANGEROUS, ["file.aSp", "file.PHp3", "file.pHtMl", "FILE.ASPX"]),
    "ufu.bypass.short-names": (RESERVED, ["web~1.con", "HTACCE~1", "WEBCON~1.CON"]),
    "ufu.bypass.wildcards": (INVALID, ["web<config", "web>config", 'web"config', "a<.png"]),
    "ufu.bypass.trailing": (INVALID, ["file.asp.", "file.asp ", "file.asp. . .", "test.php/"]),
    "ufu.bypass.multiple-dots": (DANGEROUS, ["file.txt.jpg.php", "a.b.c.d.php.png"]),
    "ufu.bypass.null-byte": (INVALID, ["file.php\x00.jpg", "file.php%00.jpg", "file.php%2500.jpg"]),
    "ufu.bypass.ads": (INVALID, ["file.asax:.jpg", "file.asp::$data.", "file.php::$DATA"]),
}


def _cases() -> Iterator[tuple[str, str, str]]:
    for item, (code, names) in BYPASSES.items():
        for name in names:
            yield item, name, code


@owasp(
    "ufu.bypass.missed-extensions",
    "ufu.bypass.double-extension",
    "ufu.bypass.iis-semicolon",
    "ufu.bypass.ntfs-index",
    "ufu.bypass.case",
    "ufu.bypass.short-names",
    "ufu.bypass.wildcards",
    "ufu.bypass.trailing",
    "ufu.bypass.multiple-dots",
    "ufu.bypass.null-byte",
    "ufu.bypass.ads",
)
@pytest.mark.parametrize(("item", "name", "code"), list(_cases()), ids=[n for _, n, _ in _cases()])
def test_deny_list_bypasses_in_the_engine(item: str, name: str, code: str) -> None:
    refused_with(name, code)


@owasp(
    "ufu.bypass.missed-extensions",
    "ufu.bypass.double-extension",
    "ufu.bypass.iis-semicolon",
    "ufu.bypass.ntfs-index",
    "ufu.bypass.case",
    "ufu.bypass.short-names",
    "ufu.bypass.wildcards",
    "ufu.bypass.trailing",
    "ufu.bypass.multiple-dots",
    "ufu.bypass.null-byte",
    "ufu.bypass.ads",
)
@pytest.mark.parametrize("name", [name for _, name, _ in _cases()], ids=[n for _, n, _ in _cases()])
def test_deny_list_bypasses_in_every_framework(app: App, name: str) -> None:
    blocked(app, name)


@owasp("ufu.bypass.iis-semicolon")
def test_script_named_folders(app: App) -> None:
    # "folder.asp\\file.txt": separators are refused (Django keeps only "file.txt").
    assert INVALID in codes(PNG, "folder.asp\\file.txt")
    blocked(app, "folder.asp\\file.txt")


@owasp("ufu.bypass.replacement")
@pytest.mark.parametrize("name", ["file.p.phphp", "file.pphphp", "file.ph.php.p"])
def test_names_are_refused_never_rewritten(app: App, name: str) -> None:
    # A filter that deletes "php" once would turn these into "file.php". Nothing here
    # rewrites names: they are refused (the extension does not belong to the content).
    result = validate(Upload.from_bytes(PNG, name), presets.DEFAULT)
    assert not result.ok
    assert result.sanitized is None
    blocked(app, name)


@owasp("ufu.bypass.combined")
@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    stem=st.text(string.ascii_letters, min_size=1, max_size=8),
    extension=st.sampled_from(sorted(DANGEROUS_EXTENSIONS)),
    upper=st.booleans(),
    trick=st.sampled_from(["", ";", "::$DATA", "%00", "\x00", ".", " ", ":"]),
    allowed=st.sampled_from(["jpg", "png", "gif", "pdf"]),
    double=st.booleans(),
)
def test_combined_techniques(
    stem: str, extension: str, upper: bool, trick: str, allowed: str, double: bool
) -> None:
    ext = extension.upper() if upper else extension
    name = f"{stem}.{ext}{trick}.{allowed}" if double else f"{stem}.{allowed}.{ext}{trick}"
    assert not validate(Upload.from_bytes(PNG, name), presets.DEFAULT).ok, name


# --------------------------------------------------------------------------- #
# Beating getimagesize(): valid images that carry code
# --------------------------------------------------------------------------- #


def png_with_text(text: bytes) -> bytes:
    import io

    from PIL import Image

    info = PngImagePlugin.PngInfo()
    info.add_text("Comment", text.decode())
    buf = io.BytesIO()
    Image.new("RGB", (4, 4)).save(buf, "PNG", pnginfo=info)
    return buf.getvalue()


@owasp("ufu.getimagesize.comment", "ufu.detector.comments")
@pytest.mark.parametrize(
    ("name", "data"),
    [
        # gifsicle --comment "<?php ... ?>": still a valid GIF for getimagesize()
        ("cat.gif", corpus.image("GIF", comment=b"<?php system($_GET['c']); ?>")),
        ("cat.jpg", corpus.image("JPEG", comment=b"<?php system($_GET['c']); ?>")),
        ("cat.png", png_with_text(b"<?php system($_GET['c']); ?>")),
        ("song.mp3", corpus.mp3() + b"COMM<?php system($_GET['c']); ?>"),
    ],
    ids=["gif-comment", "jpeg-comment", "png-text", "mp3-tag"],
)
def test_code_in_the_metadata_of_a_valid_image(app: App, name: str, data: bytes) -> None:
    assert "embedded_code" in codes(data, name)
    blocked(app, name, data)


@owasp("ufu.getimagesize.comment")
def test_sanitizing_drops_comments_and_metadata() -> None:
    clean = corpus.image("GIF", comment=b"just a comment")
    result = validate(Upload.from_bytes(clean, "a.gif"), presets.SANITIZED_IMAGES)
    assert result.sanitized is not None
    assert b"just a comment" not in (result.sanitized.data or b"")


@owasp("ufu.getimagesize.filesmatch")
@pytest.mark.parametrize("name", ["output.php.gif", "output.php5.gif", "output.phtml.gif"])
def test_names_an_unanchored_filesmatch_would_run(app: App, name: str) -> None:
    refused_with(name, DANGEROUS, corpus.image("GIF"))
    blocked(app, name, corpus.image("GIF"))


# --------------------------------------------------------------------------- #
# Allow-listing file extensions
# --------------------------------------------------------------------------- #


@owasp("ufu.allowlist.dangerous-types")
@pytest.mark.parametrize("policy", list(BUILTIN_POLICIES.values()), ids=list(BUILTIN_POLICIES))
def test_no_preset_allows_script_capable_types(policy: Policy) -> None:
    for mime in (
        "text/html",
        "image/svg+xml",
        "application/xml",
        "application/x-httpd-php",
        "application/x-sh",
        "application/x-shockwave-flash",
    ):
        assert not policy.allows_mime(mime), (policy.name, mime)


@owasp("ufu.allowlist.dangerous-types")
def test_ssi_pages_are_refused_by_name(app: App) -> None:
    blocked(app, "page.shtml", b'<!--#exec cmd="id" -->')
    blocked(app, "page.shtm.png")


@owasp("ufu.allowlist.full-name")
@pytest.mark.parametrize("name", ["image.jpg.php", "image.php.jpg", "image.jpg.php.jpg"])
def test_the_full_name_is_validated(app: App, name: str) -> None:
    refused_with(name, DANGEROUS, corpus.image("JPEG"))
    blocked(app, name, corpus.image("JPEG"))


# --------------------------------------------------------------------------- #
# File type detectors
# --------------------------------------------------------------------------- #


@owasp("ufu.detector.after-header")
@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("a.gif", b"GIF89a" + corpus.PHP_SHELL),
        ("a.png", b"\x89PNG\r\n\x1a\n" + corpus.PHP_SHELL),
        ("a.jpg", b"\xff\xd8\xff\xe0" + corpus.PHP_SHELL),
        ("a.png", PNG + corpus.PHP_SHELL),  # a complete image, then code
    ],
    ids=["gif-header", "png-header", "jpeg-header", "after-a-whole-png"],
)
def test_code_after_a_valid_header(app: App, name: str, data: bytes) -> None:
    blocked(app, name, data)


@owasp("ufu.detector.obfuscation")
@pytest.mark.parametrize(
    "payload",
    [
        b"<?PhP system($_GET[0]); ?>",
        b"<?php\n\t@eval(base64_decode('c3lzdGVtKCRfR0VUWzBdKTs='));?>",
        b"<?=`$_GET[0]`?>",
        b"<?= system($_GET[0]) ?>",
        b'<script language="php">system("id");</script>',
        b"<SCRIPT>alert(1)</SCRIPT>",
    ],
    ids=[
        "mixed-case",
        "base64-eval",
        "short-echo-backticks",
        "short-echo-call",
        "script-php",
        "script-upper",
    ],
)
def test_obfuscated_payloads_in_images(payload: bytes) -> None:
    assert "embedded_code" in codes(PNG + payload, "a.png")


@owasp("ufu.detector.obfuscation")
def test_what_obfuscation_still_gets_through() -> None:
    # The documented limit of "partial": short open tags carry too little signal to tell
    # code from compressed pixels, and payloads without a tag are not code by themselves.
    assert codes(PNG + b"<? system($_GET[0]); ?>", "a.png") == ()
    # Rebuilding the image removes them anyway.
    result = validate(
        Upload.from_bytes(PNG + b"<? system($_GET[0]); ?>", "a.png"), presets.SANITIZED_IMAGES
    )
    assert result.sanitized is not None
    assert b"<? system" not in (result.sanitized.data or b"")


@dataclass(frozen=True)
class InjectsCode(Sanitizer):
    """Stands in for an image library that a crafted image tricks into writing code."""

    name = "injects_code"

    def sanitize(self, file: InspectedFile) -> Replacement:
        return Replacement(data=file.read(10_000_000) + b"<?php system($_GET[0]); ?>")


@owasp("ufu.detector.decompression")
def test_sanitized_output_is_checked_again() -> None:
    policy = presets.IMAGES.replace(sanitizers=(InjectsCode(),))
    result = validate(Upload.from_bytes(PNG, "a.png"), policy)
    assert result.codes == ("embedded_code",)
    assert result.sanitized is None
    assert result.violations[0].details["in_sanitized_output"] is True


@owasp("ufu.detector.decompression")
@pytest.mark.parametrize(
    ("name", "data", "policy", "code"),
    [
        (
            "a.zip",
            corpus.build_zip({"shell.php": corpus.PHP_SHELL}),
            "zip",
            "archive_dangerous_member",
        ),
        (
            "a.zip",
            corpus.build_zip({"in.zip": corpus.build_zip({"x.jsp": b"x"})}),
            "zip",
            "archive_dangerous_member",
        ),
        ("a.zip", corpus.zip_lying_about_size(), "zip", "archive_bomb"),
        ("a.pdf", corpus.pdf_with_javascript_in_object_stream(), "pdf", "pdf_active_content"),
    ],
    ids=["zip-member", "nested-zip-member", "lying-zip", "compressed-pdf-object"],
)
def test_content_that_appears_only_once_decompressed(
    name: str, data: bytes, policy: str, code: str
) -> None:
    chosen = Policy(allowed_types={"application/zip"}) if policy == "zip" else presets.PDF
    assert code in codes(data, name, chosen)
