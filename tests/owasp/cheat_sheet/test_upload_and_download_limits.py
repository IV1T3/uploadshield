"""OWASP File Upload Cheat Sheet - Upload and Download Limits.

Size limits, and the "secure ZIP size calculation" the cheat sheet asks for: archive
members are measured by inflating them, never by trusting their headers.
"""

from __future__ import annotations

import io
import time
import zipfile

import pytest

from tests.support import corpus
from tests.support.engine import codes
from tests.support.harness import App, file
from uploadshield import MB, Policy, Upload, presets, validate
from uploadshield.checks import ArchiveSafety

owasp = pytest.mark.owasp
ZIPS = Policy(allowed_types={"application/zip"}, max_size=50 * MB)


# --------------------------------------------------------------------------- #
# Upload size
# --------------------------------------------------------------------------- #


@owasp("limits.upload-size", "threat.huge-files")
def test_the_limit_is_exact() -> None:
    policy = Policy(allowed_types={"text/plain"}, max_size=1000)
    assert codes(b"x" * 1000, "a.txt", policy) == ()
    assert codes(b"x" * 1001, "a.txt", policy) == ("file_too_large",)


@owasp("limits.upload-size")
def test_every_preset_has_a_limit() -> None:
    from uploadshield.presets import BUILTIN_POLICIES

    for policy in BUILTIN_POLICIES.values():
        assert policy.max_size is not None
        assert policy.max_size <= 500 * MB


@owasp("limits.upload-size", "threat.huge-files")
def test_the_endpoint_limit_applies_in_every_framework(app: App) -> None:
    big = b"\xff\xd8\xff\xe0" + b"\x00" * (10 * 1000 * 1000)  # just over /avatar's 10 MB
    reply = app.post("/avatar", file("big.jpg", big))
    assert (reply.status, reply.codes) == (413, ["file_too_large"])


# --------------------------------------------------------------------------- #
# Size after decompression
# --------------------------------------------------------------------------- #


@owasp("limits.decompressed-size", "threat.zip-bomb")
def test_headers_that_understate_the_size_are_caught() -> None:
    lying = corpus.zip_lying_about_size(actual=20 * 1024 * 1024, declared=1000)
    assert len(lying) < 100_000
    started = time.perf_counter()
    assert codes(lying, "a.zip", ZIPS) == ("archive_bomb",)
    assert time.perf_counter() - started < 1  # stopped at byte 1001, not after 20 MiB
    header_only = ZIPS.replace(content_checks=(ArchiveSafety(verify_sizes=False),))
    assert codes(lying, "a.zip", header_only) == ()  # why measuring matters


@owasp("limits.decompressed-size", "threat.zip-bomb")
def test_a_lying_office_document_is_caught_in_every_framework(app: App) -> None:
    lying = bytearray(corpus.docx_bomb(megabytes=30))
    central = lying.rfind(b"word/document.xml") - 46  # its central-directory record
    assert lying[central : central + 4] == b"PK\x01\x02"
    lying[central + 24 : central + 28] = (2000).to_bytes(4, "little")
    reply = app.post("/documents", file("report.docx", bytes(lying)))
    assert (reply.status, reply.codes) == (400, ["archive_bomb"])


@owasp("limits.decompressed-size", "threat.zip-bomb")
@pytest.mark.parametrize(
    ("data", "why"),
    [
        (corpus.zip_bomb_ratio(64), "compression ratio"),
        (corpus.zip_bomb_overlapping(), "overlapping entries"),
        (corpus.docx_bomb(200), "office document"),
    ],
)
def test_honest_bombs(data: bytes, why: str) -> None:
    name = "a.docx" if why == "office document" else "a.zip"
    policy = presets.DOCUMENTS if name.endswith(".docx") else ZIPS
    assert codes(data, name, policy) == ("archive_bomb",), why


@owasp("limits.decompressed-size", "threat.zip-bomb")
def test_nested_archives_share_one_budget() -> None:
    # 16 x 16 archives of 9 MiB each: harmless per archive, 2.25 GiB in total.
    inner = corpus.build_zip({"zeros.bin": b"\x00" * (9 * 1024 * 1024)})
    layer = corpus.build_zip({f"{i}.zip": inner for i in range(16)})
    outer = corpus.build_zip({f"{i}.zip": layer for i in range(16)})
    assert len(outer) < 20_000
    assert codes(outer, "a.zip", ZIPS) == ("archive_bomb",)


@owasp("limits.decompressed-size", "threat.zip-bomb")
def test_nesting_depth_is_limited() -> None:
    assert codes(corpus.zip_nested(3), "a.zip", ZIPS) == ()  # two archives deep: fine
    assert codes(corpus.zip_nested(5), "a.zip", ZIPS) == ("archive_bomb",)  # like 42.zip
    deeper = ZIPS.replace(content_checks=(ArchiveSafety(max_depth=5),))
    assert codes(corpus.zip_nested(5), "a.zip", deeper) == ()


@owasp("limits.decompressed-size")
def test_damaged_members_are_refused() -> None:
    assert codes(corpus.zip_with_bad_crc(), "a.zip", ZIPS) == ("archive_corrupt",)
    truncated = corpus.build_zip({"a.txt": b"abc" * 1000})
    truncated = truncated[:40] + truncated[60:]
    assert codes(truncated, "a.zip", ZIPS)[0] in (
        "archive_corrupt",
        "type_unknown",
        "type_not_allowed",
    )


@owasp("limits.decompressed-size")
@pytest.mark.parametrize(
    "method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA]
)
def test_every_compression_method_is_measured(method: int) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as zf:
        zf.writestr("a.txt", b"hello " * 1000)
    assert codes(buf.getvalue(), "a.zip", ZIPS) == ()


# --------------------------------------------------------------------------- #
# Safe extraction (CERT IDS04-J)
# --------------------------------------------------------------------------- #


@owasp("limits.safe-extraction")
@pytest.mark.parametrize(
    "member",
    [
        "../../etc/passwd",
        "/etc/passwd",
        "C:/Windows/win.ini",
        "C:\\boot.ini",
        "a/../../b",
        "..\\..\\x",
    ],
)
def test_zip_slip(member: str) -> None:
    assert codes(corpus.zip_with_member_name(member), "a.zip", ZIPS) == ("archive_unsafe_path",)


@owasp("limits.safe-extraction")
def test_zip_slip_inside_a_nested_archive() -> None:
    nested = corpus.build_zip({"inner.zip": corpus.zip_with_member_name("../../notes.txt")})
    result = validate(Upload.from_bytes(nested, "a.zip"), ZIPS)
    assert result.codes == ("archive_unsafe_path",)
    assert result.violations[0].details["paths"] == ["inner.zip/../../notes.txt"]


@owasp("limits.safe-extraction")
def test_links_encryption_and_entry_counts() -> None:
    assert codes(corpus.zip_with_symlink(), "a.zip", ZIPS) == ("archive_unsafe_path",)
    assert codes(corpus.zip_encrypted_flag(), "a.zip", ZIPS) == ("archive_encrypted",)
    many = corpus.build_zip({f"{i}.txt": b"x" for i in range(30)})
    capped = ZIPS.replace(content_checks=(ArchiveSafety(max_entries=20),))
    assert codes(many, "a.zip", capped) == ("archive_bomb",)
