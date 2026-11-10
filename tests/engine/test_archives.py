"""ArchiveSafety: ZIP bombs, zip slip, links and encryption."""

from __future__ import annotations

import pytest

from tests.support import corpus
from tests.support.engine import codes
from uploadshield import Policy
from uploadshield.checks import (
    ArchiveSafety,
)

ZIP_POLICY = Policy(allowed_types={"application/zip"})


@pytest.mark.parametrize(
    "member", ["../../etc/passwd", "/etc/passwd", "C:/Windows/win.ini", "a/../../b", "..\\..\\x"]
)
def test_zip_slip_is_refused(member: str) -> None:
    assert codes(corpus.zip_with_member_name(member), "a.zip", ZIP_POLICY) == (
        "archive_unsafe_path",
    )


def test_zip_symlinks_encryption_and_corruption() -> None:
    assert codes(corpus.zip_with_symlink(), "a.zip", ZIP_POLICY) == ("archive_unsafe_path",)
    assert codes(corpus.zip_encrypted_flag(), "a.zip", ZIP_POLICY) == ("archive_encrypted",)
    lenient = ZIP_POLICY.replace(content_checks=(ArchiveSafety(allow_encrypted=True),))
    assert codes(corpus.zip_encrypted_flag(), "a.zip", lenient) == ()
    assert codes(b"PK\x03\x04" + b"\x00" * 100, "a.zip", ZIP_POLICY) == ("archive_corrupt",)


def test_zip_bombs_are_refused() -> None:
    assert codes(corpus.zip_bomb_ratio(), "a.zip", ZIP_POLICY) == ("archive_bomb",)
    assert codes(corpus.zip_bomb_overlapping(), "a.zip", ZIP_POLICY) == ("archive_bomb",)
    many = corpus.build_zip({f"{i}.txt": b"x" for i in range(30)})
    capped = ZIP_POLICY.replace(content_checks=(ArchiveSafety(max_entries=10),))
    assert codes(many, "a.zip", capped) == ("archive_bomb",)
    assert codes(corpus.build_zip({"ok.txt": b"hello" * 100}), "a.zip", ZIP_POLICY) == ()


# --------------------------------------------------------------------------- #
# Measured sizes (secure size calculation) and nested archives
# --------------------------------------------------------------------------- #


def test_nested_archives_too_large_to_inspect_are_refused() -> None:
    nested = corpus.build_zip({"big.zip": corpus.build_zip({"a.txt": b"a" * 5000})})
    small_window = ZIP_POLICY.replace(content_checks=(ArchiveSafety(max_nested_bytes=100),))
    assert codes(nested, "a.zip", small_window) == ("archive_bomb",)
    assert codes(nested, "a.zip", ZIP_POLICY) == ()
    # A large member that is no archive is fine.
    plain = corpus.build_zip({"data.bin": bytes(range(256)) * 50})
    assert codes(plain, "a.zip", small_window) == ()


def test_damaged_central_directories_fail_closed() -> None:
    # Found by the property tests: a single changed byte yields a negative offset.
    original = corpus.odt()
    mutated = original[:404] + b"\xd3" + original[405:]
    assert codes(mutated, "a.zip", ZIP_POLICY) == ("archive_corrupt",)
    # A central directory that points at no local header.
    data = bytearray(corpus.build_zip({"a.txt": b"hello"}))
    data[0:4] = b"XXXX"
    assert codes(bytes(data), "a.zip", ZIP_POLICY)[0] in ("archive_corrupt", "type_unknown")


def test_large_bzip2_members_are_streamed() -> None:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_BZIP2) as zf:
        zf.writestr("zeros.bin", b"\x00" * (3 * 1024 * 1024))  # > one output chunk
    assert codes(buf.getvalue(), "a.zip", ZIP_POLICY) == ()


def test_the_byte_budget_is_shared_by_all_members() -> None:
    members = {f"{i}.bin": bytes(range(256)) * 2000 for i in range(4)}  # 4 x 512 KB
    tight = ZIP_POLICY.replace(content_checks=(ArchiveSafety(max_uncompressed_bytes=1_500_000),))
    assert codes(corpus.build_zip(members), "a.zip", tight) == ("archive_bomb",)
    assert codes(corpus.build_zip(members), "a.zip", ZIP_POLICY) == ()


def test_unsafe_paths_are_all_reported_before_measuring_stops() -> None:
    from uploadshield import Upload, validate

    archive = corpus.build_zip({"../a": b"x", "../../b": b"y", "ok.txt": b"z"})
    result = validate(Upload.from_bytes(archive, "a.zip"), ZIP_POLICY)
    assert result.codes == ("archive_unsafe_path",)
    assert result.violations[0].details["paths"] == ["../a", "../../b"]


def test_zip_head_reads_the_start_of_a_member() -> None:
    from uploadshield import BuiltinSniffer, InspectedFile, Upload
    from uploadshield.core.containers import zip_head

    archive = corpus.build_zip({"a.txt": b"hello world"})
    file = InspectedFile(Upload.from_bytes(archive, "a.zip"), BuiltinSniffer())
    assert zip_head(file, "a.txt", 5) == b"hello"
    assert zip_head(file, "missing.txt", 5) is None
    broken = InspectedFile(Upload.from_bytes(b"PK\x03\x04junk", "a.zip"), BuiltinSniffer())
    assert zip_head(broken, "a.txt", 5) is None


def test_members_whose_local_name_differs_are_refused() -> None:
    # Extractors that read local headers would write config.php; the central directory
    # (what most checks read) says config.txt.
    data = bytearray(corpus.build_zip({"config.txt": b"<?php system($_GET[0]); ?>"}))
    data[30:40] = b"config.php"
    assert codes(bytes(data), "a.zip", ZIP_POLICY) == ("archive_corrupt",)


def test_containers_with_many_members_are_checked_in_linear_time() -> None:
    import time

    epub = corpus.epub(extra={f"OEBPS/p{i}.xhtml": b"<html/>" for i in range(3000)})
    started = time.perf_counter()
    assert codes(epub, "a.epub", Policy(allowed_types={"application/epub+zip"})) == ()
    assert time.perf_counter() - started < 5
