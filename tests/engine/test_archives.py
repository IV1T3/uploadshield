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


# --------------------------------------------------------------------------- #
# Tar archives, plain and compressed (gzip, bzip2, xz)
# --------------------------------------------------------------------------- #

COMPRESSIONS = list(corpus.TAR_COMPRESSIONS)
TAR_IDS = ["tar", "tar.gz", "tar.bz2", "tar.xz"]


def tar_policy(compression: str, **options: object) -> Policy:
    policy = Policy(allowed_types={corpus.TAR_TYPES[compression]}, max_size=None)
    return policy.replace(content_checks=(ArchiveSafety(**options),)) if options else policy


def tar_codes(compression: str, data: bytes, **options: object) -> set[str]:
    name = "a.tar" + (f".{compression}" if compression else "")
    return set(codes(data, name, tar_policy(compression, **options)))


@pytest.mark.parametrize("compression", COMPRESSIONS, ids=TAR_IDS)
def test_clean_tar_archives_are_accepted(compression: str) -> None:
    archive = corpus.build_tar({"docs/readme.txt": b"hello", "docs/": b""}, compression=compression)
    assert tar_codes(compression, archive) == set()


@pytest.mark.owasp("limits.safe-extraction")
@pytest.mark.parametrize("compression", COMPRESSIONS, ids=TAR_IDS)
@pytest.mark.parametrize(
    "member", ["../../etc/passwd", "/etc/passwd", "C:/Windows/win.ini", "a/../../b", "..\\..\\x"]
)
def test_tar_slip_is_refused(compression: str, member: str) -> None:
    archive = corpus.build_tar({member: b"payload"}, compression=compression)
    assert tar_codes(compression, archive) == {"archive_unsafe_path"}


@pytest.mark.owasp("limits.safe-extraction")
@pytest.mark.parametrize("compression", COMPRESSIONS, ids=TAR_IDS)
def test_tar_links_and_special_files_are_refused(compression: str) -> None:
    for archive in (
        corpus.build_tar(links={"www": "/var/www/html"}, compression=compression),
        corpus.build_tar(hardlinks={"passwd": "../../etc/passwd"}, compression=compression),
        corpus.build_tar(devices=("dev/sda",), compression=compression),
    ):
        assert tar_codes(compression, archive) == {"archive_unsafe_path"}


@pytest.mark.parametrize("compression", COMPRESSIONS, ids=TAR_IDS)
def test_tar_members_that_servers_execute_are_refused(compression: str) -> None:
    # A regular member named "shell.php/" is extracted by tarfile as the file shell.php.
    names = ("shell.php", "site/.htaccess", "web.config", "x.php.png", "x.phtml ")
    for name in (*names, "shell.php/", "site/.htaccess/", "shell.php\\"):
        archive = corpus.build_tar({name: b"x"}, compression=compression)
        assert tar_codes(compression, archive) == {"archive_dangerous_member"}, name
    allowed = corpus.build_tar({"shell.php": b"x"}, compression=compression)
    assert tar_codes(compression, allowed, check_member_names=False) == set()


def test_a_tar_slip_to_a_script_reports_both() -> None:
    from uploadshield import Upload, validate

    archive = corpus.build_tar({"../../var/www/html/shell.php": b"x"}, compression="gz")
    result = validate(Upload.from_bytes(archive, "a.tar.gz"), tar_policy("gz"))
    assert {v.code: dict(v.details) for v in result.violations} == {
        "archive_unsafe_path": {"paths": ["../../var/www/html/shell.php"]},
        "archive_dangerous_member": {"members": ["../../var/www/html/shell.php"]},
    }


def test_members_after_the_end_of_archive_marker_are_judged() -> None:
    # tar --ignore-zeros extracts what follows the two zero blocks; so must the check.
    hidden = corpus.build_tar({"ok.txt": b"x"}) + corpus.build_tar({"shell.php": b"x"})
    assert tar_codes("", hidden) == {"archive_dangerous_member"}
    assert tar_codes("gz", corpus.TAR_COMPRESSIONS["gz"](hidden)) == {"archive_dangerous_member"}


def test_archives_inside_tar_archives_are_walked() -> None:
    from uploadshield import Upload, validate

    site = corpus.build_zip({"index.html": b"<p>", "shell.php": b"x"})
    inner = corpus.build_tar({"conf/.htaccess": b"x"}, compression="xz")
    archive = corpus.build_tar({"site.zip": site, "inner.tar.xz": inner}, compression="gz")
    result = validate(Upload.from_bytes(archive, "a.tar.gz"), tar_policy("gz"))
    assert result.codes == ("archive_dangerous_member", "archive_dangerous_member")
    assert [v.details["members"] for v in result.violations] == [
        ["site.zip/shell.php"],
        ["inner.tar.xz/conf/.htaccess"],
    ]


def test_tar_archives_inside_zip_archives_are_walked() -> None:
    from uploadshield import Upload, validate

    inner = corpus.build_tar({"../escape.txt": b"x"}, compression="bz2")
    archive = corpus.build_zip({"backup.tar.bz2": inner})
    result = validate(Upload.from_bytes(archive, "a.zip"), ZIP_POLICY)
    assert result.codes == ("archive_unsafe_path",)
    assert result.violations[0].details["paths"] == ["backup.tar.bz2/../escape.txt"]


@pytest.mark.owasp("limits.decompressed-size")
def test_tar_bombs_are_refused_while_they_decompress() -> None:
    import time

    started = time.perf_counter()
    assert tar_codes("gz", corpus.tar_gz_bomb(900)) == {"archive_bomb"}  # ratio, measured
    assert time.perf_counter() - started < 10
    # The byte budget holds even when the ratio looks harmless.
    members = {f"{i}.bin": bytes(range(256)) * 2000 for i in range(4)}  # 4 x 512 KB
    archive = corpus.build_tar(members, compression="gz")
    assert tar_codes("gz", archive, max_uncompressed_bytes=1_500_000) == {"archive_bomb"}
    assert tar_codes("gz", archive) == set()


def test_declared_tar_sizes_and_member_counts_are_capped() -> None:
    import tarfile

    # A header declaring 2 GiB (or a sparse file of that size) is refused before reading.
    info = tarfile.TarInfo("huge.bin")
    info.size = 2 * 1024**3
    assert tar_codes("", info.tobuf() + b"\x00" * 1024) == {"archive_bomb"}
    many = corpus.build_tar({f"{i}.txt": b"x" for i in range(30)}, compression="gz")
    assert tar_codes("gz", many, max_entries=10) == {"archive_bomb"}


def test_nesting_depth_and_nested_size_are_capped() -> None:
    leaf = corpus.build_tar({"a.bin": bytes(range(256)) * 20}, compression="gz")
    nested = corpus.build_tar({"inner.tar.gz": leaf})
    assert tar_codes("", nested) == set()
    assert tar_codes("", nested, max_nested_bytes=100) == {"archive_bomb"}
    assert tar_codes("", nested, max_depth=0) == {"archive_bomb"}
    # gzip inside gzip inside gzip... (a gzip quine never ends): each layer is a level.
    layered = b"data"
    for _ in range(6):
        layered = corpus.TAR_COMPRESSIONS["gz"](layered)
    assert tar_codes("gz", layered) == {"archive_bomb"}


@pytest.mark.parametrize("compression", ["gz", "bz2", "xz"])
def test_tar_archives_without_the_ustar_magic_are_walked(compression: str) -> None:
    # Old V7 archives have no magic; tar extracts them all the same.
    v7 = corpus.tar_v7("../../var/www/html/shell.php", b"x")
    compressed = corpus.TAR_COMPRESSIONS[compression](v7)
    assert tar_codes(compression, compressed) == {"archive_unsafe_path", "archive_dangerous_member"}


@pytest.mark.parametrize("compression", ["gz", "bz2", "xz"])
def test_a_tar_archive_behind_leading_junk_is_refused(compression: str) -> None:
    # GNU tar skips to the next valid header: tar -xzf would extract shell.php.
    hidden = b"\x01" * 512 + corpus.build_tar({"shell.php": b"x"})
    compressed = corpus.TAR_COMPRESSIONS[compression](hidden)
    assert tar_codes(compression, compressed) == {"archive_corrupt"}
    v7 = b"junk".ljust(1024, b"\x02") + corpus.tar_v7("shell.php", b"x")
    assert tar_codes(compression, corpus.TAR_COMPRESSIONS[compression](v7)) == {"archive_corrupt"}
    # Starting like another archive does not hide it either.
    fake_zip = b"PK\x03\x04".ljust(512, b"\x03") + corpus.build_tar({"shell.php": b"x"})
    compressed = corpus.TAR_COMPRESSIONS[compression](fake_zip)
    assert tar_codes(compression, compressed) == {"archive_corrupt"}


def test_text_that_merely_looks_like_tar_magic_is_not_refused() -> None:
    # "mustard" puts "ustar" at offset 257 of every block, the first one included; only
    # a valid checksum makes a header, for tar and for this check.
    base = (b"recipe,ingredient\n" * 30)[:512]
    block = base[:256] + b"mustard" + base[263:]
    assert block[257:262] == b"ustar"
    assert tar_codes("gz", corpus.TAR_COMPRESSIONS["gz"](block * 6)) == set()


@pytest.mark.parametrize("compression", ["gz", "bz2", "xz"])
def test_compressed_files_that_hold_no_archive_are_measured(compression: str) -> None:
    compress = corpus.TAR_COMPRESSIONS[compression]
    assert tar_codes(compression, compress(b"a,b\n1,2\n" * 5000)) == set()
    assert tar_codes(compression, compress(b"\x00" * (64 * 1024 * 1024))) == {"archive_bomb"}
    zipped = compress(corpus.build_zip({"shell.php": b"x"}))  # site.zip.gz
    assert tar_codes(compression, zipped) == {"archive_dangerous_member"}


@pytest.mark.parametrize("compression", COMPRESSIONS, ids=TAR_IDS)
def test_damaged_tar_archives_fail_closed(compression: str) -> None:
    archive = corpus.build_tar({"a.bin": bytes(range(256)) * 400}, compression=compression)
    truncated = archive[: len(archive) // 2]
    assert tar_codes(compression, truncated) == {"archive_corrupt"}


def test_damaged_tar_headers_are_refused_not_skipped() -> None:
    # A lenient extractor may read a member where tarfile sees a bad checksum.
    ok = corpus.build_tar({"a.txt": b"x"})
    damaged = bytearray(corpus.build_tar({"shell.txt": b"x"}))
    damaged[148:156] = b"0000000\x00"  # wrong checksum
    archive = ok[:1024] + bytes(damaged[:1024]) + ok[1024:]
    assert tar_codes("", archive) == {"archive_corrupt"}
    assert tar_codes("", ok + b"junk" * 128) == {"archive_corrupt"}  # not zeros after the end
    assert tar_codes("", ok + b"\x00" * 4096) == set()  # zero padding is normal


def test_negative_tar_sizes_fail_closed_without_hanging() -> None:
    # CVE-2025-8194: negative offsets made tarfile loop forever on some Pythons.
    import time

    started = time.perf_counter()
    assert tar_codes("", corpus.tar_with_negative_size()) == {"archive_corrupt"}
    assert time.perf_counter() - started < 2


def test_tar_archives_with_many_members_are_checked_in_linear_time() -> None:
    import time

    archive = corpus.build_tar({f"src/f{i}.txt": b"x" for i in range(5000)}, compression="gz")
    started = time.perf_counter()
    assert tar_codes("gz", archive) == set()
    assert time.perf_counter() - started < 5


# --------------------------------------------------------------------------- #
# Archives no check opens
# --------------------------------------------------------------------------- #


def test_wildcards_never_match_archives_that_cannot_be_inspected() -> None:
    from uploadshield.checks import UNINSPECTED_ARCHIVES

    anything = Policy(allowed_types={"application/*"})
    assert {"application/x-7z-compressed", "application/vnd.rar"} == UNINSPECTED_ARCHIVES
    for mime in UNINSPECTED_ARCHIVES:
        assert not anything.allows_mime(mime), mime
    for mime in ("application/zip", *corpus.TAR_TYPES.values()):
        assert anything.allows_mime(mime), mime  # these are opened and inspected
    assert codes(corpus.SEVEN_ZIP, "a.7z", anything) == ("type_not_allowed",)
    # Naming the type is the explicit opt-in to accept what cannot be looked into.
    assert (
        codes(corpus.SEVEN_ZIP, "a.7z", Policy(allowed_types={"application/x-7z-compressed"})) == ()
    )
