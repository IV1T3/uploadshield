"""FilenameCheck: names that attack storage, servers or users."""

from __future__ import annotations

import pytest

from tests.support import corpus
from tests.support.engine import codes
from uploadshield import presets


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("shell.php.png", "filename_dangerous_extension"),
        ("shell.PHP5.png", "filename_dangerous_extension"),
        ("shell.asp;.png", "filename_dangerous_extension"),
        ("shell.aspx::$DATA.png", "filename_dangerous_extension"),
        ("shell.php .png", "filename_dangerous_extension"),
        ("payload.exe.png", "filename_dangerous_extension"),
        (".htaccess", "filename_reserved"),
        ("web.config", "filename_reserved"),
        (".user.ini", "filename_reserved"),
        (".hidden.png", "filename_hidden"),
        ("CON.png", "filename_reserved"),
        ("lpt1.png", "filename_reserved"),
        ("image.png.", "filename_invalid"),
        ("image.png ", "filename_invalid"),
        ("evil\u202egnp.exe.png", "filename_invalid"),
        ("tab\there.png", "filename_invalid"),
        ("dir/name.png", "filename_invalid"),
        ("dir\\name.png", "filename_invalid"),
        ("C:x.png", "filename_invalid"),  # drive-relative: escapes the upload dir on Windows
        ("photo.png:payload", "filename_invalid"),  # NTFS alternate data stream
        ("a" * 252 + ".png", "filename_too_long"),
        ("\u00e9" * 130 + ".png", "filename_too_long"),  # 255 limit is in bytes
        ("noextension", "filename_missing_extension"),
        ("   ", "filename_invalid"),
    ],
)
def test_filename_attacks(name: str, expected: str) -> None:
    assert expected in codes(corpus.png(), name)


@pytest.mark.parametrize(
    "name",
    [
        "photo.png",
        "My Photo (1).png",
        "report.final.v2.png",
        "Screenshot 2026-01-01 at 10.00.00\u202fAM.png",  # macOS uses U+202F
        "family-\U0001f468\u200d\U0001f469\u200d\U0001f467.png",  # emoji ZWJ sequence
        "\u00fcberwachung.png",
        "a" * 251 + ".png",
    ],
)
def test_legitimate_filenames_pass(name: str) -> None:
    assert codes(corpus.png(), name) == ()


def test_filename_check_is_configurable() -> None:
    lenient = presets.IMAGES.replace(
        filename=presets.IMAGES.filename.__class__(allow_hidden=True, require_extension=False)
    )
    assert codes(corpus.png(), ".avatar.png", lenient) == ()


def test_names_that_are_not_valid_utf8_are_refused() -> None:
    # os.listdir() returns undecodable bytes as lone surrogates ("\udcff").
    name = "photo\udcff.png"
    assert codes(corpus.png(), name) == ("filename_invalid",)
    long = "\udcff" * 300 + ".png"
    assert "filename_too_long" in validate_all(long)


def validate_all(name: str) -> tuple[str, ...]:
    from uploadshield import Upload, validate

    policy = presets.DEFAULT.replace(fail_fast=False)
    return validate(Upload.from_bytes(corpus.png(), name), policy).codes


def test_reserved_names_are_exported_with_the_other_constants() -> None:
    from uploadshield.checks import WINDOWS_RESERVED_NAMES

    assert {"con", "nul", "com1", "lpt9", "conin$"} <= WINDOWS_RESERVED_NAMES
