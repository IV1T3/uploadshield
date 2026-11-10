"""Size limits, the content-type allow-list and name/content consistency."""

from __future__ import annotations

from tests.support import corpus
from tests.support.engine import codes
from uploadshield import KB, MB, Policy, presets


def test_size_limits() -> None:
    policy = Policy(allowed_types={"text/plain"}, max_size=10)
    assert codes(b"0123456789", "a.txt", policy) == ()
    assert codes(b"0123456789!", "a.txt", policy) == ("file_too_large",)
    assert codes(b"", "a.txt", policy) == ("file_empty",)
    assert codes(b"", "a.txt", policy.replace(allow_empty=True)) == ("type_unknown",)
    assert codes(b"x" * 100, "a.txt", policy.replace(max_size=None)) == ()


def test_type_allowlist_uses_content_not_name_or_header() -> None:
    php = b"<?php system($_GET['c']); ?>"
    assert codes(php, "avatar.png", presets.IMAGES, declared_type="image/png") == (
        "type_not_allowed",
    )
    assert codes(b"\x00\x01garbage", "a.png", presets.IMAGES) == ("type_unknown",)


def test_extension_must_match_content() -> None:
    assert codes(corpus.png(), "picture.jpg") == ("extension_mismatch",)
    assert codes(corpus.image("JPEG"), "picture.jpeg") == ()
    assert codes(corpus.pdf(), "invoice.pdf.png") == ("extension_mismatch",)
    assert codes(corpus.png(), "picture.jpg", presets.IMAGES.replace(match_extension=False)) == ()


def test_html_and_svg_disguised_as_images_are_refused() -> None:
    assert codes(b"<html><script>alert(1)</script></html>", "x.png") == ("type_not_allowed",)
    assert codes(corpus.svg(), "logo.png", presets.IMAGES) == ("type_not_allowed",)
    assert codes(b"<!-- --><img src=x onerror=alert(1)>", "x.txt") == ("type_not_allowed",)


def test_wildcards_never_grant_scriptable_or_executable_types() -> None:
    policy = Policy(allowed_types={"image/*", "text/*", "application/*"})
    assert codes(corpus.png(), "a.png", policy) == ()
    assert codes(corpus.svg(), "a.svg", policy) == ("type_not_allowed",)
    assert codes(b"<!doctype html><p>x", "a.html", policy) == ("type_not_allowed",)
    assert codes(corpus.pe_executable(), "a.exe", policy) == ("filename_dangerous_extension",)
    assert codes(
        corpus.pe_executable(),
        "a.dll.bin",
        policy.replace(filename=policy.filename.__class__(forbidden_extensions=frozenset())),
    ) == ("type_not_allowed",)
    explicit = Policy(allowed_types={"image/svg+xml"}, content_checks=())
    assert codes(corpus.svg(), "a.svg", explicit) == ()


def test_declared_type_check_is_opt_in() -> None:
    strict = presets.IMAGES.replace(match_declared_type=True)
    assert codes(corpus.png(), "a.png", strict, declared_type="image/png") == ()
    assert codes(corpus.png(), "a.png", strict, declared_type="image/x-png") == ()
    assert codes(corpus.png(), "a.png", strict, declared_type="application/octet-stream") == ()
    assert codes(corpus.png(), "a.png", strict, declared_type="image/gif") == (
        "declared_type_mismatch",
    )
    csv = Policy(allowed_types={"text/csv"}, match_declared_type=True)
    assert codes(b"a,b", "a.csv", csv, declared_type="text/plain") == ()  # parent type ok
    assert codes(b"a,b", "a.csv", presets.DOCUMENTS, declared_type="application/vnd.ms-excel") == ()


def test_size_units() -> None:
    assert KB == 1000
    assert MB == 1000 * KB
