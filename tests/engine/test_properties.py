"""Property-based tests: the engine must never crash or accept garbage as a known type."""

from __future__ import annotations

import logging
from collections.abc import Generator
from contextlib import contextmanager

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.support import corpus
from uploadshield import Policy, Upload, ValidationResult, Violation, presets, validate
from uploadshield.checks import FilenameCheck

SIGNATURES = [
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"GIF89a",
    b"%PDF-",
    b"PK\x03\x04",
    b"RIFF",
    b"\x00\x00\x00\x18ftyp",
    b"\x1a\x45\xdf\xa3",
    b"MZ",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    b"<?xml",
    b"<svg",
    b"ID3",
    b"\xff\xfb",
    b"\xff\xfe",
    b"BM",
    b"\x00\x00\x01\x00",
    b"\x1f\x8b\x08",
    b"BZh9",
    b"\xfd7zXZ\x00",
]
REAL_FILES = [
    corpus.png(),
    corpus.image("JPEG"),
    corpus.pdf(),
    corpus.ooxml("docx"),
    corpus.animated_gif(),
    corpus.odt(),
    corpus.build_tar({"a.txt": b"hello", "b/c.txt": b"x" * 600}),
    corpus.build_tar({"a.txt": b"hello"}, compression="gz"),
    corpus.build_tar({"a.txt": b"hello"}, compression="xz"),
]

ALL_TYPES_POLICY = Policy(
    allowed_types={"image/*", "audio/*", "video/*", "application/*", "text/*"}, fail_fast=False
)


@contextmanager
def no_errors_logged() -> Generator[None, None, None]:
    """Sniffers fail closed silently; make sure a crash still shows up in the tests."""
    records: list[logging.LogRecord] = []

    class Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = Collect(logging.ERROR)
    logger = logging.getLogger("uploadshield")
    logger.addHandler(handler)
    try:
        yield
    finally:
        logger.removeHandler(handler)
    assert not records, [r.getMessage() for r in records]


fuzz_settings = settings(
    max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)


def crashed(result: ValidationResult) -> list[Violation]:
    """``check_failed`` other than "too large to verify" (headers may claim any size)."""
    return [
        v
        for v in result.violations
        if v.code == "check_failed" and v.message != "The file is too large to be verified."
    ]


@pytest.mark.owasp("threat.parser-exploit")
@fuzz_settings
@given(prefix=st.sampled_from(SIGNATURES), tail=st.binary(max_size=2048), name=st.text(max_size=80))
def test_engine_never_raises_on_hostile_input(prefix: bytes, tail: bytes, name: str) -> None:
    for policy in (presets.DEFAULT, ALL_TYPES_POLICY, presets.SANITIZED_IMAGES):
        with no_errors_logged():
            result = validate(Upload.from_bytes(prefix + tail, name), policy)
        assert all(isinstance(code, str) for code in result.codes)
        assert not crashed(result), result.violations


@pytest.mark.owasp("threat.parser-exploit")
@fuzz_settings
@given(original=st.sampled_from(REAL_FILES), data=st.data())
def test_mutated_real_files_never_crash_checks(original: bytes, data: st.DataObject) -> None:
    position = data.draw(st.integers(0, len(original) - 1))
    junk = data.draw(st.binary(min_size=1, max_size=64))
    mutated = original[:position] + junk + original[position + len(junk) :]
    with no_errors_logged():
        result = validate(Upload.from_bytes(mutated, "file"), ALL_TYPES_POLICY)
    assert not crashed(result), result.violations


@pytest.mark.owasp("extension.vetted-logic")
@fuzz_settings
@given(name=st.text(min_size=1, max_size=300))
def test_filename_check_is_total(name: str) -> None:
    file_check = FilenameCheck()
    policy = Policy(allowed_types={"image/png"}, filename=file_check)
    result = validate(Upload.from_bytes(corpus.png(), name), policy)
    if result.ok:
        # Anything accepted is safe to hand to a filesystem as-is.
        assert "/" not in name
        assert "\\" not in name
        assert "\x00" not in name
        assert not name.startswith(".")
        assert len(name.encode()) <= 255
        assert name.lower().endswith(".png")
