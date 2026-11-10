"""OWASP Unrestricted File Upload - Prevention Methods.

The developer recommendations uploadshield implements; deployment advice is in
docs/OWASP.md.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass

import pytest

from tests.owasp.unrestricted_upload.payloads import PNG
from tests.support import corpus
from tests.support.engine import codes
from tests.support.harness import App, file
from uploadshield import InspectedFile, Policy, Upload, Violation, presets, validate, web
from uploadshield.checks import ArchiveSafety, Check
from uploadshield.sanitizers import RandomizeFilename, SafeFilename

owasp = pytest.mark.owasp
ZIPS = Policy(allowed_types={"application/zip"})


@dataclass(frozen=True)
class Crashes(Check):
    name = "crashes"

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        raise RuntimeError("bug in a parser")


@owasp("ufu.prevent.validate-first")
def test_refused_files_never_reach_the_view(app: App) -> None:
    reply = app.post("/legacy", file("cat.png", corpus.PHP_SHELL))
    assert reply.status == 415
    assert reply.rejection is not None
    assert b"sha256" not in reply.body  # the view, which hashes what it reads, never ran


@owasp("ufu.prevent.validate-first")
def test_in_doubt_files_are_discarded() -> None:
    crashing = presets.DEFAULT.extend(checks=[Crashes()])
    assert codes(PNG, "a.png", crashing) == ("check_failed",)
    assert codes(b"", "a.png") == ("file_empty",)
    assert codes(b"\x00\x01\x02 unknown", "a.bin", presets.DEFAULT)[0] in (
        "type_unknown",
        "filename_missing_extension",
    )


@owasp("ufu.prevent.extension-from-list")
@pytest.mark.parametrize(
    ("data", "name", "expected"),
    [
        (corpus.image("JPEG"), "photo.JPEG", ".jpg"),
        (corpus.image("JPEG"), "photo.exe", ".jpg"),
        (corpus.png(), "no-extension", ".png"),
        (corpus.pdf(), "cv.php", ".pdf"),
    ],
)
def test_generated_names_take_the_extension_from_the_content(
    data: bytes, name: str, expected: str
) -> None:
    lenient = presets.DEFAULT.replace(
        filename=presets.DEFAULT.filename.__class__(
            forbidden_extensions=frozenset(), require_extension=False
        ),
        match_extension=False,
        sanitizers=(RandomizeFilename(),),
    )
    result = validate(Upload.from_bytes(data, name), lenient)
    assert result.sanitized is not None
    assert result.sanitized.name.endswith(expected)


@owasp("ufu.prevent.strict-names")
@pytest.mark.parametrize(
    "name",
    [
        "My CV (final).pdf",
        "résumé.v2.final.pdf",
        "a.b.c.d.pdf",
        "weird!!name$$.pdf",
        "сведения.pdf",
    ],
)
def test_safe_names_have_one_dot_and_a_restricted_alphabet(name: str) -> None:
    policy = presets.PDF.replace(sanitizers=(SafeFilename(),))
    result = validate(Upload.from_bytes(corpus.pdf(), name), policy)
    assert result.sanitized is not None
    assert re.fullmatch(r"[A-Za-z0-9_\- ]{1,200}\.pdf", result.sanitized.name), (
        result.sanitized.name
    )


@owasp("ufu.prevent.size-limits")
def test_maximum_and_empty_files() -> None:
    small = Policy(allowed_types={"text/plain"}, max_size=100)
    assert codes(b"x" * 100, "a.txt", small) == ()
    assert codes(b"x" * 101, "a.txt", small) == ("file_too_large",)
    assert codes(b"", "a.txt", small) == ("file_empty",)  # the only minimum there is


@owasp("ufu.prevent.logging")
@pytest.mark.parametrize(
    "name",
    ["cat.png\nINFO admin logged in", "cat.png\r\n2026-11-09 forged line", "cat\x1b[31m.png"],
)
def test_names_cannot_forge_log_lines(name: str, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="uploadshield")
    result = validate(Upload.from_bytes(corpus.PHP_SHELL, name), presets.DEFAULT)
    web.log_rejection(result, field="file", policy_name="default", mode="enforce")
    (record,) = caplog.records
    message = record.getMessage()
    assert "\n" not in message
    assert "\r" not in message
    assert "\x1b" not in message
    assert record.__dict__["upload"]["name"] == name  # the structured data stays exact


@owasp("ufu.prevent.logging")
@pytest.mark.parametrize("field", ["file\nINFO admin logged in", "f\r\n2026-11-09 forged"])
def test_field_names_cannot_forge_log_lines(field: str, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="uploadshield")
    result = validate(Upload.from_bytes(corpus.PHP_SHELL, "cat.png"), presets.DEFAULT)
    web.log_rejection(result, field=field, policy_name="default", mode="enforce")
    (record,) = caplog.records
    assert "\n" not in record.getMessage()
    assert "\r" not in record.getMessage()
    assert record.__dict__["upload"]["field"] == field


@owasp("ufu.prevent.logging")
def test_every_refusal_is_logged_with_its_hash(app: App, caplog: pytest.LogCaptureFixture) -> None:
    import hashlib

    caplog.set_level(logging.WARNING, logger="uploadshield")
    app.post("/legacy", file("cat.png", corpus.PHP_SHELL))
    (record,) = [r for r in caplog.records if r.name == "uploadshield"]
    assert record.__dict__["upload"]["sha256"] == hashlib.sha256(corpus.PHP_SHELL).hexdigest()


@owasp("ufu.prevent.archive-members")
@pytest.mark.parametrize(
    "member",
    [
        "shell.php",
        "dir/shell.PHP",
        ".htaccess",
        "web.config",
        "x.php.png",
        "run.bat",
        "crossdomain.xml",
        "app.jsp",
    ],
)
def test_each_member_of_an_archive_is_checked(member: str) -> None:
    archive = corpus.build_zip({"readme.txt": b"hello", member: b"payload"})
    result = validate(Upload.from_bytes(archive, "a.zip"), ZIPS)
    assert result.codes == ("archive_dangerous_member",)
    assert result.violations[0].details["members"] == [member]


@owasp("ufu.prevent.archive-members")
def test_members_of_nested_archives_and_documents() -> None:
    nested = corpus.build_zip({"inner.zip": corpus.build_zip({"shell.php": b"x"})})
    result = validate(Upload.from_bytes(nested, "a.zip"), ZIPS)
    assert result.violations[0].details["members"] == ["inner.zip/shell.php"]
    # Office documents are archives too; their ordinary parts are fine.
    for document, name in ((corpus.ooxml("docx"), "a.docx"), (corpus.odt(), "a.odt")):
        assert codes(document, name, presets.DOCUMENTS) == ()


@owasp("ufu.prevent.archive-members")
def test_what_member_checks_do_not_cover() -> None:
    # The documented limit of "partial": member names are judged, member contents are not
    # validated against a policy (a script named notes.txt passes).
    assert codes(corpus.build_zip({"notes.txt": corpus.PHP_SHELL}), "a.zip", ZIPS) == ()
    relaxed = ZIPS.replace(content_checks=(ArchiveSafety(check_member_names=False),))
    assert codes(corpus.build_zip({"shell.php": b"x"}), "a.zip", relaxed) == ()
