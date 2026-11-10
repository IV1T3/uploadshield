"""OWASP File Upload Cheat Sheet - storage location, filesystem permissions, and the
core principles of the introduction that are not covered elsewhere.

Most of these belong to the application or the deployment (docs/OWASP.md); the tests
here pin down how uploadshield behaves where it meets them.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest

from tests.support import corpus
from tests.support.engine import codes
from tests.support.harness import App, file
from uploadshield import InspectedFile, Upload, Violation, presets, validate
from uploadshield.checks import Check

owasp = pytest.mark.owasp


# --------------------------------------------------------------------------- #
# File storage location
# --------------------------------------------------------------------------- #


@owasp("storage.config-overrides")
@pytest.mark.parametrize(
    "name",
    [".htaccess", ".HTACCESS", ".htpasswd", "web.config", "Web.Config", ".user.ini", "php.ini"],
)
def test_server_configuration_files_are_refused_everywhere(app: App, name: str) -> None:
    reply = app.post("/legacy", file(name, b"AddType application/x-httpd-php .png\n"))
    assert reply.status == 400
    assert "filename_reserved" in reply.codes


@owasp("storage.unstored")
def test_files_that_are_only_processed_get_the_same_checks() -> None:
    # e.g. an e-mail attachment handed to a worker: no web framework involved.
    attachment = Upload.from_bytes(corpus.docx_with_remote_template(), "invoice.docx")
    assert validate(attachment, presets.DOCUMENTS).codes == ("office_external_reference",)


@owasp("storage.unstored")
def test_storage_validates_outside_requests(tmp_path: Any) -> None:
    from django.core.files.base import ContentFile

    from uploadshield.django.exceptions import UploadRejected
    from uploadshield.django.storage import ValidatingStorage

    storage = ValidatingStorage(options={"location": str(tmp_path)}, policy="documents")
    with pytest.raises(UploadRejected):  # a Celery task, a management command, ...
        storage.save("import/cv.pdf", ContentFile(corpus.PHP_SHELL))
    assert list(tmp_path.rglob("*")) == []


@owasp("storage.separate-host")
def test_any_storage_backend_can_be_wrapped() -> None:
    django = pytest.importorskip("django")
    if django.VERSION < (4, 2):
        pytest.skip("InMemoryStorage is Django 4.2+")
    from django.core.files.base import ContentFile

    from uploadshield.django.exceptions import UploadRejected
    from uploadshield.django.storage import ValidatingStorage

    remote = ValidatingStorage(backend="django.core.files.storage.InMemoryStorage", policy="images")
    assert remote.save("a.png", ContentFile(corpus.png())) == "a.png"
    with pytest.raises(UploadRejected):
        remote.save("b.png", ContentFile(corpus.PHP_SHELL))


# --------------------------------------------------------------------------- #
# Filesystem permissions: nothing executable gets stored
# --------------------------------------------------------------------------- #


@owasp("filesystem.scan-before-execute")
@pytest.mark.parametrize(
    ("data", "name"),
    [
        (corpus.pe_executable(), "setup.pdf"),
        (corpus.ELF, "tool.png"),
        (corpus.SHELL_SCRIPT, "run.txt"),
        (corpus.PHP_SHELL, "index.txt"),
        (corpus.ooxml("docm"), "macros.docx"),
        (corpus.pdf_with_javascript(), "auto.pdf"),
        (corpus.image("JPEG", comment=b"<?php system($_GET[0]); ?>"), "a.jpg"),
    ],
    ids=["pe", "elf", "shell", "php", "docm", "pdf-js", "php-in-jpeg"],
)
def test_executables_scripts_and_macros_are_refused(app: App, data: bytes, name: str) -> None:
    path = "/legacy" if name.endswith(".jpg") else "/documents"
    assert app.post(path, file(name, data)).status in (400, 415)


# --------------------------------------------------------------------------- #
# Introduction: validate input first
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class MustNotRun(Check):
    name = "must_not_run"

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        raise AssertionError("content was inspected although the name was refused")


@owasp("intro.input-first")
def test_names_are_refused_before_any_content_is_inspected() -> None:
    policy = presets.DEFAULT.extend(checks=[MustNotRun()])
    result = validate(Upload.from_bytes(corpus.png(), "shell.php.png"), policy)
    assert result.codes == ("filename_dangerous_extension",)
    assert result.checks_run == ("size", "filename")


@owasp("intro.input-first")
def test_the_pipeline_runs_cheapest_first() -> None:
    names = [check.name for check in presets.DEFAULT.pipeline]
    assert names[:4] == ["size", "filename", "type", "extension"]
    assert codes(corpus.PHP_SHELL, "shell.php.png") == ("filename_dangerous_extension",)
    assert codes(corpus.PHP_SHELL, "cat.png") == ("type_not_allowed",)
