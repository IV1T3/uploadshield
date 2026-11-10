"""``uploadshield validate``: a policy's verdict, the trace behind it, and --save."""

from __future__ import annotations

import io
from pathlib import Path
from typing import TYPE_CHECKING

from PIL import Image

from tests.support import corpus

if TYPE_CHECKING:
    from tests.cli.conftest import Cli


def test_accepted_files_show_their_trace(cli: Cli, tmp_path: Path) -> None:
    (tmp_path / "a.pdf").write_bytes(corpus.pdf())
    run = cli("validate", tmp_path / "a.pdf", "--policy", "pdf")
    assert run.status == 0
    assert 'accepted by "pdf"' in run.out
    assert "PDF document (application/pdf)" in run.out
    assert "\u2713 size  \u2713 filename  \u2713 type  \u2713 extension  \u2713 pdf" in run.out
    assert "not applicable: archive" in run.out


def test_refused_files_show_why(cli: Cli, tmp_path: Path) -> None:
    (tmp_path / "cat.png").write_bytes(corpus.PHP_SHELL)
    run = cli("validate", tmp_path / "cat.png", "--policy", "images")
    assert run.status == 1
    assert 'refused by "images" (dangerous)' in run.out
    assert "\u2717 type_not_allowed  PHP script files are not allowed." in run.out
    assert "detected_type: application/x-httpd-php" in run.out
    assert "not run after the first failure: extension" in run.out
    assert "uploadshield explain type_not_allowed" in run.out


def test_all_checks(cli: Cli, tmp_path: Path) -> None:
    (tmp_path / "shell.php.png").write_bytes(corpus.PHP_SHELL)
    first = cli("validate", tmp_path / "shell.php.png", "--json").json()["files"][0]
    every = cli("validate", tmp_path / "shell.php.png", "--all-checks", "--json").json()
    codes = [e["code"] for e in every["files"][0]["errors"]]
    assert len(first["errors"]) == 1
    assert {"filename_dangerous_extension", "type_not_allowed", "embedded_code"} <= set(codes)


def test_policies_by_dotted_path(cli: Cli, tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_bytes(b"hello\n")
    ok = cli(
        "validate", tmp_path / "notes.txt", "--policy", "tests.django_site.testapp.policies.CUSTOM"
    )
    assert ok.status == 0
    assert 'accepted by "custom"' in ok.out
    wrong = cli(
        "validate",
        tmp_path / "notes.txt",
        "--policy",
        "tests.django_site.testapp.policies.NOT_A_POLICY",
    )
    assert wrong.status == 2
    assert "is not a uploadshield.Policy" in wrong.err
    unknown = cli("validate", tmp_path / "notes.txt", "--policy", "imgaes")
    assert unknown.status == 2
    assert "Known policies: default, documents, images" in unknown.err


def test_declared_types(cli: Cli, tmp_path: Path) -> None:
    (tmp_path / "a.pdf").write_bytes(corpus.pdf())
    ignored = cli("validate", tmp_path / "a.pdf", "--policy", "pdf", "--declared-type", "image/png")
    assert ignored.status == 0
    assert "--declared-type has no effect" in ignored.err
    strict = cli(
        "validate",
        tmp_path / "a.pdf",
        "--policy",
        "tests.cli.policies.STRICT_TYPES",
        "--declared-type",
        "image/png",
    )
    assert strict.status == 1
    assert "declared_type_mismatch" in strict.out


def test_save_writes_what_would_be_stored(cli: Cli, tmp_path: Path) -> None:
    photo = tmp_path / "me.jpg"
    photo.write_bytes(corpus.jpeg_with_metadata())
    out = tmp_path / "out"
    run = cli("validate", photo, "--policy", "sanitized_images", "--save", out, "--json")
    assert run.status == 0
    entry = run.json()["files"][0]
    saved = Path(entry["saved"])
    assert saved.parent == out
    assert saved.name == entry["sanitized_as"]["name"] != "me.jpg"
    with Image.open(io.BytesIO(saved.read_bytes())) as image:
        assert not image.getexif()  # re-encoded: metadata gone


def test_save_never_overwrites_and_skips_refused_files(cli: Cli, tmp_path: Path) -> None:
    (tmp_path / "Report Final.pdf").write_bytes(corpus.pdf())
    (tmp_path / "cat.png").write_bytes(corpus.PHP_SHELL)
    out = tmp_path / "out"
    policy = ("--policy", "tests.cli.policies.SAFE_NAMES", "--save", out)
    first = cli("validate", tmp_path / "Report Final.pdf", *policy)
    assert first.status == 0
    assert (out / "Report_Final.pdf").read_bytes() == corpus.pdf()  # renamed only
    again = cli("validate", tmp_path / "Report Final.pdf", *policy)
    assert again.status == 2
    assert "never overwritten" in again.out
    assert cli("validate", tmp_path / "cat.png", *policy).status == 1
    assert sorted(p.name for p in out.iterdir()) == ["Report_Final.pdf"]


def test_standard_input(cli: Cli, tmp_path: Path) -> None:
    run = cli(
        "validate",
        "-",
        "--name",
        "a.pdf",
        "--policy",
        "pdf",
        "--save",
        tmp_path,
        stdin=corpus.pdf(),
    )
    assert run.status == 0
    assert "<stdin>" in run.out
    assert "a.pdf" in run.out
    assert (tmp_path / "a.pdf").read_bytes() == corpus.pdf()


def test_names_are_judged_as_given(cli: Cli, tmp_path: Path) -> None:
    (tmp_path / "upload.bin").write_bytes(corpus.pdf())
    run = cli("validate", tmp_path / "upload.bin", "--policy", "pdf", "--name", "cv.pdf.php")
    assert run.status == 1
    assert "as         cv.pdf.php" in run.out
    assert "filename_dangerous_extension" in run.out
    undecodable = cli("validate", "-", "--name", "a" + chr(0xDCFF) + ".pdf", stdin=corpus.pdf())
    assert undecodable.status == 1
    assert "filename_invalid" in undecodable.out
    assert "a\\udcff.pdf" in undecodable.out
