"""``explain`` and ``policies``, and the verdict each violation code gets."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from tests.support import corpus
from uploadshield import Code, Upload, presets, validate
from uploadshield.cli._scan import scan_policy
from uploadshield.cli._verdicts import CODE_INFO, Verdict, judge

if TYPE_CHECKING:
    from tests.cli.conftest import Cli


def test_every_code_is_explained() -> None:
    assert set(CODE_INFO) == set(Code)
    for info in CODE_INFO.values():
        assert info.title
        assert info.meaning.endswith(".")
        assert info.relax


@pytest.mark.parametrize("code", [str(c) for c in Code])
def test_explain_each_code(cli: Cli, code: str) -> None:
    run = cli("explain", code)
    assert run.status == 0
    assert run.out.startswith(code)
    assert "to allow" in run.out


def test_explain_lists_codes_and_suggests_spellings(cli: Cli) -> None:
    listing = cli("explain")
    assert listing.status == 0
    assert listing.out.index("Dangerous") < listing.out.index("Not verified")
    assert "office_macros" in listing.out
    typo = cli("explain", "ofice_macro")
    assert typo.status == 2
    assert "did you mean office_macros?" in typo.err
    data = cli("explain", "type_not_allowed", "--json").json()
    (entry,) = data["codes"]
    assert entry["verdict"] == "refused"
    assert "executable" in entry["condition"]


def verdict(data: bytes, name: str, *, scan: bool, policy=None) -> Verdict:
    policy = scan_policy() if scan else policy
    result = validate(Upload.from_bytes(data, name), policy)
    return judge(result, scan=scan)[0]


def test_verdicts_depend_on_what_was_found() -> None:
    # A format a policy does not take is refused; code in disguise is dangerous.
    assert verdict(corpus.pdf(), "a.pdf", scan=False, policy=presets.IMAGES) is Verdict.REFUSED
    php = verdict(corpus.PHP_SHELL, "cat.png", scan=False, policy=presets.IMAGES)
    assert php is Verdict.DANGEROUS
    html = verdict(corpus.HTML, "page.html", scan=True)
    assert html is Verdict.DANGEROUS
    # Archives a scan cannot open are not verified; encrypted PDFs are not either.
    assert verdict(corpus.SEVEN_ZIP, "a.7z", scan=True) is Verdict.NOT_VERIFIED
    # Tar archives are opened: judged by what they hold.
    site = corpus.build_tar({"index.html": b"<p>"}, compression="gz")
    assert verdict(site, "site.tar.gz", scan=True) is Verdict.CLEAN
    slip = corpus.build_tar({"../../var/www/shell.php": b"x"}, compression="xz")
    assert verdict(slip, "site.tar.xz", scan=True) is Verdict.DANGEROUS
    assert verdict(corpus.pdf_encrypted(), "a.pdf", scan=True) is Verdict.NOT_VERIFIED
    assert verdict(corpus.pdf_with_javascript(), "a.pdf", scan=True) is Verdict.DANGEROUS
    assert verdict(corpus.png(), "a.png", scan=True) is Verdict.CLEAN


def test_scan_judges_names_only_for_danger() -> None:
    for name in (".gitignore", "Makefile", "empty.txt"):
        data = b"" if name == "empty.txt" else b"text\n"
        assert verdict(data, name, scan=True) is Verdict.CLEAN, name
    assert verdict(b"text\n", ".htaccess", scan=True) is Verdict.DANGEROUS
    assert verdict(corpus.png(), "x.php.png", scan=True) is Verdict.DANGEROUS


def test_policies_listing(cli: Cli) -> None:
    run = cli("policies")
    assert run.status == 0
    for name in presets.BUILTIN_POLICIES:
        assert name in run.out
    assert "sanitizes: reencode_image, randomize_filename" in run.out
    data = cli("policies", "--json").json()
    assert {p["name"] for p in data["policies"]} == set(presets.BUILTIN_POLICIES)


def test_policy_details(cli: Cli) -> None:
    run = cli("policies", "images")
    assert run.status == 0
    assert "JPEG image (image/jpeg)" in run.out
    assert "size \u2192 filename \u2192 type" in run.out
    assert "fail fast" in run.out
    assert cli("policies", "nope").status == 2


def test_inactive_checks_are_pointed_out(cli: Cli, monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib.util

    real = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util, "find_spec", lambda name, *a: None if name == "PIL" else real(name, *a)
    )
    run = cli("policies", "sanitized_images")
    assert "image does nothing without uploadshield[images]" in run.out
    assert "reencode_image does nothing without uploadshield[images]" in run.out
    data = cli("policies", "images", "--json").json()
    assert data["policies"][0]["inactive"] == ["image"]
    assert Path  # keep the import for type checkers
