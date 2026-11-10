"""YARA signatures (skipped where yara-python has no wheels, e.g. Python 3.14)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.support import corpus
from uploadshield import Upload, presets, validate
from uploadshield.checks import YaraRules

yara = pytest.importorskip("yara")


def scan(data: bytes, name: str, check: YaraRules) -> tuple[str, ...]:
    return validate(Upload.from_bytes(data, name), presets.DEFAULT.extend(checks=[check])).codes


WEBSHELL_RULE = """
rule php_webshell {
    strings: $a = "eval(base64_decode(" nocase
    condition: $a
}
"""


def test_yara_inline_rules() -> None:
    check = YaraRules(source=WEBSHELL_RULE)
    assert scan(b"just text", "a.txt", check) == ()
    result = validate(
        Upload.from_bytes(b"x eval(base64_decode('...'))", "a.txt"),
        presets.DEFAULT.extend(checks=[check]),
    )
    assert result.codes == ("signature_match",)
    assert result.violations[0].details["rules"] == ["php_webshell"]


def test_yara_rule_directory(tmp_path: Path) -> None:
    (tmp_path / "shells.yar").write_text(WEBSHELL_RULE)
    (tmp_path / "eicar.yara").write_text(
        'rule eicar { strings: $e = "EICAR-STANDARD" condition: $e }'
    )
    (tmp_path / "README.md").write_text("ignored")
    check = YaraRules(rules=(str(tmp_path),))
    assert scan(corpus.EICAR, "a.txt", check) == ("signature_match",)
    assert check.compile() is check.compile()  # compiled once and cached


def test_yara_configuration_errors(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="needs rule paths"):
        YaraRules()
    with pytest.raises(ValueError, match="No YARA rule files"):
        YaraRules(rules=(str(tmp_path),)).compile()
    broken = YaraRules(source="rule broken {")
    assert scan(b"x", "a.txt", broken) == ("check_failed",)
