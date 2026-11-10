"""The CWE mapping stays complete, valid, and in step with the docs."""

from __future__ import annotations

import re
from pathlib import Path

from uploadshield.core.violations import CWE, Code

REFUSALS = Path(__file__).parents[2] / "docs" / "refusals.md"


def test_every_code_has_a_cwe_decision() -> None:
    # A code must appear in the map even if it maps to nothing, so adding a new code
    # forces a conscious choice instead of silently having no taxonomy.
    assert set(CWE) == set(Code)


def test_cwe_ids_are_well_formed() -> None:
    for refs in CWE.values():
        for ref in refs:
            assert re.fullmatch(r"CWE-\d+", ref.id), ref.id
            assert ref.name.strip(), ref.id


def test_refusals_doc_lists_every_mapped_code() -> None:
    # The docs/refusals.md CWE table must not drift from the map: every mapped code's
    # row names exactly its CWE ids, and no unmapped code is given a CWE there.
    page = REFUSALS.read_text(encoding="utf-8")
    rows = dict(re.findall(r"^\| `([a-z_]+)` \| (CWE-[\d,\s CWE-]*) \|$", page, re.MULTILINE))
    for code in Code:
        ids = [ref.id for ref in CWE[code]]
        if ids:
            assert code.value in rows, f"{code.value} missing from the CWE table"
            assert re.findall(r"CWE-\d+", rows[code.value]) == ids, code.value
        else:
            assert code.value not in rows, f"{code.value} has no CWE but is in the table"
