"""OWASP File Upload Cheat Sheet - Extension Validation.

Every bypass the cheat sheet names is sent to Django (WSGI and ASGI), Flask and FastAPI
as a real multipart request (``app``), and the full extension list is checked against
the engine directly.
"""

from __future__ import annotations

import string

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.support import corpus
from tests.support.engine import codes
from tests.support.harness import App, file
from uploadshield import Policy, Upload, presets, validate
from uploadshield.checks import DANGEROUS_EXTENSIONS
from uploadshield.checks.basic import name_variants
from uploadshield.core.types import all_types
from uploadshield.presets import BUILTIN_POLICIES

owasp = pytest.mark.owasp
PNG = corpus.png()


def refused_by_name(app: App, name: str) -> list[str]:
    reply = app.post("/legacy", file(name, PNG))
    assert reply.status == 400, (app.name, name, reply.status, reply.body[:300])
    assert reply.codes
    assert all(code.startswith("filename_") for code in reply.codes), reply.codes
    return reply.codes


# --------------------------------------------------------------------------- #
# "Validate after decoding the filename"
# --------------------------------------------------------------------------- #

DECODED = {
    "shell%2ephp.png": "shell.php.png",  # percent-encoded dot
    "shell.%70%68%70.png": "shell.php.png",  # percent-encoded letters
    "shell.php%00.png": "shell.php\x00.png",  # encoded NUL
    "shell.php%2500.png": "shell.php%00.png",  # double encoding, decoded twice
    "..%2f..%2fetc%2fx.png": "../../etc/x.png",  # encoded traversal
    "shell.\uff50\uff48\uff50.png": "shell.php.png",  # fullwidth: Windows "best fit"
    "shell\uff0ephp.png": "shell.php.png",  # fullwidth full stop
}


@owasp("extension.decode-first")
@pytest.mark.parametrize("name", list(DECODED))
def test_names_are_judged_as_decoding_layers_read_them(app: App, name: str) -> None:
    refused_by_name(app, name)


@owasp("extension.decode-first")
@pytest.mark.parametrize(("name", "reading"), DECODED.items())
def test_the_decoded_reading_is_considered_and_logged(name: str, reading: str) -> None:
    assert reading in [variant for variant, _ in name_variants(name)]
    result = validate(Upload.from_bytes(PNG, name), presets.DEFAULT)
    assert not result.ok
    readings = [v.details.get("read_as") for v in result.violations]
    assert any(r is not None for r in readings), result.violations  # shown in the logs


@owasp("extension.decode-first")
@pytest.mark.parametrize("name", ["100%.png", "50%25 off.png", "Q3 %20 report.pdf", "\u2460.png"])
def test_harmless_percent_signs_and_compatibility_characters_pass(name: str) -> None:
    data = corpus.pdf() if name.endswith(".pdf") else PNG
    assert codes(data, name) == ()


# --------------------------------------------------------------------------- #
# The named bypasses
# --------------------------------------------------------------------------- #


@owasp("extension.double")
@pytest.mark.parametrize(
    "name", ["shell.jpg.php", "shell.php.png", "shell.php.jpg.png", "shell.png.php5", "a.asp;.png"]
)
def test_double_extensions(app: App, name: str) -> None:
    assert "filename_dangerous_extension" in refused_by_name(app, name)


@owasp("extension.null-byte")
@pytest.mark.parametrize("name", ["shell.php\x00.png", "shell.php%00.png", "shell.php\x00"])
def test_null_bytes(app: App, name: str) -> None:
    # Django deletes the NUL itself and then sees ".php"; the others refuse the NUL.
    refused_by_name(app, name)


@owasp("extension.case")
@pytest.mark.parametrize("name", ["shell.pHp.png", "shell.phP.png", "SHELL.PHP.PNG", "x.AsPx.png"])
def test_case_manipulation(app: App, name: str) -> None:
    assert "filename_dangerous_extension" in refused_by_name(app, name)


@owasp("extension.alternative")
@pytest.mark.parametrize("extension", ["phtml", "php5", "pht", "jsp", "jspx", "asp", "aspx"])
def test_alternative_extensions_named_by_owasp(app: App, extension: str) -> None:
    assert "filename_dangerous_extension" in refused_by_name(app, f"shell.{extension}.png")


@owasp("extension.alternative", "extension.case")
@pytest.mark.parametrize("extension", sorted(DANGEROUS_EXTENSIONS))
def test_every_listed_extension_in_every_position_and_case(extension: str) -> None:
    for name in (f"x.{extension}.png", f"x.{extension.upper()}.png", f"x.png.{extension}"):
        assert "filename_dangerous_extension" in codes(PNG, name), name


@owasp("extension.ntfs-ads")
@pytest.mark.parametrize(
    "name",
    ["shell.asp:.jpg", "shell.php::$DATA", "shell.php::$DATA.png", "x.png:evil.php", "x.png:x"],
)
def test_ntfs_alternate_data_streams(app: App, name: str) -> None:
    assert "filename_invalid" in refused_by_name(app, name)  # ":" is refused outright


# --------------------------------------------------------------------------- #
# Vetted logic, allow-list first, blocklist as defense in depth
# --------------------------------------------------------------------------- #


def _spell(extension: str, case: list[bool], encode: list[bool]) -> str:
    out = []
    for char, upper, percent in zip(extension, case, encode, strict=False):
        char = char.upper() if upper else char  # noqa: PLW2901
        out.append(f"%{ord(char):02x}" if percent else char)
    return "".join(out)


@owasp("extension.vetted-logic", "extension.case", "extension.decode-first")
@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    stem=st.text(string.ascii_letters + string.digits, min_size=1, max_size=12),
    extension=st.sampled_from(sorted(DANGEROUS_EXTENSIONS)),
    case=st.lists(st.booleans(), min_size=20, max_size=20),
    encode=st.lists(st.booleans(), min_size=20, max_size=20),
    last=st.sampled_from(["png", "jpg", "pdf", ""]),
)
def test_no_spelling_of_a_dangerous_extension_passes(
    stem: str, extension: str, case: list[bool], encode: list[bool], last: str
) -> None:
    name = f"{stem}.{_spell(extension, case, encode)}" + (f".{last}" if last else "")
    assert not validate(Upload.from_bytes(PNG, name), presets.DEFAULT).ok, name


@owasp("extension.allowlist")
@pytest.mark.parametrize("policy", list(BUILTIN_POLICIES.values()), ids=list(BUILTIN_POLICIES))
def test_no_preset_allows_executable_or_scriptable_content(policy: Policy) -> None:
    scriptable = {"text/html", "image/svg+xml", "application/xml", "application/x-sh"}
    for file_type in all_types():
        if file_type.executable or file_type.mime in scriptable:
            assert not policy.allows(file_type), (policy.name, file_type.mime)


@owasp("extension.allowlist")
def test_only_business_critical_types_per_endpoint(app: App) -> None:
    # /avatar accepts images, /documents documents: each refuses the other's formats.
    assert app.post("/avatar", file("cv.pdf", corpus.pdf())).codes == ["type_not_allowed"]
    assert app.post("/documents", file("me.png", PNG)).codes == ["type_not_allowed"]
    assert app.post("/legacy", file("cat.png", corpus.PHP_SHELL)).codes == ["type_not_allowed"]


@owasp("extension.allowlist")
@pytest.mark.parametrize(
    ("name", "data"),
    [("photo.png", corpus.image("JPEG")), ("report.pdf", PNG), ("notes.txt", corpus.pdf())],
)
def test_the_extension_must_belong_to_the_detected_type(app: App, name: str, data: bytes) -> None:
    assert app.post("/legacy", file(name, data)).codes == ["extension_mismatch"]


@owasp("extension.blocklist")
def test_the_blocklist_only_complements_the_allow_list() -> None:
    # Allowed content under a blocked extension: the blocklist adds protection ...
    assert codes(PNG, "shell.php.png") == ("filename_dangerous_extension",)
    # ... but names it does not know are decided by the content allow-list.
    assert codes(corpus.pe_executable(), "report.xyz") == ("type_not_allowed",)
    assert codes(corpus.SHELL_SCRIPT, "notes.txt") == ("type_not_allowed",)
