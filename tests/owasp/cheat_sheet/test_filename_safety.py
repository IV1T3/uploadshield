"""OWASP File Upload Cheat Sheet - Filename Safety."""

from __future__ import annotations

import re
import string

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tests.support import corpus
from tests.support.engine import codes
from tests.support.harness import App, file
from uploadshield import Upload, presets, validate
from uploadshield.checks import FilenameCheck
from uploadshield.sanitizers import RandomizeFilename, SafeFilename

owasp = pytest.mark.owasp
PNG = corpus.png()


def refused(
    app: App, name: str, code: str = "filename_invalid", *, django: str | None = None
) -> None:
    """Refused - or, where ``django`` is given, rewritten to it by Django's own parser."""
    reply = app.post("/legacy", file(name, PNG))
    if django is not None and app.framework == "django":
        assert [f["name"] for f in reply.files] == [django]
        return
    assert reply.status == 400, (app.name, name, reply.status)
    assert code in reply.codes, (name, reply.codes)


# --------------------------------------------------------------------------- #
# Generated names
# --------------------------------------------------------------------------- #


@owasp("filename.generated", "filename.overwrite")
def test_generated_names_are_random_and_keep_the_detected_extension(app: App) -> None:
    upload = file("Jane Doe - passport scan.png", PNG)  # personal data in the name
    names = {app.post("/avatar", upload).files[0]["name"] for _ in range(3)}
    assert len(names) == 3  # never the same name twice: nothing is overwritten
    assert all(re.fullmatch(r"[0-9a-f]{32}\.png", n) for n in names), names


@owasp("filename.generated")
def test_generated_names_follow_the_content_not_the_claim() -> None:
    policy = presets.IMAGES.replace(sanitizers=(RandomizeFilename(),), match_extension=False)
    result = validate(Upload.from_bytes(corpus.image("JPEG"), "photo.png"), policy)
    assert result.sanitized is not None
    assert result.sanitized.name.endswith(".jpg")


# --------------------------------------------------------------------------- #
# User-supplied names: length, characters, information
# --------------------------------------------------------------------------- #


@owasp("filename.max-length")
def test_names_are_limited_in_bytes() -> None:
    assert codes(PNG, "a" * 251 + ".png") == ()  # 255 bytes
    assert codes(PNG, "a" * 252 + ".png") == ("filename_too_long",)
    assert codes(PNG, "\u00e9" * 126 + ".png") == ("filename_too_long",)  # 2 bytes each
    short = presets.IMAGES.replace(filename=FilenameCheck(max_length=20))
    assert codes(PNG, "a" * 17 + ".png", short) == ("filename_too_long",)


@owasp("filename.max-length")
def test_long_names_are_refused_in_every_framework(app: App) -> None:
    refused(app, "a" * 300 + ".png", "filename_too_long")


@owasp("filename.charset")
@pytest.mark.parametrize(
    ("name", "safe"),
    [
        ("R\u00e9sum\u00e9 (final).PDF", "Resume_final.pdf"),
        ("report.final.v2.pdf", "report.pdf"),
        ("-rf --no-preserve-root.pdf", "rf_--no-preserve-root.pdf"),
        ("\u0627\u0644\u0633\u064a\u0631\u0629.pdf", "file.pdf"),
    ],
)
def test_safe_filename_restricts_the_character_set(name: str, safe: str) -> None:
    policy = presets.PDF.replace(
        sanitizers=(SafeFilename(),),
        filename=FilenameCheck(allow_leading_hyphen=True, allow_consecutive_dots=True),
    )
    result = validate(Upload.from_bytes(corpus.pdf(), name), policy)
    assert result.sanitized is not None
    assert result.sanitized.name == safe
    assert re.fullmatch(r"[A-Za-z0-9_.\- ]+", result.sanitized.name)
    assert result.sanitized.name.endswith(".pdf")
    assert not result.sanitized.name.startswith(("-", ".", " "))


@owasp("filename.charset")
@settings(max_examples=300, deadline=None)
@given(stem=st.text(min_size=1, max_size=80))
def test_safe_filename_output_is_always_in_the_allowed_set(stem: str) -> None:
    sanitizer = SafeFilename()
    policy = presets.PDF.replace(
        filename=FilenameCheck(
            allow_hidden=True,
            allow_leading_hyphen=True,
            allow_consecutive_dots=True,
            allow_short_names=True,
            forbidden_extensions=frozenset(),
            forbidden_names=frozenset(),
        ),
        sanitizers=(sanitizer,),
    )
    result = validate(Upload.from_bytes(corpus.pdf(), f"{stem}.pdf"), policy)
    if result.sanitized is not None:
        assert re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.\- ]*\.pdf", result.sanitized.name), (
            result.sanitized.name
        )


@owasp("filename.inform-users")
@pytest.mark.parametrize(
    "name",
    [
        "shell.php.png",
        ".htaccess",
        "a..b.png",
        "-x.png",
        "CON.png",
        "a" * 300 + ".png",
        "noext",
        "a|b.png",
    ],
)
def test_every_refusal_explains_itself(name: str) -> None:
    result = validate(Upload.from_bytes(PNG, name), presets.DEFAULT)
    assert result.violations
    for violation in result.violations:
        assert violation.message.endswith(".")
        assert name not in violation.message  # no echo of attacker input in messages
        assert len(violation.message) < 100


@owasp("filename.inform-users")
def test_messages_can_be_rewritten_per_code(app: App) -> None:
    from uploadshield import web
    from uploadshield.core.violations import Violation

    custom = {"filename_invalid": "Use letters, digits, spaces, '-' and '.' only."}
    violation = Violation("filename_invalid", "The file name contains invalid characters.")
    assert web.message_for(violation, custom) == custom["filename_invalid"]


# --------------------------------------------------------------------------- #
# The characters and shapes OWASP names
# --------------------------------------------------------------------------- #


@owasp("filename.leading-period")
@pytest.mark.parametrize(
    ("name", "code"),
    [
        (".bashrc.png", "filename_hidden"),
        (".png", "filename_hidden"),
        (".htaccess", "filename_reserved"),
        ("..png", "filename_hidden"),
    ],
)
def test_leading_periods(app: App, name: str, code: str) -> None:
    refused(app, name, code)


@owasp("filename.leading-period")
def test_hidden_names_can_be_allowed() -> None:
    lenient = presets.IMAGES.replace(filename=FilenameCheck(allow_hidden=True))
    assert codes(PNG, ".avatar.png", lenient) == ()
    assert "filename_reserved" in codes(PNG, ".htaccess", lenient)  # configuration: never


@owasp("filename.sequential-periods")
@pytest.mark.parametrize("name", ["a..png", "x..y.png", "a...b.png", "a.%2e.png"])
def test_sequential_periods(app: App, name: str) -> None:
    refused(app, name)


@owasp("filename.sequential-periods")
def test_sequential_periods_can_be_allowed_and_ellipses_pass() -> None:
    assert codes(PNG, "Wait\u2026what.png") == ()  # one ellipsis character
    lenient = presets.IMAGES.replace(filename=FilenameCheck(allow_consecutive_dots=True))
    assert codes(PNG, "a..b.png", lenient) == ()


@owasp("filename.leading-hyphen-space")
@pytest.mark.parametrize(
    ("name", "django"),
    [
        ("-rf.png", None),
        ("--help.png", None),
        ("-o-evil.png", None),
        (" photo.png", None),
        ("\u00a0photo.png", "photo.png"),  # Django strips tabs and no-break spaces itself
        ("\tphoto.png", "photo.png"),
    ],
)
def test_leading_hyphens_and_spaces(app: App, name: str, django: str | None) -> None:
    refused(app, name, django=django)


@owasp("filename.leading-hyphen-space")
def test_hyphens_elsewhere_pass_and_the_rule_can_be_relaxed() -> None:
    assert codes(PNG, "my-photo - final.png") == ()
    lenient = presets.IMAGES.replace(filename=FilenameCheck(allow_leading_hyphen=True))
    assert codes(PNG, "-final.png", lenient) == ()
    assert codes(PNG, " final.png", lenient) == ("filename_invalid",)  # spaces never


@owasp("filename.dangerous-chars")
@pytest.mark.parametrize(
    "char",
    [
        "<",
        ">",
        ":",
        "|",
        "?",
        "*",
        "\x00",
        "\x07",
        "\x1b",
        "\x7f",
        "\x85",
        "\u202e",
        "\u2066",
        "\u200f",
    ],
)
def test_dangerous_characters(char: str) -> None:
    assert "filename_invalid" in codes(PNG, f"a{char}b.png")


@owasp("filename.dangerous-chars")
@pytest.mark.parametrize(
    ("name", "django"),
    [
        ("a<b>.png", None),
        ("a|b.png", None),
        ("a?b.png", None),
        ("a*b.png", None),
        ("a%22b.png", None),
        ("evil\u202egnp.png", "evilgnp.png"),  # Django deletes unprintable characters itself
    ],
)
def test_dangerous_characters_in_every_framework(app: App, name: str, django: str | None) -> None:
    refused(app, name, django=django)


@owasp("filename.dangerous-chars")
@pytest.mark.parametrize(
    "name",
    [
        "photo.png",
        "My Photo (1).png",
        "Screenshot 2026-11-09 at 10.30.00\u202fAM.png",
        "\u00fcbung.png",
        "family-\U0001f468\u200d\U0001f469\u200d\U0001f467.png",
        "\u5199\u771f.png",
        "50% off.png",
        "a_b-c+d=e,f;g.png",
        "it's.png",
    ],
)
def test_legitimate_names_still_pass(name: str) -> None:
    assert codes(PNG, name) == ()


@owasp("filename.reserved-names")
@pytest.mark.parametrize(
    "name",
    [
        "CON.png",
        "con.png",
        "PRN.png",
        "AUX.png",
        "NUL.png",
        "COM1.png",
        "LPT9.png",
        "CONIN$.png",
        "con.tar.gz.png",
        "CON .png",
        "COM\u00b9.png",
        "photo.png.",
        "photo.png ",
        ".",
        "..",
    ],
)
def test_platform_reserved_names(name: str) -> None:
    assert {"filename_reserved", "filename_invalid", "filename_hidden"} & set(codes(PNG, name)), (
        name
    )


@owasp("filename.reserved-names")
@pytest.mark.parametrize("name", ["CON.png", "lpt1.png", "COM\u00b9.png"])
def test_platform_reserved_names_in_every_framework(app: App, name: str) -> None:
    refused(app, name, "filename_reserved")


@owasp("filename.short-names")
@pytest.mark.parametrize(
    "name", ["WEBCON~1.CON", "PROGRA~1", "DOCUME~2.PNG", "photo~1.png", "AB~12345.jpg"]
)
def test_windows_short_name_aliases(name: str) -> None:
    assert "filename_reserved" in codes(PNG, name)


@owasp("filename.short-names")
def test_short_names_in_every_framework_and_lookalikes_that_pass(app: App) -> None:
    refused(app, "WEBCON~1.PNG", "filename_reserved")
    assert codes(PNG, "my~file.png") == ()
    assert codes(PNG, "longername~1.png") == ()  # stems of 8.3 names have at most 6 characters
    lenient = presets.IMAGES.replace(filename=FilenameCheck(allow_short_names=True))
    assert codes(PNG, "photo~1.png", lenient) == ()


@owasp("filename.overwrite")
def test_django_storage_never_overwrites(tmp_path: object, settings: object) -> None:
    from django.core.files.base import ContentFile

    from uploadshield.django.storage import ValidatingStorage

    storage = ValidatingStorage(options={"location": str(tmp_path)}, policy="images")
    first = storage.save("photo.png", ContentFile(PNG, name="photo.png"))
    second = storage.save("photo.png", ContentFile(PNG, name="photo.png"))
    assert first == "photo.png"
    assert second != first


@owasp("filename.dangerous-chars")
@settings(max_examples=300, deadline=None)
@given(name=st.text(alphabet=string.printable, min_size=1, max_size=40))
def test_accepted_names_never_contain_separators_or_forbidden_characters(name: str) -> None:
    result = validate(Upload.from_bytes(PNG, f"{name}.png"), presets.DEFAULT)
    if result.ok:
        assert not set(f"{name}.png") & set('/\\:<>"|?*\x00')
        assert not name.startswith(("-", ".", " "))
        assert ".." not in name
