"""OWASP Unrestricted File Upload - Other Interesting Test Cases.

The page's list of further test cases, each attempted as written.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from tests.owasp.unrestricted_upload.payloads import (
    CROSSDOMAIN_XML,
    GZIP,
    PNG,
    RAR,
    SEVEN_ZIP,
    SWF,
    SWF_COMPRESSED,
    XAP,
    blocked,
)
from tests.support import corpus
from tests.support.engine import codes
from tests.support.harness import App, file
from uploadshield import Policy, Upload, presets, validate

owasp = pytest.mark.owasp
WINDOWS_RESERVED = [
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
]


@owasp("ufu.case.existing-names")
def test_names_that_exist_on_the_server_and_collisions(app: App) -> None:
    blocked(app, "web.config")  # an existing, critical name
    names = {app.post("/avatar", file("photo.png", PNG)).files[0]["name"] for _ in range(2)}
    assert len(names) == 2  # the same name uploaded twice is stored twice


@owasp("ufu.case.long-names")
def test_very_long_names(app: App) -> None:
    assert codes(PNG, "a" * 251 + ".png") == ()  # 255 bytes, the NTFS and ext4 limit
    assert codes(PNG, "a" * 252 + ".png") == ("filename_too_long",)
    assert codes(PNG, "文" * 84 + ".png") == ("filename_too_long",)  # 256 bytes in UTF-8
    reply = app.post("/legacy", file("a" * 300 + ".png", PNG))  # (Django caps headers at 1 KiB)
    assert reply.codes == ["filename_too_long"]


@owasp("ufu.case.concurrent")
def test_concurrent_uploads_get_independent_verdicts() -> None:
    uploads = [(PNG, "same.png"), (corpus.PHP_SHELL, "same.png"), (PNG, "same.png.php")] * 20

    def verdict(upload: tuple[bytes, str]) -> tuple[str, ...]:
        data, name = upload
        return validate(Upload.from_bytes(data, name), presets.SANITIZED_IMAGES).codes

    with ThreadPoolExecutor(max_workers=12) as pool:
        verdicts = list(pool.map(verdict, uploads))
    assert verdicts == [(), ("type_not_allowed",), ("filename_dangerous_extension",)] * 20


@owasp("ufu.case.concurrent")
def test_concurrent_sanitizing_gives_unique_names() -> None:
    def name(_: int) -> str:
        result = validate(Upload.from_bytes(PNG, "same.png"), presets.SANITIZED_IMAGES)
        assert result.sanitized is not None
        return result.sanitized.name

    with ThreadPoolExecutor(max_workers=12) as pool:
        names = list(pool.map(name, range(50)))
    assert len(set(names)) == 50


@owasp("ufu.case.compressed-xml")
@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("a.zip", corpus.build_zip({"a.txt": b"a"})),
        ("a.gz", GZIP),
        ("a.rar", RAR),
        ("a.7z", SEVEN_ZIP),
        ("a.xml", corpus.xml(root=b"<r/>")),
        ("a.xml", corpus.xml(corpus.XXE_DTD)),
        ("a.svg", corpus.svg()),
    ],
    ids=["zip", "gzip", "rar", "7z", "xml", "xml-xxe", "svg"],
)
def test_compressed_and_xml_files_probing_for_processing(app: App, name: str, data: bytes) -> None:
    reply = blocked(app, name, data)
    assert reply.status == 415  # never parsed: refused for their type


@owasp("ufu.case.compressed-xml")
def test_where_archives_and_xml_are_allowed_they_are_still_inspected() -> None:
    assert codes(corpus.zip_bomb_ratio(), "a.zip", Policy(allowed_types={"application/zip"})) == (
        "archive_bomb",
    )
    assert codes(
        corpus.xml(corpus.XXE_DTD), "a.xml", Policy(allowed_types={"application/xml"})
    ) == ("xml_dtd",)


@owasp("ufu.case.dot-names")
@pytest.mark.parametrize("name", [".", "..", "..."])
def test_dot_names(app: App, name: str) -> None:
    found = set(codes(PNG, name))
    assert found & {"filename_reserved", "filename_invalid", "filename_hidden"}, found
    blocked(app, name)


@owasp("ufu.case.ntfs-names")
@pytest.mark.parametrize("name", ["...:.jpg", "a.jpg::$DATA", "a.jpg:stream", "..:.png"])
def test_ntfs_names_that_are_hard_to_delete(app: App, name: str) -> None:
    assert "filename_invalid" in codes(PNG, name)
    blocked(app, name)


@owasp("ufu.case.windows-characters")
@pytest.mark.parametrize("char", ["|", "<", ">", "*", "?", '"'])
def test_characters_windows_forbids(app: App, char: str) -> None:
    assert "filename_invalid" in codes(PNG, f"a{char}b.png")
    # Browsers send '"' percent-encoded; it is refused once decoded.
    blocked(app, "a%22b.png" if char == '"' else f"a{char}b.png")


@owasp("ufu.case.reserved-names")
@pytest.mark.parametrize("name", WINDOWS_RESERVED)
def test_every_reserved_windows_name(name: str) -> None:
    for variant in (name, name.lower(), f"{name}.png", f"{name.lower()}.tar.png", f"{name} .png"):
        assert "filename_reserved" in codes(PNG, variant), variant


@owasp("ufu.case.reserved-names")
@pytest.mark.parametrize("name", ["CON.png", "aux.png", "COM1.png", "lpt9.png"])
def test_reserved_windows_names_in_every_framework(app: App, name: str) -> None:
    assert app.post("/legacy", file(name, PNG)).codes == ["filename_reserved"]


@owasp("ufu.case.content-hijacking")
@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("photo.jpg", SWF),
        ("photo.jpg", SWF_COMPRESSED),
        ("photo.jpg", corpus.pdf()),
        ("photo.png", XAP),
        ("doc.pdf", SWF),
    ],
    ids=["swf", "cws", "pdf", "xap", "swf-as-pdf"],
)
def test_flash_pdf_and_silverlight_under_an_allowed_extension(
    app: App, name: str, data: bytes
) -> None:
    reply = blocked(app, name, data, path="/avatar" if name.startswith("photo") else "/documents")
    assert reply.status == 415


@owasp("ufu.case.policy-files", "ufu.prevent.policy-files")
@pytest.mark.parametrize("name", ["crossdomain.xml", "CrossDomain.XML", "clientaccesspolicy.xml"])
def test_cross_domain_policy_files(app: App, name: str) -> None:
    xml_allowed = Policy(allowed_types={"application/xml"})
    assert codes(CROSSDOMAIN_XML, name, xml_allowed) == ("filename_reserved",)
    blocked(app, name, CROSSDOMAIN_XML)


@owasp("ufu.case.policy-files")
def test_other_xml_names_pass_where_xml_is_allowed() -> None:
    xml_allowed = Policy(allowed_types={"application/xml"})
    assert codes(corpus.xml(root=b"<feed/>"), "feed.xml", xml_allowed) == ()
