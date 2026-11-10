"""OWASP Unrestricted File Upload - Risk Factors and Examples.

Each attack the page describes, attempted against every framework.
"""

from __future__ import annotations

import pytest
from PIL import Image

from tests.owasp.unrestricted_upload.payloads import (
    ASP_SHELL,
    CROSSDOMAIN_XML,
    JSP_SHELL,
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
from uploadshield import presets
from uploadshield.checks import ClamAV

owasp = pytest.mark.owasp


# --------------------------------------------------------------------------- #
# Risk factors
# --------------------------------------------------------------------------- #


@owasp("ufu.risk.web-shell")
@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("shell.php", corpus.PHP_SHELL),
        ("shell.jpg", corpus.PHP_SHELL),  # content decides, not the name
        ("shell.jsp", JSP_SHELL),
        ("shell.asp", ASP_SHELL),
        ("shell.aspx", ASP_SHELL),
        (".htaccess", b"AddType application/x-httpd-php .jpg\n"),
        ("web.config", b'<configuration><system.webServer><handlers accessPolicy="Script"/>'),
    ],
)
def test_web_shells_and_server_configuration(app: App, name: str, data: bytes) -> None:
    blocked(app, name, data)


@owasp("ufu.risk.client-side")
@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("page.html", corpus.HTML),
        ("page.png", corpus.HTML),
        ("logo.svg", corpus.svg("<script>alert(1)</script>")),
        ("movie.swf", SWF),
        ("photo.jpg", SWF),
        ("photo.jpg", SWF_COMPRESSED),
        ("app.xap", XAP),
        ("crossdomain.xml", CROSSDOMAIN_XML),
        ("clientaccesspolicy.xml", b'<?xml version="1.0"?><access-policy/>'),
    ],
    ids=[
        "html",
        "html-as-png",
        "svg",
        "swf",
        "swf-as-jpg",
        "cws-as-jpg",
        "xap",
        "crossdomain",
        "clientaccesspolicy",
    ],
)
def test_xss_and_content_hijacking(app: App, name: str, data: bytes) -> None:
    blocked(app, name, data)


@owasp("ufu.risk.admin-machines")
@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("invoice.pdf", corpus.pe_executable()),
        ("notes.txt", corpus.SHELL_SCRIPT),
        ("budget.xlsx", corpus.xlsx_with_dde_link()),
        ("budget.xlsx", corpus.xlsx_with_dde_formula()),
        ("contacts.csv", b"name,phone\n=cmd|' /C calc'!A0,1\n"),
        ("contacts.csv", b"name;phone\n\"@SUM(1+1)*cmd|' /C calc'!A0\";1\n"),
        ("letter.docx", corpus.docx_with_dde()),
    ],
    ids=[
        "exe",
        "script",
        "xlsx-dde-link",
        "xlsx-dde-formula",
        "csv-dde",
        "csv-dde-quoted",
        "docx-dde",
    ],
)
def test_files_that_run_on_an_administrators_machine(app: App, name: str, data: bytes) -> None:
    blocked(app, name, data, path="/documents")


@owasp("ufu.risk.admin-machines")
def test_ordinary_spreadsheets_and_csv_pass() -> None:
    assert codes(corpus.ooxml("xlsx"), "a.xlsx", presets.DOCUMENTS) == ()
    plain = b"name,formula,phone\nalice,=SUM(A1:A3),+49 30 1234\nbob,-5,a|b\n"
    assert codes(plain, "a.csv", presets.DOCUMENTS) == ()  # formulas without DDE, pipes


@owasp("ufu.risk.error-messages", "ufu.case.existing-names")
def test_errors_never_reveal_paths_or_exception_texts(
    app: App, monkeypatch: pytest.MonkeyPatch
) -> None:
    def crash(*args: object, **kwargs: object) -> None:
        raise RuntimeError("/srv/app/releases/42/secret_settings.py line 7: boom")

    monkeypatch.setattr(Image, "open", crash)
    reply = app.post("/legacy", file("photo.png", PNG))
    assert reply.status == 400
    assert reply.codes == ["image_corrupt"]
    assert b"/srv/app" not in reply.body
    assert b"RuntimeError" not in reply.body


# --------------------------------------------------------------------------- #
# Examples: attacks on the application platform and on other systems
# --------------------------------------------------------------------------- #


@owasp("ufu.example.jsp")
@pytest.mark.parametrize("name", ["index.jsp", "index.jspx", "index.jsp.png", "INDEX.JSP"])
def test_jsp_files(app: App, name: str) -> None:
    blocked(app, name, JSP_SHELL)


@owasp("ufu.example.overwrite")
@pytest.mark.parametrize(
    "name",
    [
        "../../web.config",
        "..\\..\\index.php",
        "/etc/cron.d/job",
        "web.config",
        "WEB~1.CON",
        "index.php",
        ".htaccess",
        "C:index.html",
    ],
)
def test_names_that_would_overwrite_critical_files(app: App, name: str) -> None:
    blocked(app, name)


@owasp("ufu.example.included-tags", "ufu.bypass.later-use")
@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("avatar.gif", corpus.image("GIF", comment=b'<?php include($_GET["p"]); ?>')),
        ("avatar.jpg", corpus.image("JPEG", comment=b'<!--#include virtual="/etc/passwd" -->')),
        ("avatar.png", PNG + b'<%@ page import="java.io.*" %>'),
        ("avatar.png", PNG + b"<script>alert(document.cookie)</script>"),
        ("notes.txt", corpus.PHP_SHELL),  # PHP's include runs PHP code from any file
    ],
    ids=["php-in-gif", "ssi-in-jpeg", "jsp-in-png", "script-in-png", "php-as-text"],
)
def test_tags_that_run_when_the_file_is_included(app: App, name: str, data: bytes) -> None:
    path = "/documents" if name.endswith(".txt") else "/legacy"
    blocked(app, name, data, path=path)


@owasp("ufu.example.antivirus-exploit")
@pytest.mark.parametrize(
    ("name", "data"), [("scan.rar", RAR), ("scan.zip", RAR), ("a.7z", SEVEN_ZIP)]
)
def test_archives_never_reach_the_virus_scanner(name: str, data: bytes) -> None:
    # The scanner address is unreachable: refusing by type proves it was never asked.
    policy = presets.DEFAULT.extend(checks=[ClamAV(address="tcp://127.0.0.1:9", timeout=0.2)])
    assert codes(data, name, policy)[0] in ("type_not_allowed", "extension_mismatch")


@owasp("ufu.example.antivirus-exploit")
def test_archives_are_refused_in_every_framework(app: App) -> None:
    blocked(app, "scan.rar", RAR)


@owasp("ufu.example.trojan")
@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("setup.exe", corpus.pe_executable()),
        ("report.pdf", corpus.pe_executable()),
        ("tool.png", corpus.ELF),
        ("photo.jpg.exe", corpus.image("JPEG")),
    ],
)
def test_executables_for_visitors_to_download(app: App, name: str, data: bytes) -> None:
    blocked(app, name, data)


@owasp("ufu.example.html-xss")
@pytest.mark.parametrize("name", ["xss.html", "xss.htm", "xss.txt", "xss.png", "xss.pdf"])
def test_html_with_script(app: App, name: str) -> None:
    blocked(app, name, corpus.HTML, path="/documents")


@owasp("ufu.example.flash-in-jpg")
@pytest.mark.parametrize("data", [SWF, SWF_COMPRESSED], ids=["fws", "cws"])
def test_flash_named_as_an_image(app: App, data: bytes) -> None:
    blocked(app, "photo.jpg", data, path="/avatar")
