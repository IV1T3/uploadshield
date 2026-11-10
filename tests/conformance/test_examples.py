"""The example apps of every framework, sent byte-for-byte identical requests.

``examples/{django,flask,fastapi}_app.py`` expose the same endpoints:

* ``/documents`` - the ``documents`` policy, chosen per view;
* ``/avatar`` - ``sanitized_images`` (re-encoded, random name);
* ``/gallery`` - ``images``, several files in the field ``files``;
* ``/legacy`` - no per-view configuration: only the framework-wide safety net.

Every request body is encoded once, here, as raw multipart bytes (the way browsers
and curl send it), so the three adapters must agree on what is accepted, refused
(status code and error code) and delivered to the view.  Django runs both under WSGI
and ASGI.  Where the *framework* differs (Django drops path components from
filenames itself), the test asserts the security property rather than one status.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest

from tests.support import corpus
from tests.support.harness import (
    CONTENT_TYPE,
    App,
    Part,
    _django,
    django_example_settings,
    encode,
    file,
    noise,
    sanitized,
    sha256,
)

PHP = b"<?php system($_GET['cmd']); ?>"
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
ODT = "application/vnd.oasis.opendocument.text"


# --------------------------------------------------------------------------- #
# Accepted: delivered intact, with the content type taken from the bytes
# --------------------------------------------------------------------------- #


ACCEPTED = [
    ("/documents", "report.pdf", corpus.pdf(), "application/pdf"),
    ("/documents", "paper.pdf", corpus.pdf_latex_style(), "application/pdf"),
    ("/documents", "letter.docx", corpus.ooxml("docx"), DOCX),
    ("/documents", "links.docx", corpus.docx_with_external_hyperlink(), DOCX),
    ("/documents", "budget.xlsx", corpus.ooxml("xlsx"), XLSX),
    ("/documents", "notes.odt", corpus.odt(), ODT),
    ("/documents", "data.csv", b"name,amount\nalice,3\nbob,4\n", "text/csv"),
    ("/documents", "readme.txt", "Grüße aus Köln\n".encode(), "text/plain"),
    ("/legacy", "photo.png", corpus.png(), "image/png"),
    ("/legacy", "photo.jpg", corpus.image("JPEG"), "image/jpeg"),
    ("/legacy", "anim.gif", corpus.animated_gif(), "image/gif"),
    ("/legacy", "photo.webp", corpus.image("WEBP"), "image/webp"),
    ("/legacy", "song.mp3", corpus.mp3(), "audio/mpeg"),
    ("/legacy", "clip.mp4", corpus.mp4(), "video/mp4"),
    ("/legacy", "report.pdf", corpus.pdf(), "application/pdf"),
]


@pytest.mark.parametrize(
    ("path", "name", "data", "detected"), ACCEPTED, ids=[c[1] for c in ACCEPTED]
)
def test_accepted_files_arrive_intact(
    app: App, path: str, name: str, data: bytes, detected: str
) -> None:
    # The client lies about the type; the view sees the type proven by the bytes.
    (delivered,) = app.post(path, file(name, data, "text/plain")).files
    assert delivered == {
        "field": "file",
        "name": name,
        "content_type": detected,
        "size": len(data),
        "sha256": sha256(data),
    }


@pytest.mark.parametrize("name", ["résumé.pdf", "履歴書.pdf", "CV Jane Doe (final).pdf"])
def test_international_and_spaced_names_are_kept(app: App, name: str) -> None:
    (delivered,) = app.post("/documents", file(name, corpus.pdf())).files
    assert delivered["name"] == name


def test_large_files_spooled_to_disk_arrive_intact(app: App) -> None:
    # > 2.5 MB: Django's TemporaryUploadedFile, Werkzeug's and Starlette's temp files.
    data = noise((1100, 1000), "PNG")
    assert len(data) > 3 * 1024 * 1024
    (delivered,) = app.post("/legacy", file("scan.png", data)).files
    assert (delivered["size"], delivered["sha256"]) == (len(data), sha256(data))


# --------------------------------------------------------------------------- #
# Refused: same status, same machine-readable code, everywhere
# --------------------------------------------------------------------------- #

REFUSED = [
    # names, checked before the content
    ("/legacy", "shell.php.png", corpus.png(), 400, "filename_dangerous_extension"),
    ("/legacy", "shell.asp;.jpg", corpus.image("JPEG"), 400, "filename_dangerous_extension"),
    ("/legacy", "shell.phtml", PHP, 400, "filename_dangerous_extension"),
    ("/legacy", ".htaccess", b"AddType application/x-httpd-php .png", 400, "filename_reserved"),
    ("/legacy", "web.config", b"<configuration/>", 400, "filename_reserved"),
    ("/legacy", "CON.png", corpus.png(), 400, "filename_reserved"),
    ("/legacy", "C:x.png", corpus.png(), 400, "filename_invalid"),  # drive-relative path
    ("/legacy", "photo.png.", corpus.png(), 400, "filename_invalid"),
    ("/legacy", "noextension", corpus.png(), 400, "filename_missing_extension"),
    # content that is not what it claims to be
    ("/legacy", "cat.png", PHP, 415, "type_not_allowed"),
    ("/legacy", "report.pdf", corpus.pe_executable(), 415, "type_not_allowed"),
    ("/legacy", "notes.txt", b"<html><script>alert(1)</script></html>", 415, "type_not_allowed"),
    ("/legacy", "logo.svg", corpus.svg("<script>alert(1)</script>"), 415, "type_not_allowed"),
    ("/legacy", "photo.png", corpus.image("JPEG"), 415, "extension_mismatch"),
    ("/legacy", "archive.pdf", corpus.build_zip({"a.txt": b"a"}), 415, "type_not_allowed"),
    ("/avatar", "me.pdf", corpus.pdf(), 415, "type_not_allowed"),
    ("/documents", "photo.png", corpus.png(), 415, "type_not_allowed"),
    # active content inside allowed formats
    ("/legacy", "photo.png", corpus.png() + b"<?php echo 1; ?>", 400, "embedded_code"),
    ("/documents", "invoice.pdf", corpus.pdf_with_javascript(), 400, "pdf_active_content"),
    (
        "/documents",
        "invoice.pdf",
        corpus.pdf_with_obfuscated_javascript(),
        400,
        "pdf_active_content",
    ),
    (
        "/documents",
        "invoice.pdf",
        corpus.pdf_with_javascript_in_object_stream(),
        400,
        "pdf_active_content",
    ),
    (
        "/documents",
        "report.docx",
        corpus.ooxml("docx", extra={"word/vbaProject.bin": b"x"}),
        400,
        "office_macros",
    ),
    ("/documents", "report.docx", corpus.docx_with_dde(), 400, "office_macros"),
    (
        "/documents",
        "report.docx",
        corpus.docx_with_remote_template(),
        400,
        "office_external_reference",
    ),
    # broken or hostile images
    ("/avatar", "bomb.png", corpus.png_huge_dimensions(), 400, "image_too_large"),
    ("/avatar", "broken.png", corpus.png()[:60], 400, "image_corrupt"),
    # sizes
    ("/legacy", "empty.pdf", b"", 400, "file_empty"),
    # /avatar's own 10 MB limit wins over the 50 MB of the framework-wide default
    (
        "/avatar",
        "huge.jpg",
        b"\xff\xd8\xff\xe0" + b"\x00" * 11 * 1024 * 1024,
        413,
        "file_too_large",
    ),
]


@pytest.mark.parametrize(
    ("path", "name", "data", "status", "code"),
    REFUSED,
    ids=[f"{c[0][1:]}-{c[4]}-{c[1]}" for c in REFUSED],
)
def test_refusals_agree(
    app: App, path: str, name: str, data: bytes, status: int, code: str
) -> None:
    reply = app.post(path, file(name, data, "image/png"))
    assert (reply.status, reply.codes[0]) == (status, code)
    assert reply.rejection is not None
    (refused,) = reply.rejection["files"]
    assert (refused["field"], refused["name"]) == ("file", name)


def test_error_payload_shape_and_no_leaked_details(app: App) -> None:
    reply = app.post("/legacy", file("cat.png", PHP, "image/png"))
    assert reply.rejection == {
        "error": "upload_rejected",
        "message": "The upload was rejected.",
        "files": [
            {
                "field": "file",
                "name": "cat.png",
                "errors": [
                    {"code": "type_not_allowed", "message": "PHP script files are not allowed."}
                ],
            }
        ],
    }


def test_browsers_get_escaped_html(app: App) -> None:
    reply = app.post(
        "/legacy",
        file("<img src=x onerror=alert(1)>.png", PHP),
        headers={"Accept": "text/html,application/xhtml+xml"},
    )
    assert reply.status == 400  # refused for its name ("<" and ">"), which the page echoes
    if app.framework == "fastapi":  # HTTPException: always JSON
        assert reply.codes == ["filename_invalid"]
        return
    assert reply.content_type.startswith("text/html")
    assert b"<img src=x" not in reply.body
    assert b"&lt;img src=x" in reply.body
    assert b"The file name contains invalid characters." in reply.body


def test_rejections_are_logged_with_the_hash_of_the_refused_bytes(
    app: App, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger="uploadshield")
    app.post("/documents", file("cat.pdf", PHP))
    (record,) = [r for r in caplog.records if r.name == "uploadshield"]
    upload = record.__dict__["upload"]
    assert (upload["path"], upload["field"], upload["policy"]) == (
        "/documents",
        "file",
        "documents",
    )
    assert [v["code"] for v in upload["violations"]] == ["type_not_allowed"]
    assert upload["detected_type"] == "application/x-httpd-php"
    assert upload["sha256"] == sha256(PHP)


# --------------------------------------------------------------------------- #
# Filenames the frameworks themselves treat differently
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name", ["../../etc/x.png", "..\\..\\boot\\x.png", "C:\\Windows\\x.png", "/var/www/x.png"]
)
def test_path_components_never_reach_the_view(app: App, name: str) -> None:
    # Each parser reads these differently: Django keeps the last component, Werkzeug
    # unescapes backslashes ("C:Windowsx.png"), python-multipart keeps the last
    # component of Windows paths only.  Whatever arrives must be refused or harmless.
    reply = app.post("/legacy", file(name, corpus.png()))
    if reply.status == 200:
        (delivered,) = reply.files
        assert delivered["name"] == "x.png"
    else:
        assert reply.status == 400
        assert reply.codes
        assert all(code.startswith("filename_") for code in reply.codes)
    if app.framework == "django":
        assert reply.status == 200


def test_bidi_overrides_never_reach_the_view(app: App) -> None:
    # "invoice\u202egnp.exe" displays as "invoiceexe.png".  Django deletes unprintable
    # characters from names itself (and then sees ".exe"); the others pass it on.
    reply = app.post("/legacy", file("invoice\u202egnp.exe", corpus.png()))
    expected = "filename_dangerous_extension" if app.framework == "django" else "filename_invalid"
    assert (reply.status, reply.codes[0]) == (400, expected)


def test_a_file_part_without_a_name_is_not_a_bypass(app: App) -> None:
    reply = app.post("/legacy", file("", PHP, "image/png"))
    if app.framework == "django":  # Django's parser drops nameless file parts
        assert reply.files == []
    else:
        assert (reply.status, reply.codes) == (400, ["filename_invalid"])


def test_an_empty_file_input_is_not_a_rejection(app: App) -> None:
    # What a browser sends for an <input type="file"> left empty.
    reply = app.post("/legacy", file("", b""))
    assert reply.rejection is None
    if reply.status == 422:  # recent FastAPI reports the required `file` as missing
        assert app.framework == "fastapi"
    else:
        assert all(f["size"] == 0 for f in reply.files)


# --------------------------------------------------------------------------- #
# Sanitization and several files
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("me.jpg", corpus.jpeg_with_metadata()),
        ("me.gif", corpus.animated_gif()),
        ("large.jpg", noise((1400, 1000), "JPEG", quality=95)),  # spooled to disk first
    ],
    ids=["exif-gps", "animated-gif", "large-jpeg"],
)
def test_avatars_are_the_engine_s_sanitized_bytes(app: App, name: str, data: bytes) -> None:
    (delivered,) = app.post("/avatar", file(name, data, "image/png")).files
    expected = sanitized(data, name)
    assert delivered["sha256"] == sha256(expected) != sha256(data)
    assert delivered["size"] == len(expected)
    stem, extension = delivered["name"].rsplit(".", 1)
    assert (len(stem), f".{extension}") == (32, name[name.rindex(".") :])
    assert delivered["content_type"] == f"image/{'jpeg' if extension == 'jpg' else extension}"


def test_gallery_keeps_order_and_detects_each_type(app: App) -> None:
    images = [
        ("1.png", corpus.png()),
        ("2.gif", corpus.image("GIF")),
        ("3.jpg", corpus.image("JPEG")),
    ]
    reply = app.post("/gallery", *(Part("files", n, d, "text/plain") for n, d in images))
    assert [(f["field"], f["name"], f["content_type"], f["sha256"]) for f in reply.files] == [
        ("files", "1.png", "image/png", sha256(images[0][1])),
        ("files", "2.gif", "image/gif", sha256(images[1][1])),
        ("files", "3.jpg", "image/jpeg", sha256(images[2][1])),
    ]


def test_one_bad_file_refuses_the_whole_request(app: App) -> None:
    reply = app.post(
        "/gallery",
        Part("files", "ok.png", corpus.png()),
        Part("files", "cat.png", PHP),
        Part("files", "ok2.png", corpus.png()),
    )
    assert reply.status == 415
    assert reply.rejection is not None
    assert [(f["field"], f["name"]) for f in reply.rejection["files"]] == [("files", "cat.png")]


def test_mixed_problems(app: App) -> None:
    reply = app.post(
        "/gallery",
        Part("files", "cat.png", PHP),  # 415 on its own
        Part("files", "shell.php.png", corpus.png()),  # 400 on its own
    )
    assert reply.rejection is not None
    if app.framework == "django":  # the stream is aborted at the first refused file
        assert reply.status == 415
        expected = [["type_not_allowed"]]
    else:  # parsed completely first: every file is reported, and mixed problems are a 400
        assert reply.status == 400
        expected = [["type_not_allowed"], ["filename_dangerous_extension"]]
    assert [[e["code"] for e in f["errors"]] for f in reply.rejection["files"]] == expected


# --------------------------------------------------------------------------- #
# Django only: the HTML form with inline errors
# --------------------------------------------------------------------------- #


@pytest.fixture
def django_app() -> Iterator[App]:
    for send in _django(asgi=False):
        yield App("django-wsgi", send)


def form(nickname: str, picture: Part | None) -> tuple[Part, ...]:
    return (Part("nickname", None, nickname.encode()), *([picture] if picture else []))


def test_django_form_shows_refusals_next_to_the_field(django_app: App) -> None:
    reply = django_app.post(
        "/profile", *form("mallory", Part("picture", "me.png", PHP)), headers={}
    )
    assert reply.status == 200  # the view ran and re-rendered its form
    html = reply.body.decode()
    assert "PHP script files are not allowed." in html
    assert 'value="mallory"' in html  # the rest of the form survives
    assert "&lt;?php" not in html  # the refused bytes never reached the view


def test_django_form_receives_the_sanitized_picture(django_app: App) -> None:
    data = corpus.jpeg_with_metadata()
    reply = django_app.post("/profile", *form("alice", Part("picture", "me.jpg", data)))
    (delivered,) = reply.files
    assert delivered["sha256"] == sha256(sanitized(data, "me.jpg"))
    assert delivered["name"] != "me.jpg"


def test_django_form_field_is_still_required(django_app: App) -> None:
    reply = django_app.post("/profile", *form("bob", None), headers={})
    assert reply.status == 200
    assert "This field is required." in reply.body.decode()


@pytest.mark.owasp("intro.csrf")
def test_django_form_keeps_csrf_while_the_api_is_exempt() -> None:
    from django.test import Client, override_settings

    with override_settings(**django_example_settings()):
        client = Client(enforce_csrf_checks=True)
        body = encode(form("eve", Part("picture", "me.png", corpus.png())))
        assert client.post("/profile", body, content_type=CONTENT_TYPE).status_code == 403
        api = client.post(
            "/legacy", encode((file("a.png", corpus.png()),)), content_type=CONTENT_TYPE
        )
        assert api.status_code == 200
        page = client.get("/profile")
        assert page.status_code == 200
        assert b'name="csrfmiddlewaretoken"' in page.content


def test_django_example_passes_the_system_checks() -> None:
    from django.core import checks
    from django.test import override_settings

    with override_settings(**django_example_settings()):
        found = checks.run_checks(tags=["security"])
    found = [m for m in found if (m.id or "").startswith("uploadshield")]
    assert found == []  # handler installed, handler400 wired, every policy usable
