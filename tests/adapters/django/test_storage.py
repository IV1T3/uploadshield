"""ValidatingStorage: nothing is persisted without passing its policy."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import django
import pytest
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage, default_storage
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, override_settings
from PIL import Image

from tests.django_site.settings import DJANGO_UPLOAD_HANDLERS
from tests.support import corpus
from uploadshield.django import UploadRejected, file_rejected
from uploadshield.django.storage import ValidatingStorage, ValidatingStorageMixin

PHP = b"<?php system($_GET['cmd']); ?>"


@pytest.fixture
def storage(tmp_path: Path) -> ValidatingStorage:
    return ValidatingStorage(
        options={"location": str(tmp_path), "base_url": "/media/"},
        policy="default",
        path_policies={"avatars/": "sanitized_images", "thumbs/": None, "docs/": "pdf"},
    )


@pytest.fixture
def use_default_storage(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Install a storage as ``default_storage``.

    ``override_settings(STORAGES=...)`` drops ``OPTIONS`` on Django < 5.1 (its
    ``DEFAULT_FILE_STORAGE`` compatibility shim); real settings modules are fine.
    """
    from django.core.files.storage import storages

    def install(storage: ValidatingStorage) -> ValidatingStorage:
        monkeypatch.setattr(default_storage, "_wrapped", storage)
        # Django's (private, stable) cache of instantiated storages.
        monkeypatch.setitem(storages._storages, "default", storage)  # ty: ignore[unresolved-attribute]
        return storage

    return install


def files_in(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())


def test_valid_files_are_stored(storage: ValidatingStorage, tmp_path: Path) -> None:
    name = storage.save("docs/report.pdf", ContentFile(corpus.pdf()))
    assert name == "docs/report.pdf"
    assert (tmp_path / name).read_bytes() == corpus.pdf()


def test_rejected_files_are_never_written(storage: ValidatingStorage, tmp_path: Path) -> None:
    signalled: list[Any] = []
    file_rejected.connect(lambda **kw: signalled.append(kw), weak=False)
    try:
        with pytest.raises(UploadRejected, match="type_not_allowed") as excinfo:
            storage.save("docs/cv.pdf", ContentFile(PHP))
    finally:
        file_rejected.receivers.clear()
    assert files_in(tmp_path) == []
    assert excinfo.value.validation.rejected[0].policy_name == "pdf"
    assert signalled[0]["result"].codes == ("type_not_allowed",)


def test_path_policies_pick_the_longest_prefix(storage: ValidatingStorage, tmp_path: Path) -> None:
    with pytest.raises(UploadRejected):  # docs/ only accepts PDFs
        storage.save("docs/a.png", ContentFile(corpus.png()))
    assert storage.save("other/a.png", ContentFile(corpus.png())) == "other/a.png"  # default
    assert storage.save("thumbs/x.bin", ContentFile(b"\x00generated")) == "thumbs/x.bin"  # None


def test_sanitizing_policies_rewrite_name_and_content(storage: ValidatingStorage, tmp_path) -> None:
    name = storage.save("avatars/me.jpg", ContentFile(corpus.jpeg_with_metadata()))
    assert name.startswith("avatars/")
    assert name.endswith(".jpg")
    assert name != "avatars/me.jpg"
    stored = (tmp_path / name).read_bytes()
    assert b"EvilCam" not in stored
    with Image.open(io.BytesIO(stored)) as image:
        assert dict(image.getexif()) == {}


def test_files_validated_upstream_are_not_checked_again(
    storage: ValidatingStorage, monkeypatch: pytest.MonkeyPatch
) -> None:
    from uploadshield.django import service
    from uploadshield.django.conf import get_config

    calls: list[str] = []
    real = service.validate

    def spy(upload: Any, policy: Any, **kwargs: Any) -> Any:
        calls.append(upload.name)
        return real(upload, policy, **kwargs)

    monkeypatch.setattr(service, "validate", spy)
    policy = get_config().resolve("sanitized_images")
    original = SimpleUploadedFile("me.jpg", corpus.jpeg_with_metadata())
    result = service.validate_file(original, policy)
    assert result is not None
    delivered = service.build_replacement(original, result, policy)
    storage.save(f"avatars/{delivered.name}", delivered)
    assert calls == ["me.jpg"]  # validated (and re-encoded) once, by the upstream layer


def test_the_stored_name_is_what_counts(storage: ValidatingStorage, tmp_path: Path) -> None:
    # A file validated as "a.pdf" upstream but stored as ".html" (e.g. by upload_to).
    pdf = SimpleUploadedFile("a.pdf", corpus.pdf())
    assert storage.save("docs/a.pdf", pdf) == "docs/a.pdf"
    with pytest.raises(UploadRejected, match="extension_mismatch"):
        storage.save("other/a.html", SimpleUploadedFile("a.pdf", corpus.pdf()))
    assert files_in(tmp_path) == ["docs/a.pdf"]


def test_rejected_placeholders_cannot_be_stored(storage: ValidatingStorage) -> None:
    from uploadshield.django import RejectedUpload
    from uploadshield.django.conf import get_config
    from uploadshield.engine import preflight
    from uploadshield.presets import PDF

    placeholder = RejectedUpload(
        preflight(PDF, stages={"name"}, name="cv.php.pdf"), field_name="cv", config=get_config()
    )
    with pytest.raises(UploadRejected):
        storage.save("docs/cv.pdf", placeholder)


def test_storage_api_is_delegated(storage: ValidatingStorage, tmp_path: Path) -> None:
    name = storage.save("other/a.txt", ContentFile(b"hello"))
    assert storage.exists(name)
    assert storage.size(name) == 5
    assert storage.url(name) == "/media/other/a.txt"
    assert storage.path(name) == str(tmp_path / name)
    assert storage.listdir("other") == ([], ["a.txt"])
    with storage.open(name) as fh:
        assert fh.read() == b"hello"
    assert storage.get_modified_time(name) is not None
    assert storage.get_available_name(name) != name
    assert storage.generate_filename("dir/my file.txt") == "dir/my_file.txt"
    assert storage.location == str(tmp_path)  # backend-specific attribute
    storage.delete(name)
    assert not storage.exists(name)
    assert storage.deconstruct()[0] == "uploadshield.django.storage.ValidatingStorage"


def test_storage_follows_the_global_mode(storage: ValidatingStorage, tmp_path: Path) -> None:
    from tests.django_site.settings import UPLOADSHIELD

    with override_settings(UPLOADSHIELD={**UPLOADSHIELD, "MODE": "report"}):
        assert storage.save("docs/cv.pdf", ContentFile(PHP)) == "docs/cv.pdf"  # logged only
    with override_settings(UPLOADSHIELD={**UPLOADSHIELD, "MODE": "off"}):
        assert storage.save("docs/cv2.pdf", ContentFile(PHP)) == "docs/cv2.pdf"
    assert files_in(tmp_path) == ["docs/cv.pdf", "docs/cv2.pdf"]


def test_mixin_for_custom_backends(tmp_path: Path) -> None:
    class PdfOnlyStorage(ValidatingStorageMixin, FileSystemStorage):
        upload_policy = "pdf"

    storage = PdfOnlyStorage(location=str(tmp_path))
    assert storage.save("a.pdf", ContentFile(corpus.pdf())) == "a.pdf"
    with pytest.raises(UploadRejected):
        storage.save("a.png", io.BytesIO(corpus.png()))  # plain file objects work too


@pytest.mark.django_db
def test_default_storage_protects_code_outside_requests(
    tmp_path: Path, use_default_storage
) -> None:
    use_default_storage(ValidatingStorage(options={"location": str(tmp_path)}, policy="pdf"))
    from tests.django_site.testapp.models import Document

    document = Document(title="from a task")
    with pytest.raises(UploadRejected):
        document.file.save("cv.pdf", ContentFile(PHP), save=False)  # e.g. in Celery
    with pytest.raises(UploadRejected):
        default_storage.save("legacy.pdf", ContentFile(PHP))
    document.file.save("ok.pdf", ContentFile(corpus.pdf()), save=True)
    assert files_in(tmp_path) == ["docs/ok.pdf"]


@pytest.mark.skipif(django.VERSION < (5, 1), reason="STORAGES OPTIONS shim in older Django")
def test_configured_through_storages_setting(tmp_path: Path) -> None:
    storages = {
        "default": {
            "BACKEND": "uploadshield.django.storage.ValidatingStorage",
            "OPTIONS": {"options": {"location": str(tmp_path)}, "policy": "pdf"},
        }
    }
    with override_settings(STORAGES=storages):
        assert getattr(default_storage, "upload_policy", None) == "pdf"
        with pytest.raises(UploadRejected):
            default_storage.save("a.png", ContentFile(corpus.png()))
        default_storage.save("a.pdf", ContentFile(corpus.pdf()))
    assert files_in(tmp_path) == ["a.pdf"]


def test_storage_backs_up_views_without_the_handler(tmp_path: Path, use_default_storage) -> None:
    use_default_storage(ValidatingStorage(options={"location": str(tmp_path)}))
    with override_settings(FILE_UPLOAD_HANDLERS=DJANGO_UPLOAD_HANDLERS):
        response = Client().post(
            "/store/",
            {"file": SimpleUploadedFile("cat.png", PHP)},
            headers={"Accept": "application/json"},
        )
    assert response.status_code == 415  # raised in the view, answered by handler400
    assert files_in(tmp_path) == []


def test_report_mode_reports_each_file_once_across_layers(
    tmp_path: Path, use_default_storage
) -> None:
    from tests.django_site.settings import UPLOADSHIELD
    from uploadshield.django import upload_rejected

    use_default_storage(ValidatingStorage(options={"location": str(tmp_path)}))
    request_level: list[Any] = []
    field_level: list[Any] = []

    def on_request(**kw: Any) -> None:
        request_level.append(kw)

    def on_field(**kw: Any) -> None:
        field_level.append(kw)

    upload_rejected.connect(on_request)
    file_rejected.connect(on_field)
    try:
        with override_settings(UPLOADSHIELD={**UPLOADSHIELD, "MODE": "report"}):
            response = Client().post(
                "/store-checked/", {"file": SimpleUploadedFile("cat.png", PHP)}
            )
    finally:
        upload_rejected.disconnect(on_request)
        file_rejected.disconnect(on_field)
    assert response.status_code == 200
    assert files_in(tmp_path) == ["cat.png"]  # report mode stores
    assert len(request_level) == 1  # reported by the handler ...
    assert field_level == []  # ... and not a second time by the storage layer


# --------------------------------------------------------------------------- #
# Ways around save() that storage closes
# --------------------------------------------------------------------------- #

HTML = b"<!doctype html><html><body><script>alert(document.domain)</script></body></html>"


@pytest.mark.parametrize("mode", ["wb", "w", "ab", "r+b", "xb", "w+"])
def test_opening_for_writing_is_refused(
    storage: ValidatingStorage, tmp_path: Path, mode: str
) -> None:
    with pytest.raises(PermissionError, match="bypass"):
        storage.open("avatars/x.html", mode)
    assert files_in(tmp_path) == []


def test_opening_for_reading_and_unvalidated_paths(storage: ValidatingStorage) -> None:
    storage.save("docs/a.pdf", ContentFile(corpus.pdf()))
    with storage.open("docs/a.pdf") as fh:
        assert fh.read() == corpus.pdf()
    storage.save("thumbs/existing.png", ContentFile(corpus.png()))  # creates the directory
    with storage.open("thumbs/t.png", "wb") as fh:  # path_policies maps thumbs/ to None
        fh.write(corpus.png())
    with storage.open("thumbs/t.png", "rb") as fh:
        assert fh.read() == corpus.png()


def test_mixin_refuses_writing_too(tmp_path: Path) -> None:
    class Validated(ValidatingStorageMixin, FileSystemStorage):
        upload_policy = "default"

    with pytest.raises(PermissionError):
        Validated(location=str(tmp_path)).open("x.html", "wb")


def test_stored_files_copied_under_a_new_name_are_validated(
    storage: ValidatingStorage, tmp_path: Path
) -> None:
    from django.db.models.fields.files import FieldFile, FileField

    storage.save("thumbs/x.html", ContentFile(HTML))  # an unvalidated prefix
    field = FileField(storage=storage)
    field.name = "file"
    committed = FieldFile(None, field, "thumbs/x.html")
    with pytest.raises(UploadRejected):
        storage.save("avatars/copy.html", committed)
    committed.close()
    assert files_in(tmp_path) == ["thumbs/x.html"]
    # A stored PDF copied to a PDF prefix is fine.
    storage.save("thumbs/a.pdf", ContentFile(corpus.pdf()))
    pdf = FieldFile(None, field, "thumbs/a.pdf")
    assert storage.save("docs/copy.pdf", pdf) == "docs/copy.pdf"
    pdf.close()


def test_files_renamed_after_validation_are_judged_again(
    tmp_path: Path, use_default_storage
) -> None:
    storage = use_default_storage(ValidatingStorage(options={"location": str(tmp_path)}))
    # A valid PDF that a browser renders as a page when it is served as .html.
    pdf = corpus.pdf(b"4 0 obj << /Length 80 >> stream\n" + HTML + b"\nendstream endobj")
    send = {"file": SimpleUploadedFile("doc.pdf", pdf, content_type="application/pdf")}
    response = Client().post("/rename/", {**send, "filename": "doc.html"})
    assert response.status_code == 415  # UploadRejected from storage -> handler400
    assert files_in(tmp_path) == []
    send = {"file": SimpleUploadedFile("doc.pdf", pdf, content_type="application/pdf")}
    assert Client().post("/rename/", {**send, "filename": "renamed.pdf"}).json() == {
        "saved": "renamed.pdf"
    }
    assert storage.exists("renamed.pdf")
