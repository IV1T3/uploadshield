"""Configuration, system checks, validators, form fields and migrations."""

from __future__ import annotations

from typing import Any

import pytest
from django import forms
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile, UploadedFile
from django.db.migrations.writer import MigrationWriter
from django.test import Client, override_settings
from django.utils.datastructures import MultiValueDict

from tests.django_site.settings import DJANGO_UPLOAD_HANDLERS, UPLOADSHIELD
from tests.django_site.testapp import views
from tests.django_site.testapp.models import Document
from tests.support import corpus
from uploadshield import Policy, presets
from uploadshield.checks import YaraRules
from uploadshield.core.check import Check
from uploadshield.django import FileValidator, ValidatedFileField
from uploadshield.django.checks import check_configuration
from uploadshield.django.conf import get_config, load_config
from uploadshield.django.service import SKIP, ViewSpec, get_view_spec

PHP = b"<?php echo 1; ?>"


def config_with(**overrides: Any) -> dict[str, Any]:
    return {**UPLOADSHIELD, **overrides}


def files(mapping: dict[str, SimpleUploadedFile]) -> MultiValueDict[str, UploadedFile]:
    return MultiValueDict({name: [upload] for name, upload in mapping.items()})


def check_ids(**settings: Any) -> list[str]:
    with override_settings(**settings):
        return [m.id or "" for m in check_configuration()]


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("config", "message"),
    [
        ({"MODEE": "report"}, "Unknown UPLOADSHIELD keys: MODEE"),
        ({"MODE": "strict"}, "must be one of"),
        ({"POLICIES": {"x": {"allowed_types": ["image/png"]}}}, "must be a Policy"),
        ({"DEFAULT_POLICY": "nope"}, "Unknown upload policy 'nope'"),
        ({"DEFAULT_POLICY": 42}, "must be a Policy or a string"),
        (
            {"DEFAULT_POLICY": "tests.django_site.testapp.policies.NOT_A_POLICY"},
            "is not a",
        ),
        (
            {"DEFAULT_POLICY": "tests.django_site.testapp.policies.MISSING"},
            "Cannot import upload policy",
        ),
        ({"VIEW_POLICIES": {"x-*": "nope"}}, "Unknown upload policy"),
        ({"REJECTION_HANDLER": "tests.nowhere.handler"}, "Cannot import REJECTION_HANDLER"),
        ({"REJECTION_HANDLER": 42}, "must be callable"),
        ({"MAX_UPLOAD_SIZE": -5}, "positive int"),
    ],
)
def test_invalid_configuration(config: dict[str, Any], message: str) -> None:
    with (
        override_settings(UPLOADSHIELD=config),
        pytest.raises(ImproperlyConfigured, match=message),
    ):
        load_config()


def test_non_dict_setting() -> None:
    with override_settings(UPLOADSHIELD=["nope"]), pytest.raises(ImproperlyConfigured):
        load_config()


def test_defaults_and_resolution() -> None:
    with override_settings(UPLOADSHIELD={}):
        config = get_config()
        assert config.mode == "enforce"
        assert config.default_policy is presets.DEFAULT
        assert config.resolve("images") is presets.IMAGES
        assert config.resolve("tests.django_site.testapp.policies.CUSTOM").name == "custom"
        assert config.resolve(presets.PDF) is presets.PDF
    assert get_config().resolve("tiny_images").max_size == 2_000  # cache reset on change


def test_misconfiguration_surfaces_when_the_handler_is_built() -> None:
    from uploadshield.django.handlers import ValidatingUploadHandler

    with (
        override_settings(UPLOADSHIELD={"MODE": "bogus"}),
        pytest.raises(ImproperlyConfigured),
    ):
        ValidatingUploadHandler()


@pytest.mark.parametrize(
    ("handlers", "message"),
    [
        ([], "non-empty list"),
        ("django.core.files.uploadhandler.MemoryFileUploadHandler", "non-empty list"),
        (["uploadshield.django.handlers.ValidatingUploadHandler"], "must not contain"),
        (["tests.nowhere.Handler"], "Cannot import upload handler"),
        (["tests.django_site.testapp.policies.CUSTOM"], "not a FileUploadHandler"),
    ],
)
def test_invalid_upload_handlers_setting(handlers: Any, message: str) -> None:
    config = config_with(UPLOAD_HANDLERS=handlers)
    with (
        override_settings(UPLOADSHIELD=config),
        pytest.raises(ImproperlyConfigured, match=message),
    ):
        load_config()


def test_invalid_on_reject_setting() -> None:
    with (
        override_settings(UPLOADSHIELD=config_with(ON_REJECT="maybe")),
        pytest.raises(ImproperlyConfigured, match="ON_REJECT"),
    ):
        load_config()


def test_view_spec_validation_and_lookup() -> None:
    with pytest.raises(ValueError, match="mode must be one of"):
        ViewSpec(mode="sometimes")
    assert get_view_spec(views.raw) is SKIP
    assert get_view_spec(views.PdfView.as_view()) is not None
    assert get_view_spec(views.plain) is None
    with pytest.raises(TypeError, match="not a Django class-based view"):
        from uploadshield.django import validate_uploads

        validate_uploads("images")(type("NotAView", (), {}))


# --------------------------------------------------------------------------- #
# system checks
# --------------------------------------------------------------------------- #


def test_system_checks_clean_configuration() -> None:
    assert check_ids() == []


def test_system_check_reports_configuration_errors() -> None:
    assert check_ids(UPLOADSHIELD={"MODE": "bogus"}) == ["uploadshield.E001"]


class NeedsMissingModule(Check):
    name = "needs_missing"
    requires = ("module_that_does_not_exist_123",)


def test_system_check_missing_dependency() -> None:
    broken = Policy(name="broken", allowed_types={"text/plain"}, checks=(NeedsMissingModule(),))
    ids = check_ids(UPLOADSHIELD=config_with(POLICIES={"broken": broken}))
    assert ids == ["uploadshield.E002"]


def test_system_check_bad_yara_rules() -> None:
    bad = Policy(name="bad", allowed_types={"text/plain"}, checks=(YaraRules(source="rule x {"),))
    ids = check_ids(UPLOADSHIELD=config_with(POLICIES={"bad": bad}))
    # Without yara-python installed the problem is the missing module itself.
    expected = "uploadshield.E002" if YaraRules.missing_dependencies() else ("uploadshield.E003")
    assert ids == [expected]


@pytest.mark.owasp("intro.libraries")
def test_system_check_warns_when_pillow_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    from uploadshield.checks import ImageIntegrity

    monkeypatch.setattr(ImageIntegrity, "missing_dependencies", classmethod(lambda cls: ("PIL",)))
    assert "uploadshield.W002" in check_ids()


def test_system_check_handler_installation() -> None:
    ours = "uploadshield.django.handlers.ValidatingUploadHandler"
    memory = "django.core.files.uploadhandler.MemoryFileUploadHandler"
    assert check_ids(FILE_UPLOAD_HANDLERS=DJANGO_UPLOAD_HANDLERS) == ["uploadshield.I001"]
    capped = config_with(MAX_UPLOAD_SIZE=1000)
    assert check_ids(FILE_UPLOAD_HANDLERS=DJANGO_UPLOAD_HANDLERS, UPLOADSHIELD=capped) == [
        "uploadshield.I001",
        "uploadshield.W003",
    ]
    assert check_ids(FILE_UPLOAD_HANDLERS=[memory, ours]) == [
        "uploadshield.W004",
        "uploadshield.W001",
    ]
    assert check_ids(FILE_UPLOAD_HANDLERS=[ours, memory]) == ["uploadshield.W001"]


def test_system_check_handler400() -> None:
    assert check_ids(ROOT_URLCONF="tests.django_site.urls_without_handler400") == [
        "uploadshield.I002"
    ]


# --------------------------------------------------------------------------- #
# FileValidator
# --------------------------------------------------------------------------- #


def test_file_validator_on_plain_form_field() -> None:
    class Form(forms.Form):
        cv = forms.FileField(validators=[FileValidator("pdf")])

    ok = Form(files=files({"cv": SimpleUploadedFile("cv.pdf", corpus.pdf())}))
    assert ok.is_valid()
    bad = Form(files=files({"cv": SimpleUploadedFile("cv.pdf", corpus.pdf_with_javascript())}))
    assert not bad.is_valid()
    assert bad.errors.as_data()["cv"][0].code == "pdf_active_content"


def test_file_validator_enforces_even_in_report_mode() -> None:
    with (
        override_settings(UPLOADSHIELD=config_with(MODE="report")),
        pytest.raises(ValidationError) as excinfo,
    ):
        FileValidator("images")(SimpleUploadedFile("a.png", PHP))
    assert excinfo.value.error_list[0].code == "type_not_allowed"


def test_file_validator_with_policy_object_and_content_file() -> None:
    validator = FileValidator(presets.IMAGES.replace(max_size=10))
    with pytest.raises(ValidationError) as excinfo:
        validator(ContentFile(corpus.png(), name="a.png"))
    assert [e.code for e in excinfo.value.error_list] == ["file_too_large"]
    assert validator == FileValidator(presets.IMAGES.replace(max_size=10))
    assert validator != FileValidator("images")
    assert repr(FileValidator("pdf")) == "FileValidator('pdf')"
    assert hash(FileValidator("pdf")) == hash(FileValidator("pdf"))


@pytest.mark.django_db
def test_file_validator_on_model_via_model_form() -> None:
    form = views.DocumentForm(
        data={"title": "t"}, files=files({"file": SimpleUploadedFile("a.png", corpus.png())})
    )
    assert not form.is_valid()
    assert form.errors.as_data()["file"][0].code == "type_not_allowed"
    good = views.DocumentForm(
        data={"title": "t"}, files=files({"file": SimpleUploadedFile("a.pdf", corpus.pdf())})
    )
    assert good.is_valid(), good.errors


@pytest.mark.django_db
def test_stored_files_are_not_revalidated(tmp_path, settings) -> None:
    settings.MEDIA_ROOT = str(tmp_path)
    doc = Document(title="t")
    doc.file.save("stored.pdf", ContentFile(corpus.pdf()), save=False)
    doc.full_clean()  # committed FieldFile: no re-validation, no storage read


@pytest.mark.django_db
def test_model_form_view_end_to_end() -> None:
    client = Client()
    bad = client.post("/model-form/", {"title": "x", "file": SimpleUploadedFile("a.png", PHP)})
    assert bad.status_code == 400
    assert bad.json()["errors"]["file"][0]["code"] == "type_not_allowed"
    ok = client.post(
        "/model-form/", {"title": "x", "file": SimpleUploadedFile("a.pdf", corpus.pdf())}
    )
    assert ok.status_code == 200


def test_validators_serialise_into_migrations() -> None:
    by_name, imports = MigrationWriter.serialize(FileValidator("pdf"))
    assert by_name == "uploadshield.django.FileValidator('pdf')"
    assert imports == {"import uploadshield.django"}
    by_object, imports = MigrationWriter.serialize(
        FileValidator(presets.PDF.replace(max_size=1000))
    )
    assert "uploadshield.Policy(" in by_object
    assert "max_size=1000" in by_object
    namespace: dict[str, Any] = {}
    exec(  # noqa: S102 - round-trip the generated migration code
        "\n".join(sorted(imports)) + f"\nvalue = {by_object}", namespace
    )
    assert namespace["value"] == FileValidator(presets.PDF.replace(max_size=1000))


@pytest.mark.django_db
def test_no_missing_migrations_for_test_app() -> None:
    from io import StringIO

    from django.core.management import call_command

    out = StringIO()
    call_command("makemigrations", "testapp", "--check", "--dry-run", stdout=out)


# --------------------------------------------------------------------------- #
# ValidatedFileField
# --------------------------------------------------------------------------- #


def test_validated_file_field_returns_sanitized_file() -> None:
    form = views.AvatarForm(
        files=files({"picture": SimpleUploadedFile("me.jpg", corpus.jpeg_with_metadata())})
    )
    assert form.is_valid(), form.errors
    picture = form.cleaned_data["picture"]
    assert picture.name != "me.jpg"
    assert picture.name.endswith(".jpg")
    assert picture.content_type == "image/jpeg"
    assert b"EvilCam" not in picture.read()


def test_validated_file_field_errors_and_edge_cases() -> None:
    form = views.AvatarForm(files=files({"picture": SimpleUploadedFile("me.png", PHP)}))
    assert not form.is_valid()
    assert form.errors.as_data()["picture"][0].code == "type_not_allowed"

    class Optional(forms.Form):
        doc = ValidatedFileField(policy="pdf", required=False)

    empty = Optional(files=files({}))
    assert empty.is_valid()
    assert empty.cleaned_data["doc"] is None
    plain = Optional(files=files({"doc": SimpleUploadedFile("a.pdf", corpus.pdf(), "text/plain")}))
    assert plain.is_valid()
    assert plain.cleaned_data["doc"].content_type == "application/pdf"


def test_form_view_end_to_end() -> None:
    client = Client()
    response = client.post(
        "/form/", {"picture": SimpleUploadedFile("a.gif", corpus.animated_gif())}
    )
    assert response.status_code == 200
    assert response.json()["content_type"] == "image/gif"
    response = client.post("/form/", {"picture": SimpleUploadedFile("a.gif", corpus.pdf())})
    assert response.status_code == 400


def test_field_rejections_are_logged_and_signalled(upload_log) -> None:
    from uploadshield.django import file_rejected

    seen: list[dict[str, Any]] = []

    def receiver(**kwargs: Any) -> None:
        seen.append(kwargs)

    file_rejected.connect(receiver)
    try:
        with pytest.raises(ValidationError):
            FileValidator("pdf")(SimpleUploadedFile("a.pdf", PHP))
        form = views.AvatarForm(files=files({"picture": SimpleUploadedFile("me.png", PHP)}))
        assert not form.is_valid()
    finally:
        file_rejected.disconnect(receiver)
    assert [s["policy"].name for s in seen] == ["pdf", "sanitized_images"]
    assert all(s["result"].codes == ("type_not_allowed",) for s in seen)
    messages = [r.getMessage() for r in upload_log.records if "field validator" in r.getMessage()]
    assert len(messages) == 2
