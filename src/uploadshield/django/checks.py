"""Django system checks (``manage.py check``) for configuration mistakes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.core import checks
from django.core.exceptions import ImproperlyConfigured

from uploadshield.checks import ImageIntegrity, YaraRules
from uploadshield.checks.image import PILLOW_FORMATS

from .conf import SETTING, load_config

if TYPE_CHECKING:
    from uploadshield.policy import Policy

__all__ = ["check_configuration"]

_HANDLER = "uploadshield.django.handlers.ValidatingUploadHandler"


def _uses_our_handler400() -> bool:
    from importlib import import_module

    from django.utils.module_loading import import_string

    from .views import bad_request

    urlconf = getattr(settings, "ROOT_URLCONF", None)
    if not urlconf:
        return False
    try:
        handler = getattr(import_module(urlconf), "handler400", None)
        if isinstance(handler, str):
            handler = import_string(handler)
    except ImportError:
        return False
    return handler is bad_request


def _distinct_policies(config: Any) -> list[Policy]:
    seen: dict[Policy, None] = {}
    candidates = [*config.policies.values(), config.default_policy]
    candidates += [policy for _, policy in config.view_policies]
    for policy in candidates:
        if policy is not None:
            seen.setdefault(policy, None)
    return list(seen)


def _policy_messages(policy: Policy) -> list[checks.CheckMessage]:
    label = policy.name or repr(policy)
    found: list[checks.CheckMessage] = []
    for component in (*policy.checks, *policy.sanitizers):
        if missing := component.missing_dependencies():
            found.append(
                checks.Error(
                    f"Upload policy {label!r} uses {type(component).__name__}, which requires "
                    f"the missing module(s): {', '.join(missing)}.",
                    hint="Install the matching extra, e.g. uv add 'uploadshield[images,yara]'.",
                    id="uploadshield.E002",
                )
            )
        elif isinstance(component, YaraRules):
            try:
                component.compile()
            except Exception as exc:
                found.append(
                    checks.Error(
                        f"YARA rules of upload policy {label!r} do not compile: {exc}",
                        id="uploadshield.E003",
                    )
                )
    raster = any(policy.allows_mime(mime) for mime in PILLOW_FORMATS)
    uses_pillow = any(isinstance(c, ImageIntegrity) for c in policy.content_checks)
    if raster and uses_pillow and ImageIntegrity.missing_dependencies():
        found.append(
            checks.Warning(
                f"Upload policy {label!r} accepts images but Pillow is not installed, so image "
                "integrity checks are skipped.",
                hint="uv add 'uploadshield[images]'",
                id="uploadshield.W002",
            )
        )
    return found


@checks.register(checks.Tags.security)
def check_configuration(app_configs: Any = None, **kwargs: Any) -> list[checks.CheckMessage]:
    try:
        config = load_config()
    except ImproperlyConfigured as exc:
        return [checks.Error(str(exc), obj=SETTING, id="uploadshield.E001")]

    messages: list[checks.CheckMessage] = []
    for policy in _distinct_policies(config):
        messages += _policy_messages(policy)

    handlers = list(getattr(settings, "FILE_UPLOAD_HANDLERS", []))
    if _HANDLER not in handlers:
        messages.append(
            checks.Info(
                "ValidatingUploadHandler is not installed: only views with @validate_uploads, "
                "fields with FileValidator/ValidatedFileField and ValidatingStorage are protected.",
                hint=f"Set FILE_UPLOAD_HANDLERS = [{_HANDLER!r}] for project-wide protection.",
                id="uploadshield.I001",
            )
        )
        if config.max_upload_size is not None:
            messages.append(
                checks.Warning(
                    f"{SETTING}['MAX_UPLOAD_SIZE'] has no effect without ValidatingUploadHandler.",
                    id="uploadshield.W003",
                )
            )
    else:
        if handlers.index(_HANDLER) != 0:
            messages.append(
                checks.Warning(
                    "Upload handlers before ValidatingUploadHandler receive (and may store) file "
                    "data before it is validated.",
                    hint="Make ValidatingUploadHandler the only entry of FILE_UPLOAD_HANDLERS and "
                    f"list the others in {SETTING}['UPLOAD_HANDLERS'].",
                    id="uploadshield.W004",
                )
            )
        if len(handlers) > 1:
            messages.append(
                checks.Warning(
                    "Upload handlers listed next to ValidatingUploadHandler never receive data; it "
                    f"delegates storage to {SETTING}['UPLOAD_HANDLERS'] instead.",
                    hint=f"Move {[h for h in handlers if h != _HANDLER]!r} to "
                    f"{SETTING}['UPLOAD_HANDLERS'].",
                    id="uploadshield.W001",
                )
            )
        if not _uses_our_handler400():
            messages.append(
                checks.Info(
                    "Rejected uploads are answered by your handler400 with a generic 400 page.",
                    hint="Set handler400 = 'uploadshield.django.views.bad_request' in your "
                    "root URLconf for 413/415 status codes and JSON/HTML error details.",
                    id="uploadshield.I002",
                )
            )
    return messages
