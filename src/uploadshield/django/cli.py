"""The command line's bridge into a Django project (``uploadshield ... --django``).

The only place that calls ``django.setup()``: the command line itself stays free of
Django imports and loads this module only when asked to.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .conf import Config

__all__ = ["configure"]


def configure(settings: str | None = None) -> Config:
    """Set Django up with ``settings`` (or ``DJANGO_SETTINGS_MODULE``); return the config.

    Raises ``ImproperlyConfigured`` and import errors unchanged, for the caller to report.
    """
    if settings:
        os.environ["DJANGO_SETTINGS_MODULE"] = settings
    if not os.environ.get("DJANGO_SETTINGS_MODULE"):
        from django.core.exceptions import ImproperlyConfigured

        raise ImproperlyConfigured(
            "no settings: pass --settings myproject.settings or set DJANGO_SETTINGS_MODULE"
        )
    import django

    django.setup()
    from .conf import get_config

    return get_config()
