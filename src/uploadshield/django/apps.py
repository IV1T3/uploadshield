from django.apps import AppConfig


class UploadShieldConfig(AppConfig):
    """Registers system checks and ships the overridable rejection template."""

    name = "uploadshield.django"
    label = "uploadshield"
    verbose_name = "UploadShield"

    def ready(self) -> None:
        # Importing the module registers the system checks.
        from uploadshield.django import checks  # noqa: F401
