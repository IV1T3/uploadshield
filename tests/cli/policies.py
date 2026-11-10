"""Policies the CLI tests import by dotted path."""

from uploadshield import presets
from uploadshield.sanitizers import SafeFilename

SAFE_NAMES = presets.PDF.replace(name="safe_names", sanitizers=(SafeFilename(),))
STRICT_TYPES = presets.PDF.replace(name="strict_types", match_declared_type=True)
