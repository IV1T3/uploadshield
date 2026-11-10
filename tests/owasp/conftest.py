"""Every test here can take the cross-framework ``app`` fixture and a fake ``clamd``."""

from tests.support.clamd import clamd
from tests.support.harness import app

__all__ = ["app", "clamd"]
