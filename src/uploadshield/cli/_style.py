"""Terminal styling: colour decisions, glyphs, and escaping of untrusted names."""

from __future__ import annotations

import os
import sys
import unicodedata
from typing import TextIO

__all__ = ["Style", "color_enabled", "safe"]

_BIDI_CONTROLS = frozenset(
    "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
)
_CODES = {
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
}


def safe(text: str) -> str:
    """``text`` with everything that could act on a terminal made visible.

    File names are attacker-controlled: an ESC byte would let a name rewrite the
    screen, CR/LF would forge lines, bidi overrides would reverse what is shown, and
    undecodable bytes (lone surrogates) would crash the output stream.
    """
    if text.isprintable() and not _BIDI_CONTROLS.intersection(text):
        return text
    out: list[str] = []
    for char in text:
        if char in _BIDI_CONTROLS or unicodedata.category(char) in ("Cc", "Cs"):
            point = ord(char)
            out.append(f"\\x{point:02x}" if point < 0x100 else f"\\u{point:04x}")
        else:
            out.append(char)
    return "".join(out)


def color_enabled(choice: str, stream: TextIO) -> bool:
    """``--color`` first, then ``NO_COLOR``, ``FORCE_COLOR``, and finally a TTY check."""
    if choice != "auto":
        return choice == "always"
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR", "0") not in ("", "0"):
        return True
    if os.environ.get("TERM") == "dumb" or not _isatty(stream):
        return False
    return sys.platform != "win32" or "WT_SESSION" in os.environ


def _isatty(stream: TextIO) -> bool:
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


def _can_encode(stream: TextIO, text: str) -> bool:
    try:
        text.encode(getattr(stream, "encoding", None) or "ascii")
    except (UnicodeEncodeError, LookupError):
        return False
    return True


class Style:
    """Colours and glyphs for one output stream (plain text when colour is off)."""

    def __init__(self, stream: TextIO, *, color: bool) -> None:
        self.color = color
        fancy = _can_encode(stream, "\u2713\u2717\u2192\u00b7\u2026\u2500")
        self.ok, self.bad = ("\u2713", "\u2717") if fancy else ("OK", "X")
        self.arrow = "\u2192" if fancy else "->"
        self.dot = "\u00b7" if fancy else "-"
        self.ellipsis = "\u2026" if fancy else "..."

    def paint(self, text: str, *styles: str) -> str:
        if not self.color or not styles or not text:
            return text
        codes = ";".join(_CODES[s] for s in styles)
        return f"\x1b[{codes}m{text}\x1b[0m"

    def bold(self, text: str) -> str:
        return self.paint(text, "bold")

    def dim(self, text: str) -> str:
        return self.paint(text, "dim")
