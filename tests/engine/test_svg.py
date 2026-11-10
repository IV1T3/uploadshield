"""SvgActiveContent: script-capable SVG images."""

from __future__ import annotations

import pytest

from tests.support import corpus
from tests.support.engine import codes
from uploadshield import Policy
from uploadshield.checks import (
    SvgActiveContent,
)

SVG_POLICY = Policy(allowed_types={"image/svg+xml"})


@pytest.mark.parametrize(
    "body",
    [
        "<script>alert(1)</script>",
        "<svg:script>alert(1)</svg:script>",
        '<rect onload="alert(1)"/>',
        '<a href="javascript:alert(1)"><text>x</text></a>',
        '<a href="&#106;ava&#x09;script:alert(1)"><text>x</text></a>',
        "<foreignObject><iframe src=x></iframe></foreignObject>",
        '<image href="https://tracker.example/pixel.png"/>',
        '<use xlink:href="//evil.example/sprite.svg#a"/>',
        '<set attributeName="href" to="javascript:alert(1)"/>',
        # Found by the adversarial evaluation (2026-11-10): SMIL event-handler set,
        # the SVG Tiny handler element, and CSS-based script/resource loading.
        '<set attributeName="onload" to="alert(1)"/>',
        '<animate attributeName="onbegin" to="alert(1)"/>',
        "<handler>alert(1)</handler>",
        "<ev:handler>alert(1)</ev:handler>",
        "<style>rect{width:expression(alert(1))}</style>",
        "<style>@import url(http://evil.example/x.css);</style>",
        # CSS obfuscation found by the security-review follow-up (2026-11-10): an
        # external url(), a comment inside expression(), and a backslash-escaped @import.
        "<style>rect{background:url(http://evil.example/a)}</style>",
        "<style>rect{width:expr/**/ession(alert(1))}</style>",
        r"<style>@im\port url(http://evil.example/x.css);</style>",
    ],
)
def test_svg_active_content(body: str) -> None:
    assert codes(corpus.svg(body), "a.svg", SVG_POLICY) == ("svg_active_content",)


def test_svg_entities_and_benign_svg() -> None:
    xxe = b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg>&x;</svg>'
    assert codes(xxe, "a.svg", SVG_POLICY) == ("svg_active_content",)
    assert codes(corpus.svg('<text x="1">phone one = two</text>'), "a.svg", SVG_POLICY) == ()
    assert codes(corpus.svg(), "a.svg", SVG_POLICY) == ()
    assert codes(corpus.svg(), "a.svg", SVG_POLICY.replace(content_checks=())) == ()
    assert SvgActiveContent().name == "svg"


@pytest.mark.parametrize(
    "svg",
    [
        # A ">" inside an attribute value does not end the tag for an XML parser.
        b'<svg xmlns="http://www.w3.org/2000/svg" aria-label="1>2" onload="alert(1)"/>',
        b"<svg xmlns='http://www.w3.org/2000/svg' title='a>b' onload='alert(1)'/>",
        b'<svg xmlns="http://www.w3.org/2000/svg" title="a&quot;>" onload="alert(1)"/>',
        b'<svg xmlns="http://www.w3.org/2000/svg"/onload="alert(1)"/>',
        b'<svg xmlns="http://www.w3.org/2000/svg" a="1"onload="alert(1)"/>',
        b'<svg xmlns="http://www.w3.org/2000/svg"><rect x=1 ONLOAD=alert(1) /></svg>',
        b'<svg xmlns="http://www.w3.org/2000/svg">\n<rect\n\tonclick\n=\n"alert(1)"/></svg>',
    ],
)
def test_event_handlers_after_tricky_attributes(svg: bytes) -> None:
    assert codes(svg, "a.svg", SVG_POLICY) == ("svg_active_content",)


@pytest.mark.parametrize(
    "body",
    [
        "<text>click on = here, or online=yes</text>",
        '<rect data-onload="1" aria-description="turn on=off"/>',
        '<text x="1">a > b; one=1</text>',
        # Benign SMIL animation and styling must not trip the new rules above.
        '<set attributeName="opacity" to="0"/>',
        '<animate attributeName="x" from="0" to="9" dur="1s"/>',
        '<set attributeName="orient" to="auto"/>',
        "<style>rect{fill:red;width:10px}</style>",
        # A data: URI font and a fragment reference are not external resources.
        "<style>@font-face{font-family:x;src:url(data:font/woff2;base64,AAAA)}</style>",
        '<use href="#gradient"/>',
        "<style>/* a theme comment */ rect{fill:blue}</style>",
    ],
)
def test_text_and_attribute_values_mentioning_on_are_fine(body: str) -> None:
    assert codes(corpus.svg(body), "a.svg", SVG_POLICY) == ()


@pytest.mark.parametrize(
    "unit", ["<a ", '<a b="', "<a", "<!doctype", "<set ", " b", "/*x", "*/", "\\41", "@im"]
)
def test_svg_rules_scan_in_linear_time(unit: str) -> None:
    import time

    data = b'<svg xmlns="http://www.w3.org/2000/svg">' + unit.encode() * 100_000
    started = time.perf_counter()
    codes(data, "a.svg", SVG_POLICY)
    assert time.perf_counter() - started < 2
