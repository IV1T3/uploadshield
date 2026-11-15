"""SvgActiveContent: script-capable SVG images."""

from __future__ import annotations

import random
import re
from xml.parsers import expat

import pytest

from tests.support import corpus
from tests.support.engine import codes
from uploadshield import Policy, Upload, validate
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
        # Second security-review round (2026-11-10): a comment must not hide content
        # outside <style>, and url()/href with a non-data scheme or backslashes is external.
        "/* <script>alert(1)</script>",
        "<style>rect{background:url(ftp://evil.example/a)}</style>",
        r"<style>rect{background:url(http:\\evil.example\a)}</style>",
        '<a href="vbscript:msgbox(1)"><rect width="9" height="9"/></a>',
        # Third review round (2026-11-10): browsers read "\" as "/" in URLs, so a
        # backslash scheme-relative href/url in a plain attribute is still external.
        r'<a href="\\evil.example/x"><rect width="9" height="9"/></a>',
        r'<image href="\/evil.example/x"/>',
        r"<style>rect{background:url(\\evil.example/a)}</style>",
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
        # A data: URI font/image, a fragment reference, and a relative path are not
        # external resources and must pass.
        "<style>@font-face{font-family:x;src:url(data:font/woff2;base64,AAAA)}</style>",
        '<image href="data:image/png;base64,iVBOR"/>',
        '<use href="#gradient"/><rect fill="url(#gradient)"/>',
        '<image href="photo.png"/>',
        "<style>/* a theme comment */ rect{fill:blue}</style>",
        # A backslash in text (not an href/url value) is not an external resource.
        r"<text>a path like C:\users\shared\logo is just text</text>",
    ],
)
def test_text_and_attribute_values_mentioning_on_are_fine(body: str) -> None:
    assert codes(corpus.svg(body), "a.svg", SVG_POLICY) == ()


@pytest.mark.parametrize(
    "unit",
    [
        "<a ", '<a b="', "<a", "<!doctype", "<set ", " b", "/*x", "*/", "\\41", "@im",
        # Attribute soup that made a single "any attributes, then on...=" pattern
        # backtrack exponentially (security review, 2026-11-14), and its relatives.
        "x=y/", "<a x=y/", "<a b=c ", "<a b = ", "<a =", '<a "', "<a b='", "<a/ ", "< ",
        "<a:", "<a:a:", "<_:", "<a\t=\t",
    ],
)  # fmt: skip
def test_svg_rules_scan_in_linear_time(unit: str) -> None:
    import time

    data = b'<svg xmlns="http://www.w3.org/2000/svg">' + unit.encode() * 100_000
    started = time.perf_counter()
    codes(data, "a.svg", SVG_POLICY)
    assert time.perf_counter() - started < 2


@pytest.mark.parametrize("repeats", [28, 40, 5_000, 500_000])
def test_attributes_without_an_event_handler_are_read_in_linear_time(repeats: int) -> None:
    # 28 repeats (166 bytes) used to take more than 30 seconds, doubling with every one.
    import time

    data = corpus.svg("<a " + "x=y/" * repeats + "></a>")
    started = time.perf_counter()
    assert codes(data, "a.svg", SVG_POLICY) == ()
    assert time.perf_counter() - started < 2


@pytest.mark.parametrize("run", [" ", "b", "/", "=", '"', "'", "a:", "\t"])
def test_one_long_run_inside_a_tag_is_read_in_linear_time(run: str) -> None:
    import time

    data = corpus.svg("<a " + run * (2_000_000 // len(run)))
    started = time.perf_counter()
    codes(data, "a.svg", SVG_POLICY)
    assert time.perf_counter() - started < 2


E_ACUTE = chr(0xE9)  # a non-ASCII letter: valid in the prefix of an element name
SVG_NS = "http://www.w3.org/2000/svg"


@pytest.mark.parametrize(
    "svg",
    [
        # Element names are not limited to ASCII letters, and a prefix is whatever the
        # document binds to the SVG namespace (security review, 2026-11-14).
        f'<_:svg xmlns:_="{SVG_NS}" onload="alert(1)"/>',
        f'<_:svg xmlns:_="{SVG_NS}"><_:rect onclick="alert(1)"/></_:svg>',
        f'<svg xmlns="{SVG_NS}" xmlns:x.y="{SVG_NS}"><x.y:script>alert(1)</x.y:script></svg>',
        f'<svg xmlns="{SVG_NS}" xmlns:{E_ACUTE}="{SVG_NS}">'
        f"<{E_ACUTE}:script>alert(1)</{E_ACUTE}:script></svg>",
        f'<svg xmlns="{SVG_NS}" xmlns:_="{SVG_NS}"><_:script>alert(1)</_:script></svg>',
        f'<svg xmlns="{SVG_NS}" xmlns:a-1="{SVG_NS}"><a-1:foreignObject/></svg>',
        f'<svg xmlns="{SVG_NS}" xmlns:x.y="{SVG_NS}"><x.y:handler>alert(1)</x.y:handler></svg>',
        f'<svg xmlns="{SVG_NS}" xmlns:x.y="{SVG_NS}">'
        '<x.y:set attributeName="onload" to="alert(1)"/></svg>',
        f'<svg xmlns="{SVG_NS}" xmlns:h.t="http://www.w3.org/1999/xhtml"><h.t:iframe/></svg>',
    ],
)
def test_active_content_under_any_namespace_prefix(svg: str) -> None:
    # The first two documents start with "<_", which the sniffer reads as SVG too.
    assert codes(svg.encode(), "a.svg", SVG_POLICY) == ("svg_active_content",)


@pytest.mark.parametrize(
    "body",
    [
        # A line break or a tab ends an element name like a space does.  The views the
        # rules are matched against have no line breaks ("<script" + "type=..."), so
        # element names are read from the markup as written (found by comparing the
        # check with an XML parser on random documents, 2026-11-14).
        '<script\ntype="text/javascript">alert(1)</script>',
        '<script\ttype="text/javascript">alert(1)</script>',
        '<script\r\nid="a">alert(1)</script>',
        '<svg:script\nid="a">alert(1)</svg:script>',
        '<x.y:script\n\tid="a">alert(1)</x.y:script>',
        '<foreignObject\nwidth="9" height="9"><p>x</p></foreignObject>',
        '<handler\ntype="text/javascript">alert(1)</handler>',
        '<set\nattributeName="onload" to="alert(1)"/>',
        '<animate\n\tattributeName\n=\n"xlink:href" to="javascript:alert(1)"/>',
        '<set\nid="a"\nattributeName="h&#114;ef" to="x"/>',
        '<x.y:set\nattributeName="x.y:href" to="x"/>',
        "<style>@import\nurl(a.css);</style>",
        '<style>@import\n"a.css";</style>',
    ],
)
def test_line_breaks_after_a_name_hide_nothing(body: str) -> None:
    assert codes(corpus.svg(body), "a.svg", SVG_POLICY) == ("svg_active_content",)


@pytest.mark.parametrize(
    "body",
    [
        '<text\nx="1">a script, an object and a frame</text>',
        '<set\nattributeName="opacity" to="0"/>',
        '<animate\nattributeName="x" from="0" to="9" dur="1s"/>',
        '<animateTransform\nattributeName="transform" type="rotate" from="0" to="9"/>',
        '<scripted\nid="a"/><objects\nid="b"/><settings\nattributeName="onload"/>',
        '<g\nid="script"\nclass="handler iframe"/>',
    ],
)
def test_ordinary_elements_on_several_lines_pass(body: str) -> None:
    assert codes(corpus.svg(body), "a.svg", SVG_POLICY) == ()


# What the generator below builds documents from: everything XML allows around names
# and attributes, plus look-alikes that must not be mistaken for the real thing.
PREFIXES = ["", "", "s", "_", "x.y", "a-b", E_ACUTE, "_.-"]
PLAIN_ELEMENTS = ["g", "rect", "text", "a", "defs", "on", "onload", "scripts", "settle"]
ACTIVE_ELEMENTS = ["script", "foreignObject", "handler", "iframe", "embed", "object", "frame"]
PLAIN_NAMES = ["id", "class", "data-onload", "xonload", "on", "on1", "x:onload", "on-load", "_on"]
HANDLER_NAMES = ["onload", "onclick", "onerror", "onbegin", "onx"]
TARGETS = ["x", "opacity", "on", "hre", "href", "xlink:href", "onload", " onbegin ", "h&#114;ef"]
SPACES = [" ", "  ", "\t", "\n", "\r\n", " \n\t "]
VALUE_PARTS = [
    "a",
    " ",
    ">",
    "/>",
    "=",
    "on",
    "onload=",
    "&quot;",
    "&#62;",
    "]]>",
    "--",
    "?>",
    "'",
    '"',
]
LOOK_ALIKES = ['<a onload="x">', "<script>", "onload=1", "> <", "a &gt; b", "on = off"]
HANDLER_NAME = re.compile(r"on[a-z]+", re.IGNORECASE)
ANIMATED_TARGET = re.compile(r"(?:[^\s:]+:)?(?:href|on[a-z])", re.IGNORECASE)


def random_attributes(rng: random.Random, risky: bool) -> str:
    out, used = "", set()
    for _ in range(rng.randint(0, 4)):
        name = rng.choice(HANDLER_NAMES if risky and rng.random() < 0.1 else PLAIN_NAMES)
        if name in used:
            continue
        used.add(name)
        quote = rng.choice("\"'")
        parts = (rng.choice(VALUE_PARTS) for _ in range(rng.randint(0, 4)))
        value = "".join(part for part in parts if quote not in part)
        out += rng.choice(SPACES) + name + rng.choice(["=", " = ", "\n=\n"]) + quote + value + quote
    return out + rng.choice(["", " ", "\n"])


def random_element(rng: random.Random, depth: int, risky: bool) -> str:
    prefix = rng.choice(PREFIXES)
    local = rng.choice(ACTIVE_ELEMENTS if risky and rng.random() < 0.05 else PLAIN_ELEMENTS)
    name = f"{prefix}:{local}" if prefix else local
    tag = "<" + name + random_attributes(rng, risky)
    if rng.random() < 0.08:  # a SMIL animation: its target decides whether it is active
        name = rng.choice(["set", "animate", "animateMotion"])
        tag = f"<{name}{rng.choice(SPACES)}attributeName{rng.choice(['=', ' = '])}"
        tag += f'"{rng.choice(TARGETS if risky else TARGETS[:4])}"'
    if depth == 0 or rng.random() < 0.4:
        return tag + "/>"
    inner = ""
    for _ in range(rng.randint(0, 3)):
        fake = rng.choice(LOOK_ALIKES)
        noise = [f"<!-- {fake} -->", f"<![CDATA[{fake}]]>", f"<?pi {fake} ?>", "text", ""]
        inner += rng.choice(noise) if rng.random() < 0.5 else random_element(rng, depth - 1, risky)
    return f"{tag}>{inner}</{name}>"


def random_svg(rng: random.Random) -> bytes:
    risky = rng.random() < 0.5
    bound = " ".join(f'xmlns:{p}="{SVG_NS}"' for p in sorted({p for p in PREFIXES if p}))
    body = "".join(random_element(rng, 2, risky) for _ in range(rng.randint(0, 4)))
    root = rng.choice(["svg", "s:svg", "_:svg"])
    opening = f'<{root} xmlns="{SVG_NS}" {bound}{random_attributes(rng, risky)}>'
    return f"{opening}{body}</{root}>".encode()


def parser_sees_active_content(data: bytes) -> bool | None:
    """What an XML parser makes of ``data``; ``None`` if it is not well-formed."""
    seen: list[str] = []
    active = {name.lower() for name in ACTIVE_ELEMENTS}

    def start(name: str, attributes: dict[str, str]) -> None:
        local = name.rpartition(":")[2].lower()
        target = attributes.get("attributeName", "").strip()
        if (
            local in active
            or (local in ("set", "animate") and ANIMATED_TARGET.match(target))
            or any(HANDLER_NAME.fullmatch(attribute) for attribute in attributes)
        ):
            seen.append(name)

    parser = expat.ParserCreate()
    parser.StartElementHandler = start
    try:
        parser.Parse(data, True)
    except expat.ExpatError:
        return None
    return bool(seen)


def test_the_check_misses_nothing_an_xml_parser_sees() -> None:
    # Random well-formed SVG: whenever an XML parser reports an "on..." attribute, an
    # element that runs script or embeds a document, or an animation of a handler or a
    # link, the check refuses.  (The check is more liberal than a parser - it also reads
    # tags in comments - so only this direction is asserted.)
    rng = random.Random(20261114)
    verdicts = []
    for _ in range(4000):
        data = random_svg(rng)
        verdict = parser_sees_active_content(data)
        if verdict:
            assert codes(data, "a.svg", SVG_POLICY) == ("svg_active_content",), data
        verdicts.append(verdict)
    assert verdicts.count(None) < 400  # the generator really produces well-formed XML,
    assert verdicts.count(True) > 500  # and enough of it is active to mean something


def test_a_root_element_the_sniffer_does_not_know_is_no_svg() -> None:
    # A root whose prefix is not ASCII is not recognised as SVG, so it never gets as far
    # as this check: it is text, which an SVG policy does not allow and ".svg" does not fit.
    svg = f'<{E_ACUTE}:svg xmlns:{E_ACUTE}="{SVG_NS}" onload="alert(1)"/>'.encode()
    assert codes(svg, "a.svg", SVG_POLICY) == ("type_not_allowed",)
    both = Policy(allowed_types={"image/svg+xml", "text/plain"})
    assert codes(svg, "a.svg", both) == ("extension_mismatch",)


@pytest.mark.parametrize(
    "encoding",
    ["ISO-2022-JP", "iso-2022-kr", "Shift_JIS", "EUC-JP", "GBK", "Big5", "UTF-7", "IBM037", "x"],
)
def test_svg_in_an_encoding_that_cannot_be_read_reliably_is_refused(encoding: str) -> None:
    # Such encodings can spell "<script" with other bytes, or drop bytes while decoding
    # ("scr" ESC ( B "ipt" is "script" in ISO-2022-JP): what is scanned here would not be
    # what a browser runs (security review, 2026-11-14).
    for quote in "\"'":
        declaration = f"<?xml version={quote}1.0{quote} encoding = {quote}{encoding}{quote} ?>"
        svg = f'{declaration}<svg xmlns="{SVG_NS}"><rect width="1" height="1"/></svg>'
        result = validate(Upload.from_bytes(svg.encode(), "a.svg"), SVG_POLICY)
        assert result.codes == ("svg_active_content",)
        assert result.violations[0].details["found"] == ["unsupported encoding"]


def test_escape_sequences_do_not_hide_markup() -> None:
    hidden = (
        b'<?xml version="1.0" encoding="ISO-2022-JP"?>'
        b'<svg xmlns="http://www.w3.org/2000/svg"><scr\x1b(Bipt>alert(1)</scr\x1b(Bipt></svg>'
    )
    assert codes(hidden, "a.svg", SVG_POLICY) == ("svg_active_content",)


@pytest.mark.parametrize(
    "encoding", ["UTF-8", "utf-8", "US-ASCII", "ISO-8859-1", "iso-8859-15", "windows-1252"]
)
def test_svg_in_encodings_that_leave_ascii_alone_is_read(encoding: str) -> None:
    prolog = f'<?xml version="1.0" encoding="{encoding}"?>'
    benign = f'{prolog}<svg xmlns="{SVG_NS}"><rect width="1" height="1"/></svg>'
    assert codes(benign.encode("latin-1"), "a.svg", SVG_POLICY) == ()
    active = f'{prolog}<svg xmlns="{SVG_NS}" onload="alert(1)"/>'
    assert codes(active.encode("latin-1"), "a.svg", SVG_POLICY) == ("svg_active_content",)


def test_utf16_svg_is_read() -> None:
    prolog = '<?xml version="1.0" encoding="UTF-16"?>'
    benign = f'{prolog}<svg xmlns="{SVG_NS}"><rect width="1" height="1"/></svg>'.encode("utf-16")
    assert codes(benign, "a.svg", SVG_POLICY) == ()
    active = f'{prolog}<svg xmlns="{SVG_NS}" onload="alert(1)"/>'.encode("utf-16")
    assert codes(active, "a.svg", SVG_POLICY) == ("svg_active_content",)
