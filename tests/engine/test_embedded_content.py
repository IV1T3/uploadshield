"""EmbeddedContent: code hidden in media files, and polyglots."""

from __future__ import annotations

import pytest

from tests.support import corpus
from tests.support.engine import codes
from uploadshield import presets
from uploadshield.checks import (
    EmbeddedContent,
)


def test_php_hidden_in_image_metadata_is_refused() -> None:
    jpeg = corpus.image("JPEG", comment=b"<?php system($_GET['c']); ?>")
    assert codes(jpeg, "a.jpg") == ("embedded_code",)
    assert codes(corpus.png() + b"<script>alert(1)</script>", "a.png") == ("embedded_code",)


def test_polyglots_are_refused() -> None:
    gifar = corpus.image("GIF") + corpus.build_zip({"Exploit.class": b"\xca\xfe\xba\xbe"})
    assert codes(gifar, "a.gif") == ("polyglot",)
    jpeg_pdf = corpus.image("JPEG", comment=b"%PDF-1.4 hidden")
    assert codes(jpeg_pdf, "a.jpg") == ("polyglot",)


def test_random_zip_signature_bytes_are_not_a_polyglot() -> None:
    # Four magic bytes alone (which occur by chance in compressed media) are not enough:
    # a polyglot needs a structurally valid end record pointing at a central directory.
    only_embedded = presets.IMAGES.replace(content_checks=(EmbeddedContent(),))
    assert codes(corpus.png() + b"PK\x05\x06" + b"\x00" * 30, "a.png", only_embedded) == ()


# --------------------------------------------------------------------------- #
# media
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("data", "name"),
    [
        (corpus.mp3(), "a.mp3"),
        (corpus.mp4(), "a.mp4"),
        (corpus.wav(), "a.wav"),
        (corpus.webm(), "a.webm"),
    ],
)
def test_media_files(data: bytes, name: str) -> None:
    assert codes(data, name) == ()


def test_media_with_embedded_php_is_refused() -> None:
    assert codes(corpus.mp3() + b"<?php phpinfo(); ?>", "a.mp3") == ("embedded_code",)


@pytest.mark.owasp("ufu.example.included-tags")
@pytest.mark.parametrize(
    ("data", "name"),
    [
        (b"Meeting notes\n<?php system($_GET[0]); ?>", "notes.txt"),
        (b"name,amount\nx,<?php system($_GET[0]); ?>\n", "data.csv"),
        (b"line one\n<?= `id` ?>\n", "notes.txt"),
        (b"a" * 3_000_000 + b"<?PHP\nsystem('id');", "big.txt"),
        # Short open tag `<?` followed by code: found accepted by the adversarial
        # evaluation (2026-11-10). Flagged only when code follows, not after prose.
        (b"<? system($_GET['c']); ?>\n", "notes.txt"),
        (b"notes\n<?\nshell_exec($_GET[0]);\n", "notes.txt"),
        (b"name,amount\nx,<?\t`id`;\n", "data.csv"),
        # No space after `<?`, a bare keyword, a comment first, or a variable: all PHP,
        # all flagged after the security-review follow-up (2026-11-10).
        (b"<?system($_GET[0]);\n", "notes.txt"),
        (b"<?echo $_GET[0];\n", "notes.txt"),
        (b"<?include($_GET[0]);\n", "data.csv"),
        (b"<?$x=`id`;\n", "notes.txt"),
        (b"<?/* hi */system($_GET[0]);\n", "notes.txt"),
        (b"<?@eval($_GET[0]);\n", "notes.txt"),
        # Padding the space between a call and its "(" must not evade (second review round).
        (b"notes\n<?= system" + b" " * 20 + b"($_GET[0]);\n", "notes.txt"),
        # Namespaced and static calls after a short tag (fourth review round).
        (b"notes\n<?\\system($_GET[0]);\n", "notes.txt"),
        (b"notes\n<?Shell::run($_GET[0]);\n", "notes.txt"),
    ],
)
def test_php_tags_in_text_files_are_refused(data: bytes, name: str) -> None:
    # PHP's include() runs them from any file, whatever its extension.
    assert codes(data, name, presets.DOCUMENTS) == ("embedded_code",)


@pytest.mark.parametrize(
    "text",
    [
        b'Notes on XML: a <?xml version="1.0"?> declaration goes first.\n',
        b"if a <? b then c\nphp is a language, <?phpinfo is not a tag\n",
        b"Today we discussed the <script> tag and <?= in templates.\n",
        # The short-tag rule needs code to follow, so prose with a lone "<?" is fine.
        b"a ternary in C++: cond a <? b : c, and a <? d later\n",
        b"the <? token on its own, then prose, is not a tag here\n",
        b"compare with a <? b and later x <? y inside running text\n",
    ],
)
def test_ordinary_text_passes(text: bytes) -> None:
    assert codes(text, "notes.txt", presets.DOCUMENTS) == ()


# --------------------------------------------------------------------------- #
# Security review, 2026-11-14: the echo tag "<?=" is always enabled in PHP
# --------------------------------------------------------------------------- #

ECHO_TAGS = [
    b"<?=(system($_GET[0]))?>",  # the expression opens with a bracket,
    b"<?=@system($_GET[0])?>",  # an error-control operator,
    b"<?=!system($_GET[0])?>",
    b"<?= ( ( @ system($_GET[0]) ) ) ?>",
    b"<?=''.system($_GET[0])?>",  # a string,
    b'<?="".system($_GET[0])?>',
    b"<?=1?system($_GET[0]):0?>",  # a number,
    b"<?=[system($_GET[0])][0]?>",  # an array,
    b"<?=PHP_EOL.system($_GET[0])?>",  # a constant,
    b"<?=include$_GET[0]?>",
    b"<?=require_once $_GET[0]?>",
]


@pytest.mark.parametrize("tag", ECHO_TAGS)
def test_echo_tags_are_refused_whatever_the_expression_starts_with(tag: bytes) -> None:
    assert codes(b"Meeting notes\n" + tag + b"\n", "notes.txt", presets.DOCUMENTS) == (
        "embedded_code",
    )
    assert codes(b"name,amount\nx," + tag + b"\n", "data.csv", presets.DOCUMENTS) == (
        "embedded_code",
    )
    assert codes(corpus.image("JPEG", comment=tag), "a.jpg") == ("embedded_code",)
    assert codes(corpus.mp3() + tag, "a.mp3") == ("embedded_code",)


@pytest.mark.parametrize(
    "text",
    [
        b"notes\n<?=''\n.\nsystem($_GET[0]);\n",  # never closed, spread over lines
        b"notes\n<?=PHP_EOL or system($_GET[0]);\n",
        b"notes\n<?= /* " + b"x" * 150 + b" */ system($_GET[0]);\n",  # behind padding
        b"notes\n<?=<?=`id`;\n",  # a second tag is judged like the first
    ],
)
def test_echo_tags_in_text_are_refused_when_code_follows_nearby(text: bytes) -> None:
    assert codes(text, "notes.txt", presets.DOCUMENTS) == ("embedded_code",)


@pytest.mark.parametrize(
    "statement",
    [
        b"<?;system($_GET[0]);",  # an empty statement,
        b"<?{system($_GET[0]);}",  # a block,
        b"<?#\nsystem($_GET[0]);",  # a comment,
        b"<?//x\nsystem($_GET[0]);",
        b"<?'';system($_GET[0]);",  # a string,
        b"<?1;system($_GET[0]);",  # a number,
        b"<?[system($_GET[0])];",
        b"<?!system($_GET[0]);",
        b"<?-system($_GET[0]);",
        b"<?PHP_EOL;system($_GET[0]);",  # a constant as a statement
        b"<? \t\n true ;system($_GET[0]);",
    ],
)
def test_short_tags_are_refused_when_a_statement_follows(statement: bytes) -> None:
    assert codes(b"notes\n" + statement + b"\n", "notes.txt", presets.DOCUMENTS) == (
        "embedded_code",
    )


@pytest.mark.parametrize(
    "text",
    [
        b"Templates use <?= to print and <? to open a block.\n",
        b"the <?= tag and the <? tag.\n",
        b"is a <? b? no: a <?= b.\n",
        b'XML has these: <?mso-application progid="Word.Document"?> and <?xml-stylesheet?>\n',
        b'metadata: <?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>\n',
        b"x <?> y and x <?? y\n",
        # Only what can start a PHP statement counts after "<?": Vim's manual documents
        # its "<?" operator as "*expr-<?*" (refused for a while during the 2026-11-14 fix).
        b"smaller than, ignoring case: *expr-<?*  *expr-<=?*\n",
        b"operators: <?* <?. <?% <?^ <?| <?& <?, <?: <?) <?> <?=\n",
    ],
)
def test_text_that_only_mentions_the_tags_passes(text: bytes) -> None:
    assert codes(text, "notes.txt", presets.DOCUMENTS) == ()


@pytest.mark.parametrize(
    "unit",
    [
        b"<?=", b"<?= ", b"<?=" + b"a" * 201, b"<?=" + b"a" * 199 + b"<", b"<?",
        b"<? ", b"<?" + b" " * 40 + b"word ", b"<?" + b"a" * 31 + b" " * 40 + b"x ",
        b"<?=" + b"(" * 41, b"<?=" + b"a" * 31 + b" " * 41, b"<", b"?>",
    ],
)  # fmt: skip
def test_tags_are_scanned_in_linear_time(unit: bytes) -> None:
    import time

    flood = unit * (2_000_000 // len(unit))
    started = time.perf_counter()
    codes(b"notes\n" + flood, "notes.txt", presets.DOCUMENTS)
    codes(corpus.mp3() + flood, "a.mp3")
    assert time.perf_counter() - started < 3


def test_a_tag_cut_by_a_chunk_boundary_is_found() -> None:
    # Files are scanned in pieces of 1 MiB with an overlap as long as the longest tag.
    tag = b"<?=" + b" " * 180 + b"`id`"
    for lead in range(1024 * 1024 - len(tag) - 2, 1024 * 1024 + 2, 7):
        text = b"x" * lead + tag + b"\n"
        assert codes(text, "notes.txt", presets.DOCUMENTS) == ("embedded_code",), lead


def test_text_scanning_options() -> None:
    php = b"notes\n<?php system($_GET[0]); ?>"
    off = presets.DOCUMENTS.replace(content_checks=(EmbeddedContent(scan_text=False),))
    assert codes(php, "a.txt", off) == ()
    capped = presets.DOCUMENTS.replace(content_checks=(EmbeddedContent(max_scan_bytes=10),))
    assert codes(php, "a.txt", capped) == ("check_failed",)  # never "scanned in part"
