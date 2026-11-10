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


def test_text_scanning_options() -> None:
    php = b"notes\n<?php system($_GET[0]); ?>"
    off = presets.DOCUMENTS.replace(content_checks=(EmbeddedContent(scan_text=False),))
    assert codes(php, "a.txt", off) == ()
    capped = presets.DOCUMENTS.replace(content_checks=(EmbeddedContent(max_scan_bytes=10),))
    assert codes(php, "a.txt", capped) == ("check_failed",)  # never "scanned in part"
