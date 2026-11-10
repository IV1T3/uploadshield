"""Generate the SVG diagrams used by README.md and docs/ARCHITECTURE.md.

Run ``uv run python docs/images/diagrams.py`` after changing a diagram.  Each SVG is
self-contained, follows the reader's light or dark colour scheme, and uses one visual
language: grey for frameworks and your code, blue for uploadshield, green for what is
delivered, red for refusals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from xml.sax.saxutils import escape

OUT = Path(__file__).parent

STYLE = """
svg { --bg:#ffffff; --fg:#1f2328; --muted:#59636e; --line:#818b98; --panel:#f6f8fa;
  --panel-edge:#d1d9e0; --accent:#0969da; --accent-soft:#ddf4ff; --accent-edge:#54aeff;
  --ok:#1a7f37; --ok-soft:#dafbe1; --bad:#cf222e; --bad-soft:#ffebe9; --note:#fff8c5;
  --note-edge:#d4a72c; }
@media (prefers-color-scheme: dark) {
  svg { --bg:#0d1117; --fg:#e6edf3; --muted:#9198a1; --line:#7d8590; --panel:#151b23;
    --panel-edge:#3d444d; --accent:#4493f8; --accent-soft:#0d2240; --accent-edge:#1f6feb;
    --ok:#3fb950; --ok-soft:#0f2a1a; --bad:#f85149; --bad-soft:#2d1316; --note:#2b2410;
    --note-edge:#9e6a03; }
}
text { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica,
  Arial, sans-serif; fill: var(--fg); }
.card { fill: var(--bg); stroke: var(--panel-edge); }
.title { font-size: 14px; font-weight: 600; }
.label { font-size: 13px; }
.small { font-size: 12px; fill: var(--muted); }
.lane { font-size: 11px; font-weight: 600; letter-spacing: .08em; fill: var(--muted); }
.mono { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: 12px; }
.panel { fill: var(--panel); stroke: var(--panel-edge); }
.shield { fill: var(--accent-soft); stroke: var(--accent-edge); }
.shield-title { fill: var(--accent); font-size: 14px; font-weight: 600; }
.step { fill: var(--bg); stroke: var(--accent-edge); }
.num { fill: var(--accent); }
.num-text { fill: var(--bg); font-size: 11px; font-weight: 700; }
.ok-box { fill: var(--ok-soft); stroke: var(--ok); }
.bad-box { fill: var(--bad-soft); stroke: var(--bad); }
.note { fill: var(--note); stroke: var(--note-edge); }
.wire { fill: none; stroke: var(--line); stroke-width: 1.5; }
.wire-accent { fill: none; stroke: var(--accent); stroke-width: 1.5; }
.wire-ok { fill: none; stroke: var(--ok); stroke-width: 1.75; }
.wire-bad { fill: none; stroke: var(--bad); stroke-width: 1.5; stroke-dasharray: 5 4; }
.wire-return { fill: none; stroke: var(--line); stroke-width: 1.5; stroke-dasharray: 4 3; }
.boundary { fill: none; stroke: var(--muted); stroke-width: 1; stroke-dasharray: 2 4; }
.lifeline { fill: none; stroke: var(--panel-edge); stroke-width: 1.5; stroke-dasharray: 3 4; }
.activation { fill: var(--accent-soft); stroke: var(--accent-edge); }
.head-line { fill: var(--line); }
.head-accent { fill: var(--accent); }
.head-ok { fill: var(--ok); }
.head-bad { fill: var(--bad); }
.halo { paint-order: stroke; stroke: var(--bg); stroke-width: 5px; stroke-linejoin: round; }
.ok-text { fill: var(--ok); }
.bad-text { fill: var(--bad); }
"""

MARKERS = "".join(
    f'<marker id="arrow-{kind}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
    f'markerHeight="7" orient="auto-start-reverse"><path class="head-{kind}" '
    f'd="M0 0 L10 5 L0 10 z"/></marker>'
    for kind in ("line", "accent", "ok", "bad")
)
WIRE_HEAD = {"wire": "line", "wire-accent": "accent", "wire-ok": "ok", "wire-bad": "bad",
             "wire-return": "line"}  # fmt: skip


@dataclass
class Diagram:
    width: int
    height: int
    title: str
    description: str
    parts: list[str] = field(default_factory=list)

    # -- primitives ---------------------------------------------------------------------

    def text(
        self, x: float, y: float, value: str, cls: str = "label", anchor: str = "middle"
    ) -> None:
        self.parts.append(
            f'<text x="{x}" y="{y}" class="{cls}" text-anchor="{anchor}">{escape(value)}</text>'
        )

    def rect(self, x: float, y: float, w: float, h: float, cls: str, *, radius: float = 8) -> None:
        self.parts.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" class="{cls}"/>'
        )

    def wire(self, *points: tuple[float, float], cls: str = "wire", head: bool = True) -> None:
        path = " ".join(f"{'M' if i == 0 else 'L'}{x} {y}" for i, (x, y) in enumerate(points))
        marker = f' marker-end="url(#arrow-{WIRE_HEAD[cls]})"' if head else ""
        self.parts.append(f'<path d="{path}" class="{cls}"{marker}/>')

    # -- composites ---------------------------------------------------------------------

    def box(  # noqa: PLR0917 - x, y, w, h read best positionally
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        title: str | tuple[str, ...],
        lines: tuple[str, ...] = (),
        cls: str = "panel",
        title_cls: str = "title",
        line_cls: str = "small",
    ) -> None:
        """A rounded box with a (possibly multi-line) title and smaller lines below."""
        self.rect(x, y, w, h, cls)
        titles = (title,) if isinstance(title, str) else title
        rows = [(t, title_cls) for t in titles] + [(line, line_cls) for line in lines]
        top = y + h / 2 - (len(rows) - 1) * 9 + 5
        for i, (value, cls_) in enumerate(rows):
            self.text(x + w / 2, top + i * 18, value, cls_)

    def note(self, x: float, y: float, w: float, lines: tuple[str, ...], cls: str = "note") -> None:
        h = 12 + 17 * len(lines)
        self.rect(x, y, w, h, cls, radius=6)
        for i, line in enumerate(lines):
            self.text(x + 10, y + 21 + i * 17, line, "small", anchor="start")

    def message(
        self, x1: float, x2: float, y: float, label: str, *, cls: str = "wire", mono: bool = True
    ) -> None:
        """A horizontal sequence-diagram message with its label above the line."""
        self.wire((x1, y), (x2 - 2 if x2 > x1 else x2 + 2, y), cls=cls)
        text_cls = ("mono" if mono else "label") + " halo"
        if cls == "wire-ok":
            text_cls += " ok-text"
        elif cls == "wire-bad":
            text_cls += " bad-text"
        self.text((x1 + x2) / 2, y - 7, label, text_cls)

    def participant(
        self, x: float, y: float, w: float, title: str, sub: str, *, shield: bool = False
    ) -> None:
        cls, title_cls = ("shield", "shield-title") if shield else ("panel", "title")
        self.box(x - w / 2, y, w, 52, title, (sub,), cls=cls, title_cls=title_cls)

    def render(self) -> str:
        body = "\n  ".join(self.parts)
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.width} {self.height}" '
            f'width="{self.width}" height="{self.height}" role="img" aria-labelledby="t d">\n'
            f'  <title id="t">{escape(self.title)}</title>\n'
            f'  <desc id="d">{escape(self.description)}</desc>\n'
            f"  <style>{STYLE}</style>\n  <defs>{MARKERS}</defs>\n"
            f'  <rect x="0.5" y="0.5" width="{self.width - 1}" height="{self.height - 1}" rx="12" '
            f'class="card"/>\n  {body}\n</svg>\n'
        )


# --------------------------------------------------------------------------- #
# README: where uploadshield sits in an upload
# --------------------------------------------------------------------------- #


def upload_flow() -> Diagram:
    d = Diagram(
        900,
        372,
        "How uploadshield fits into an upload",
        "A client sends a file; the framework parses the request and hands every file to "
        "uploadshield, which checks size, name, type from the bytes, the allow-list and the "
        "content, then sanitizes it. Passing files reach your view with the detected content "
        "type and are re-checked on save; refused files never reach your code, and the client "
        "gets a 400, 413 or 415 response.",
    )
    for x, label in ((75, "UNTRUSTED"), (280, "YOUR FRAMEWORK"), (555, "UPLOADSHIELD"),
                     (825, "YOUR APPLICATION")):  # fmt: skip
        d.text(x, 30, label, "lane")
    # client and framework
    d.box(15, 48, 120, 124, "Client", ("file bytes", "filename", "Content-Type"))
    d.box(210, 48, 140, 124, ("Django, Flask", "or FastAPI"), ("parse the", "multipart body"))
    d.wire((135, 110), (208, 110))
    d.text(172, 102, "upload", "small halo")
    # uploadshield and its pipeline
    d.rect(420, 48, 270, 284, "shield", radius=12)
    d.text(555, 74, "every file, in this order", "small")
    steps = (
        "Size limit",
        "Filename, as sent and decoded",
        "Type from the bytes",
        "Allow-list; name fits type",
        "Content: macros, scripts, bombs",
        "Sanitize: re-encode, rename",
    )
    d.wire((440, 104), (440, 300), cls="wire-accent", head=False)
    for i, step in enumerate(steps):
        y = 88 + i * 38
        d.rect(452, y, 222, 30, "step", radius=6)
        d.parts.append(f'<circle cx="440" cy="{y + 15}" r="10" class="num"/>')
        d.text(440, y + 19, str(i + 1), "num-text")
        d.text(464, y + 20, step, "label", anchor="start")
    d.wire((350, 110), (418, 110))
    d.text(384, 102, "each file", "small halo")
    # delivered
    d.box(760, 48, 130, 124, "Your view", ("sanitized file,", "detected type"), cls="ok-box")
    d.wire((690, 110), (758, 110), cls="wire-ok")
    d.text(724, 102, "passes", "small ok-text halo")
    d.box(760, 220, 130, 92, "Storage", ("re-checked on", "save (Django)"))
    d.wire((825, 172), (825, 218))
    d.text(833, 199, "save()", "mono", anchor="start")
    # refused
    d.box(210, 220, 140, 92, "Refused", ("413 · 415 · 400", "logged, signalled"), cls="bad-box")
    d.wire((420, 266), (352, 266), cls="wire-bad")
    d.text(386, 258, "fails", "small bad-text halo")
    d.wire((210, 266), (75, 266), (75, 174), cls="wire-bad")
    d.text(142, 258, "JSON or HTML", "small bad-text halo")
    return d


# --------------------------------------------------------------------------- #
# ARCHITECTURE: one engine, three adapters
# --------------------------------------------------------------------------- #


def architecture() -> Diagram:
    d = Diagram(
        900,
        530,
        "uploadshield's layers",
        "Applications built with Django, Flask or FastAPI use the matching adapter. Each "
        "adapter imports only its own framework, turns the framework's file into an Upload "
        "and calls the engine, which imports no web framework. validate() runs the policy's "
        "checks and sanitizers, cheapest first, on top of the core, and returns a "
        "ValidationResult that the adapter turns into a delivered file or the framework's "
        "own error.",
    )
    columns = (235, 490, 745)
    for y, label in ((57, "YOUR APP"), (158, "ADAPTERS"), (389, "ENGINE"), (482, "CORE")):
        d.text(22, y, label, "lane", anchor="start")
    apps = ("Django project", "Flask app", "FastAPI app")
    adapters = (
        ("uploadshield.django", "upload handler · decorators", "fields · storage · handler400"),
        ("uploadshield.flask", "extension · decorators", "WTForms validator"),
        ("uploadshield.fastapi", "file() · files()", "all_files() safety net"),
    )
    for x, app, (name, line1, line2) in zip(columns, apps, adapters, strict=True):
        d.box(x - 110, 30, 220, 44, app)
        d.wire((x, 74), (x, 110))
        d.text(x + 8, 97, "hooks in", "small", anchor="start")
        d.box(x - 110, 112, 220, 82, name, (line1, line2), cls="shield",
              title_cls="shield-title mono")  # fmt: skip
        d.wire((x - 50, 194), (x - 50, 222), head=False)
        d.wire((x + 50, 232), (x + 50, 197), cls="wire-return")
    # every adapter calls the same engine and gets the same result type back
    d.wire((185, 222), (695, 222), head=False)
    d.wire((285, 232), (795, 232), cls="wire-return", head=False)
    d.wire((410, 222), (410, 356))
    d.text(402, 286, "Upload", "mono", anchor="end")
    d.text(402, 302, "stream, name, size,", "small", anchor="end")
    d.text(402, 317, "declared type", "small", anchor="end")
    d.wire((570, 356), (570, 234), cls="wire-return")
    d.text(578, 286, "ValidationResult", "mono", anchor="start")
    d.text(578, 302, "codes, messages, details,", "small", anchor="start")
    d.text(578, 317, "sanitized file", "small", anchor="start")
    d.wire((120, 254), (888, 254), cls="boundary", head=False)
    d.text(490, 270, "no web framework below this line", "small halo")
    # engine
    d.rect(120, 342, 768, 92, "panel", radius=10)
    d.box(136, 358, 210, 60, "Policy", ("allow-list, checks,", "sanitizers"), cls="step")
    d.box(385, 358, 210, 60, "validate()", ("cheapest first,", "fails closed"), cls="step",
          title_cls="title mono")  # fmt: skip
    d.box(634, 358, 238, 60, "checks · sanitizers", ("archives, Office, XML, PDF,", "SVG, images"),
          cls="step", title_cls="title mono")  # fmt: skip
    d.wire((346, 388), (383, 388))
    d.text(364, 380, "in", "small halo")
    d.wire((595, 388), (632, 388))
    d.text(614, 380, "runs", "small halo")
    # core
    d.rect(120, 454, 768, 58, "panel", radius=10)
    d.text(136, 478, "uploadshield.core", "mono", anchor="start")
    d.text(136, 498, "sniffing · file types · InspectedFile (cached facts) · ZIP access · "
           "stable codes", "small", anchor="start")  # fmt: skip
    d.wire((490, 434), (490, 452))
    return d


# --------------------------------------------------------------------------- #
# Integrations: one sequence diagram per framework
# --------------------------------------------------------------------------- #


def lifelines(d: Diagram, xs: tuple[float, ...], top: float, bottom: float) -> None:
    for x in xs:
        d.wire((x, top), (x, bottom), cls="lifeline", head=False)


def django() -> Diagram:
    d = Diagram(
        900,
        600,
        "Django: uploads are validated while the body streams in",
        "When the CSRF check or the view first reads request.POST or request.FILES, Django's "
        "multipart parser streams the body through ValidatingUploadHandler. The name is "
        "checked before any byte is stored, size limits and the type allow-list as data "
        "arrives, and the full policy once a file is complete; the view receives the sanitized "
        "file. A refusal raises UploadRejected, which handler400 answers with 400, 413 or 415.",
    )
    xs = (80, 260, 470, 665, 830)
    d.participant(xs[0], 20, 120, "Client", "browser / API")
    d.participant(xs[1], 20, 170, "Django parser", "MultiPartParser")
    d.participant(xs[2], 20, 210, "ValidatingUploadHandler", "the view's policy", shield=True)
    d.participant(xs[3], 20, 150, "Storage handlers", "memory or temp file")
    d.participant(xs[4], 20, 130, "Your view", "or CSRF middleware")
    lifelines(d, xs, 72, 580)
    d.rect(xs[2] - 7, 160, 14, 306, "activation", radius=3)
    d.message(xs[4], xs[1], 102, "reads request.POST / FILES")
    d.message(xs[0], xs[1], 138, "multipart body, in chunks", mono=False)
    d.message(xs[1], xs[2], 172, "new_file(name, …)")
    d.note(xs[2] + 14, 184, 262, ("name checked first: a refused name",
                                  "means nothing is ever stored"))  # fmt: skip
    d.message(xs[1], xs[2], 254, "receive_data_chunk(chunk)")
    d.note(xs[2] + 14, 266, 262, ("size limits on every chunk;",
                                  "type allow-list after the first 8 KiB"))  # fmt: skip
    d.message(xs[2], xs[3], 336, "chunk, if still allowed")
    d.message(xs[1], xs[2], 376, "file_complete()")
    d.note(xs[2] + 14, 388, 262, ("full policy: macros, bombs, …",
                                  "then sanitize (re-encode, rename)"))  # fmt: skip
    d.message(xs[2], xs[1], 456, "sanitized file", cls="wire-return")
    d.message(xs[1], xs[4], 496, "request.FILES: sanitized, detected types", cls="wire-ok")
    d.message(xs[2], xs[0], 546, "refused: UploadRejected → handler400 → 400/413/415",
              cls="wire-bad")  # fmt: skip
    return d


def flask() -> Diagram:
    d = Diagram(
        900,
        500,
        "Flask: uploads are validated before the view runs",
        "UploadShield registers a before_request hook. It reads request.files, so Werkzeug "
        "parses the whole body first, capped by MAX_CONTENT_LENGTH. The hook picks the view's "
        "policy, validates and sanitizes every file and replaces request.files, so the view "
        "receives sanitized files. A refusal raises UploadRejected, a Werkzeug HTTP error "
        "answered with 400, 413 or 415.",
    )
    xs = (80, 290, 545, 800)
    d.participant(xs[0], 20, 120, "Client", "browser / API")
    d.participant(xs[1], 20, 190, "Flask / Werkzeug", "request parsing")
    d.participant(xs[2], 20, 230, "UploadShield", "before_request hook", shield=True)
    d.participant(xs[3], 20, 150, "Your view", "@validate_uploads(…)")
    lifelines(d, xs, 72, 480)
    d.rect(xs[2] - 7, 130, 14, 250, "activation", radius=3)
    d.message(xs[0], xs[1], 104, "multipart body", mono=False)
    d.message(xs[1], xs[2], 140, "before_request")
    d.message(xs[2], xs[1], 176, "request.files")
    d.note(xs[1] - 95, 188, 190, ("parses the whole body;", "MAX_CONTENT_LENGTH → 413"))
    d.message(xs[1], xs[2], 256, "FileStorage objects", cls="wire-return")
    d.note(xs[2] + 14, 268, 230, ("policy: @validate_uploads,", "ENDPOINT_POLICIES, default;",
                                  "validate and sanitize"))  # fmt: skip
    d.message(xs[2], xs[3], 380, "sanitized request.files", cls="wire-ok")
    d.message(xs[2], xs[0], 436, "refused: UploadRejected (HTTPException) → 400 / 413 / 415",
              cls="wire-bad")  # fmt: skip
    return d


def fastapi() -> Diagram:
    d = Diagram(
        900,
        520,
        "FastAPI: uploads are validated by dependencies",
        "Starlette parses the form. The optional app or router dependency all_files() checks "
        "every file field that has no dependency of its own and sets the detected content type. "
        "An endpoint dependency shield.file(policy) validates its field in the thread pool "
        "and sanitizes the UploadFile in place. A refusal is an HTTPException with status "
        "400, 413 or 415.",
    )
    xs = (70, 230, 420, 620, 815)
    d.participant(xs[0], 20, 110, "Client", "browser / API")
    d.participant(xs[1], 20, 160, "FastAPI", "Starlette form parser")
    d.participant(xs[2], 20, 190, "all_files()", "app / router safety net", shield=True)
    d.participant(xs[3], 20, 190, "shield.file(policy)", "endpoint dependency", shield=True)
    d.participant(xs[4], 20, 130, "Your endpoint", "async or sync")
    lifelines(d, xs, 72, 500)
    d.rect(xs[2] - 7, 142, 14, 112, "activation", radius=3)
    d.rect(xs[3] - 7, 296, 14, 116, "activation", radius=3)
    d.message(xs[0], xs[1], 104, "multipart body", mono=False)
    d.message(xs[1], xs[2], 140, "the parsed form")
    d.note(xs[2] + 14, 152, 176, ("fields without their own", "dependency: validate in",
                                  "the thread pool; set the", "detected content type"))  # fmt: skip
    d.message(xs[1], xs[3], 294, "its UploadFile")
    d.note(xs[3] + 14, 306, 176, ("this field's policy:", "validate in the thread",
                                  "pool, then sanitize"))  # fmt: skip
    d.message(xs[3], xs[4], 412, "sanitized UploadFile", cls="wire-ok")
    d.message(xs[3], xs[0], 462, "refused by either: HTTPException → 400 / 413 / 415",
              cls="wire-bad")  # fmt: skip
    return d


DIAGRAMS = {
    "upload-flow.svg": upload_flow,
    "architecture.svg": architecture,
    "django.svg": django,
    "flask.svg": flask,
    "fastapi.svg": fastapi,
}

if __name__ == "__main__":
    for name, build in DIAGRAMS.items():
        (OUT / name).write_text(build().render())
        print(f"wrote {OUT / name}")
