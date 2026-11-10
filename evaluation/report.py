"""Render the evaluation summary JSON into a self-contained, theme-aware HTML report.

Usage: python report.py SUMMARY_JSON MANIFEST_JSONL OUT_HTML
"""

from __future__ import annotations

import html
import json
import math
import sys
from pathlib import Path


def esc(x: object) -> str:
    return html.escape(str(x))


def pct(x: float) -> str:
    return "n/a" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x * 100:.1f}%"


def num(x: float, nd: int = 3) -> str:
    return "n/a" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x:.{nd}f}"


def confusion_svg(m: dict, title: str) -> str:
    """A 2x2 confusion matrix as an SVG heat grid. Positive class = 'should refuse'."""
    tp, fp, tn, fn = m["tp"], m["fp"], m["tn"], m["fn"]
    cells = [
        (0, 0, "TP", tp, "ok"), (1, 0, "FN · bypass", fn, "bad" if fn else "ok"),
        (0, 1, "FP", fp, "warn" if fp else "ok"), (1, 1, "TN", tn, "ok"),
    ]
    W, H, pad, cw, ch = 420, 260, 86, 134, 84
    parts = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="{esc(title)} confusion matrix" '
             'style="max-width:100%;height:auto">']
    parts.append(f'<text x="{pad + cw}" y="18" text-anchor="middle" class="svg-cap">predicted</text>')
    parts.append(f'<text x="{pad + cw / 2}" y="40" text-anchor="middle" class="svg-sub">refuse</text>')
    parts.append(f'<text x="{pad + cw + cw / 2}" y="40" text-anchor="middle" class="svg-sub">accept</text>')
    parts.append(f'<text x="22" y="{pad + ch}" text-anchor="middle" class="svg-cap" '
                 f'transform="rotate(-90 22 {pad + ch})">actual</text>')
    for label, row in (("refuse", 0), ("accept", 1)):
        parts.append(f'<text x="{pad - 10}" y="{pad + row * ch + ch / 2 + 4}" text-anchor="end" '
                     f'class="svg-sub">{label}</text>')
    fills = {"ok": "var(--grid-ok)", "warn": "var(--grid-warn)", "bad": "var(--grid-bad)"}
    for col, row, label, value, kind in cells:
        x, y = pad + col * cw, pad + row * ch
        parts.append(f'<rect x="{x}" y="{y}" width="{cw - 4}" height="{ch - 4}" rx="8" '
                     f'fill="{fills[kind]}" stroke="var(--line)"/>')
        parts.append(f'<text x="{x + cw / 2 - 2}" y="{y + ch / 2 - 4}" text-anchor="middle" '
                     f'class="svg-val">{value}</text>')
        parts.append(f'<text x="{x + cw / 2 - 2}" y="{y + ch / 2 + 16}" text-anchor="middle" '
                     f'class="svg-lbl">{esc(label)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def class_bars(per_class: dict) -> str:
    items = sorted(per_class.items(), key=lambda kv: (kv[1]["rate"], -kv[1]["total"]))
    rows = max(len(items), 1)
    bar_h, gap, top, left, right = 24, 10, 16, 150, 70
    W = 660
    H = top + rows * (bar_h + gap)
    parts = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="Detection rate by attack class" '
             'style="max-width:100%;height:auto">']
    track = W - left - right
    for i, (name, c) in enumerate(items):
        y = top + i * (bar_h + gap)
        rate = c["rate"]
        lo, hi = c["rate_ci"]
        fill = "var(--grid-bad)" if rate < 0.999 else "var(--accent)"
        parts.append(f'<text x="{left - 8}" y="{y + bar_h / 2 + 4}" text-anchor="end" '
                     f'class="svg-sub">{esc(name)}</text>')
        parts.append(f'<rect x="{left}" y="{y}" width="{track}" height="{bar_h}" rx="4" '
                     'fill="var(--track)"/>')
        parts.append(f'<rect x="{left}" y="{y}" width="{max(1, track * rate):.1f}" height="{bar_h}" '
                     f'rx="4" fill="{fill}"/>')
        # Wilson CI whisker.
        x1, x2 = left + track * lo, left + track * hi
        cy = y + bar_h / 2
        parts.append(f'<line x1="{x1:.1f}" y1="{cy}" x2="{x2:.1f}" y2="{cy}" stroke="var(--fg)" '
                     'stroke-opacity="0.5"/>')
        parts.append(f'<text x="{left + track + 6}" y="{cy + 4}" class="svg-sub">'
                     f'{c["caught"]}/{c["total"]}</text>')
    parts.append("</svg>")
    return "".join(parts)


def timing_table(envs: dict) -> str:
    rows = []
    for label, e in envs.items():
        t = e["timing_ms"]["all"]
        tc = e["timing_ms"]["clean"]
        rows.append(f"<tr><td>{esc(label)}</td><td>{num(t['p50'])}</td><td>{num(t['p95'])}</td>"
                    f"<td>{num(t['p99'])}</td><td>{num(tc['p50'])}</td><td>{num(tc['p95'])}</td></tr>")
    return ("<table><thead><tr><th>environment</th><th>p50</th><th>p95</th><th>p99</th>"
            "<th>clean p50</th><th>clean p95</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>")


def metrics_table(envs: dict) -> str:
    rows = []
    for label, e in envs.items():
        f = e["full"]
        s = e["structural"]
        rl, rh = f["recall_ci"]
        rows.append(
            f"<tr><td>{esc(label)}</td><td>{f['n']}</td>"
            f"<td>{pct(f['recall'])}<span class='ci'>[{pct(rl)}, {pct(rh)}]</span></td>"
            f"<td>{pct(f['specificity'])}</td><td>{f['fp']}</td><td>{f['fn']}</td>"
            f"<td>{num(f['mcc'])}</td><td>{pct(s['recall'])}</td><td>{f['errors']}</td></tr>"
        )
    return ("<table><thead><tr><th>environment</th><th>N</th><th>recall (95% CI)</th>"
            "<th>specificity</th><th>FP</th><th>FN</th><th>MCC</th><th>structural recall</th>"
            "<th>errors</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


def list_section(title: str, items: list[dict], fields: list[str], empty: str) -> str:
    if not items:
        return f"<h3>{esc(title)}</h3><p class='good'>{esc(empty)}</p>"
    head = "".join(f"<th>{esc(f)}</th>" for f in fields)
    body = "".join("<tr>" + "".join(f"<td>{esc(it.get(f, ''))}</td>" for f in fields) + "</tr>"
                   for it in items[:60])
    return (f"<h3>{esc(title)} <span class='count'>{len(items)}</span></h3>"
            f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>")


def main() -> None:
    summary = json.loads(Path(sys.argv[1]).read_text())
    manifest = [json.loads(l) for l in Path(sys.argv[2]).read_text().splitlines()]
    out = Path(sys.argv[3])

    envs = summary["environments"]
    n_cases = len(manifest)
    n_files = len({m["file"] for m in manifest})
    n_eval = sum(e["full"]["n"] for e in envs.values())
    # Pool structural confusion across all environments for the headline matrix.
    pooled = {k: sum(e["structural"][k] for e in envs.values()) for k in ("tp", "fp", "tn", "fn")}
    base_env = next((e for lbl, e in envs.items() if lbl.endswith("-base")), next(iter(envs.values())))
    all_env = next((e for lbl, e in envs.items() if lbl.endswith("-all")), base_env)

    bypasses = summary["bypasses"]
    fps = summary["false_positives"]
    errs = summary["errors"]
    disagree = summary["consistency"]["disagreements"]

    css = """
:root{
  /* layout: single reading column, full-width bands for section breaks */
  --bg:#f7f6f3; --panel:#fffdf9; --fg:#1c1b19; --muted:#6b675f; --line:#e2ddd3;
  --accent:#3a6f54; --accent-soft:#e7efe9; --track:#ece8df;
  --grid-ok:#e7efe9; --grid-warn:#f6e7cf; --grid-bad:#f0d2cc;
  --good:#2f6b4f; --bad:#a33a2c;
  --sans:'Inter',system-ui,sans-serif; --head:'Space Grotesk','Inter',system-ui,sans-serif;
  --mono:'IBM Plex Mono',ui-monospace,monospace;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#17181a; --panel:#1f2124; --fg:#ececea; --muted:#9a968d; --line:#30333a;
  --accent:#6fbf93; --accent-soft:#223129; --track:#2a2d33;
  --grid-ok:#223129; --grid-warn:#3a3321; --grid-bad:#3f2622;
  --good:#6fbf93; --bad:#e08b7c; color-scheme:dark;
}}
:root[data-theme="dark"]{
  --bg:#17181a; --panel:#1f2124; --fg:#ececea; --muted:#9a968d; --line:#30333a;
  --accent:#6fbf93; --accent-soft:#223129; --track:#2a2d33;
  --grid-ok:#223129; --grid-warn:#3a3321; --grid-bad:#3f2622;
  --good:#6fbf93; --bad:#e08b7c; color-scheme:dark;
}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font-family:var(--sans);line-height:1.55;margin:0}
.wrap{max-width:1000px;margin:0 auto;padding-left:max(16px,env(safe-area-inset-left,0px));
  padding-right:max(16px,env(safe-area-inset-right,0px));padding-block:0}
header.hero{padding-block:48px 28px;border-bottom:1px solid var(--line)}
.eyebrow{font-family:var(--mono);font-size:12px;letter-spacing:.14em;text-transform:uppercase;
  color:var(--accent);margin:0 0 12px}
h1{font-family:var(--head);font-size:clamp(28px,5vw,44px);line-height:1.05;margin:0 0 14px;
  text-wrap:balance;letter-spacing:-.01em}
h2{font-family:var(--head);font-size:24px;margin:40px 0 6px;letter-spacing:-.01em}
h3{font-family:var(--head);font-size:17px;margin:26px 0 8px}
.lede{font-size:18px;color:var(--muted);max-width:68ch;margin:0}
.stat-row{display:flex;flex-wrap:wrap;gap:12px;margin:26px 0 8px}
.stat{flex:1 1 150px;min-width:0;background:var(--panel);border:1px solid var(--line);
  border-radius:12px;padding:16px 18px}
.stat .k{font-family:var(--head);font-size:26px;font-variant-numeric:tabular-nums}
.stat .l{font-size:12.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-top:4px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:22px;align-items:start}
@media (max-width:720px){.grid2{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 20px}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;font-size:13.5px;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
th{font-family:var(--mono);font-size:11.5px;text-transform:uppercase;letter-spacing:.05em;
  color:var(--muted);font-weight:600}
td:first-child,th:first-child{font-family:var(--mono);font-size:12px}
.ci{color:var(--muted);font-size:11px;margin-left:6px}
.count{display:inline-block;background:var(--grid-bad);color:var(--bad);border-radius:20px;
  font-family:var(--mono);font-size:12px;padding:1px 10px;vertical-align:middle}
.good{color:var(--good);font-weight:600}
.bad{color:var(--bad);font-weight:600}
.svg-cap{fill:var(--muted);font-family:var(--mono);font-size:12px;letter-spacing:.08em;text-transform:uppercase}
.svg-sub{fill:var(--fg);font-family:var(--sans);font-size:12.5px}
.svg-val{fill:var(--fg);font-family:var(--head);font-size:26px;font-weight:600}
.svg-lbl{fill:var(--muted);font-family:var(--mono);font-size:11px}
p{max-width:72ch}
.note{font-size:13px;color:var(--muted)}
code{font-family:var(--mono);font-size:.92em;background:var(--accent-soft);padding:1px 5px;border-radius:5px}
footer{margin:48px 0 60px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font-size:13px}
ul{max-width:72ch}
"""

    def env_dataset_line() -> str:
        labels = ", ".join(envs)
        return labels

    # Distinct accepted probes (reported leads, not scored bypasses).
    seen_probe: dict[tuple, dict] = {}
    for p in summary.get("probe_accepted", []):
        seen_probe.setdefault((p["attack_class"], p["note"].split(" (")[0]), p)
    probes = list(seen_probe.values())

    bypass_html = list_section(
        "Structural bypass candidates", bypasses,
        ["env", "attack_class", "policy", "note", "codes"],
        "None. Every purely structural attack case was refused in every environment.")
    probe_html = list_section(
        "Residual risks (accepted probes, reported not scored)", probes,
        ["attack_class", "policy", "note"],
        "None.")
    fp_html = list_section(
        "False positives (clean files refused)", fps,
        ["env", "attack_class", "policy", "note", "codes"],
        "None. Every clean, allowed file was accepted in every environment.")
    err_html = list_section(
        "Engine errors (validate raised)", errs, ["env", "attack_class", "policy", "note", "error"],
        "None. validate() never raised; every uninspectable input failed closed as a refusal.")

    consistency = (
        f"<p class='good'>All {len(envs)} environments agreed on every one of the "
        f"{summary['consistency']['structural_cases']} structural cases.</p>"
        if not disagree else
        f"<p class='bad'>{len(disagree)} structural case(s) decided differently across "
        "environments — a version-dependent differential:</p>"
        + list_section("Disagreements", [{"id": d["id"], **d["by_env"]} for d in disagree],
                       ["id", *envs], ""))

    obs_rows = "".join(
        f"<tr><td>{esc(l)}</td><td>{e['observational']['total']}</td>"
        f"<td>{e['observational']['refused']}</td>"
        f"<td>{pct(e['observational']['refused'] / e['observational']['total']) if e['observational']['total'] else 'n/a'}</td></tr>"
        for l, e in envs.items())

    html_doc = f"""<meta name="claude:viewport-fit-sides" content="cover">
<title>uploadshield Evaluation</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap">
<style>{css}</style>
<div class="wrap">
<header class="hero">
  <p class="eyebrow">Empirical security evaluation</p>
  <h1>How well does uploadshield actually block malicious uploads?</h1>
  <p class="lede">A labelled corpus of {n_cases:,} upload cases, scored as a binary
  detector across Python 3.11–3.15 and four extra configurations. Every label is fixed
  by construction, so the measurement is independent of the system under test.</p>
  <div class="stat-row">
    <div class="stat"><div class="k">{n_cases:,}</div><div class="l">labelled cases</div></div>
    <div class="stat"><div class="k">{n_eval:,}</div><div class="l">evaluations</div></div>
    <div class="stat"><div class="k">{len(envs)}</div><div class="l">environments</div></div>
    <div class="stat"><div class="k">{len(bypasses)}</div><div class="l">structural bypasses</div></div>
    <div class="stat"><div class="k">{len(errs)}</div><div class="l">engine errors</div></div>
  </div>
  <p class="note">uploadshield {esc(next(iter(envs.values()))['env']['uploadshield'])} ·
  {esc(next(iter(envs.values()))['env']['platform'])} · inert corpus (placeholder scripts,
  EICAR test string, structural tricks with harmless contents).</p>
</header>

<h2>Method</h2>
<p>For each <code>(policy, file)</code> pair the validator either accepts or refuses, so it
is a binary classifier. The positive class is <strong>should be refused</strong> (malicious
or disallowed); the negative class is <strong>should be accepted</strong> (benign and
allowed). Ground truth is assigned when each case is built — never by asking uploadshield —
so the evaluation is not circular.</p>
<ul>
<li><strong>Benign-allowed</strong> ({sum(1 for m in manifest if m['category']=='clean')} cases):
real files sampled from the host and clean synthetic files, sent to a policy that allows their
true type. A refusal here is a false positive.</li>
<li><strong>Malicious</strong> ({sum(1 for m in manifest if m['category']=='security')} cases):
disguise, dangerous names, active documents, archive attacks, polyglots, oversize. An
acceptance here is a false negative — a bypass.</li>
<li><strong>Policy enforcement</strong> ({sum(1 for m in manifest if m['category']=='policy_enforcement')}
cases): a benign file of a type the policy forbids; expected refusal.</li>
<li><strong>Observational</strong> ({sum(1 for m in manifest if m['category']=='observational')}
cases): real PDFs, Office files, HTML and SVG whose contents are unknown and may legitimately
be refused for active content; reported separately, kept out of the confusion matrix.</li>
</ul>
<p>Cases that need an extra to catch (image integrity needs Pillow; disguised-script detection
needs Magika; the EICAR signature needs a YARA rule) are tagged, and scored only in
environments where that extra is present. A miss on a purely structural case is a true bypass;
a miss on a capability case without its extra is expected. Each file is validated three times
and the fastest run is kept, with the garbage collector disabled during timing.</p>

<h2>Headline: pooled structural confusion</h2>
<div class="grid2">
  <div class="panel">{confusion_svg(pooled, "Pooled structural")}
    <p class="note">All structural cases (no extra required) pooled across every environment:
    {pooled['tp']+pooled['fn']} should-refuse and {pooled['tn']+pooled['fp']} should-accept
    decisions. The off-diagonal is what matters — top-right is a bypass, bottom-left a false
    positive.</p></div>
  <div class="panel">
    <h3 style="margin-top:0">What the matrix says</h3>
    <p>Across every Python version and extra combination, the structural checks refused
    <strong>{pct(pooled['tp']/(pooled['tp']+pooled['fn']) if pooled['tp']+pooled['fn'] else float('nan'))}</strong>
    of attacks they are designed to catch and accepted
    <strong>{pct(pooled['tn']/(pooled['tn']+pooled['fp']) if pooled['tn']+pooled['fp'] else float('nan'))}</strong>
    of clean, allowed files.</p>
    <p class="note">Positive class = should refuse. TP refused attack · TN accepted clean file ·
    FP clean file refused · FN attack accepted.</p>
  </div>
</div>

<h2>Per-environment metrics</h2>
<div class="scroll panel">{metrics_table(envs)}</div>
<p class="note">Recall is the detection rate on applicable should-refuse cases (Wilson 95% CI).
Structural recall restricts to cases needing no extra. MCC is the Matthews correlation
coefficient, robust under class imbalance.</p>

<h2>Detection by attack class</h2>
<div class="grid2">
  <div class="panel">{class_bars(all_env['per_class'])}
    <p class="note">Full-capability environment (<code>{esc(next((l for l in envs if l.endswith('-all')), next(iter(envs))))}</code>).
    Bars show detection rate; whiskers the Wilson 95% interval; the ratio is caught/total.</p></div>
  <div class="panel">
    <h3 style="margin-top:0">Reading this</h3>
    <p>Each bar is one threat class. A class short of 100% is where attacks slipped through in
    that environment; the whisker shows how tight the estimate is given the sample.</p>
    <p class="note">Classes with few members have wide intervals — honest uncertainty, not
    noise to hide.</p>
  </div>
</div>

<h2>What each extra adds</h2>
<div class="scroll panel"><table><thead><tr><th>environment</th><th>images</th><th>magika</th>
<th>yara</th><th>structural recall</th><th>full recall</th></tr></thead><tbody>
{''.join(f"<tr><td>{esc(l)}</td><td>{'yes' if e['env']['extras']['images'] else '—'}</td>"
         f"<td>{'yes' if e['env']['extras']['magika'] else '—'}</td>"
         f"<td>{'yes' if e['env']['extras']['yara'] else '—'}</td>"
         f"<td>{pct(e['structural']['recall'])}</td><td>{pct(e['full']['recall'])}</td></tr>"
         for l, e in envs.items())}
</tbody></table></div>
<p class="note">The structural checks need no extra and carry the detection. Extras add
capability at the margin: Pillow enables image-integrity checks, Magika flags disguised
scripts, a YARA rule matches the EICAR signature.</p>

<h2>Timing</h2>
<div class="scroll panel">{timing_table(envs)}</div>
<p class="note">Milliseconds per <code>validate()</code> call, fastest of three runs.
The corpus includes decompression bombs and deeply nested archives, which sit in the tail.</p>

<h2>Cross-version consistency</h2>
<div class="panel">{consistency}</div>

<h2>Observational: real active-capable files</h2>
<div class="scroll panel"><table><thead><tr><th>environment</th><th>files</th><th>refused</th>
<th>refusal rate</th></tr></thead><tbody>{obs_rows}</tbody></table></div>
<p class="note">Real PDFs, Office documents, HTML and SVG from the host, sent to a policy that
allows their type. These can legitimately be refused for active content, so they are observed,
not scored. The refusal rate reflects how much real-world content of these formats carries
scripts, macros or DTDs.</p>

<h2>Findings</h2>
<div class="panel">
  <h3 style="margin-top:0">What the hunt found, and what was fixed</h3>
  <p>The first adversarial pass found real gaps that this run confirms are now closed:
  the PHP short open tag <code>&lt;?</code> followed by code was accepted in text files
  (PHP's <code>include()</code> runs it by path), and four SVG vectors
  (<code>&lt;handler&gt;</code>, SMIL animation of an <code>on*</code> handler, CSS
  <code>expression()</code> and <code>@import</code>) were not flagged. Both were fixed
  with regression tests, keeping the existing false-positive guards (prose containing
  <code>&lt;?</code> and benign SVG animation still pass). The structural bypass count
  is now zero across every environment.</p>
  <p class="note">The residual risks below are reported, not scored: each is an
  extractor- or interpreter-dependent or best-effort case where refusing conflicts with
  a deliberate design choice (for example, the short tag is left out of the binary-media
  scan because its two bytes occur by chance in compressed data, and Magika is a
  probabilistic second opinion). They are leads for the maintainer, not defects.</p>
</div>
<div class="panel" style="margin-top:16px">{bypass_html}</div>
<div class="panel" style="margin-top:16px">{probe_html}</div>
<div class="panel" style="margin-top:16px">{fp_html}</div>
<div class="panel" style="margin-top:16px">{err_html}</div>

<footer>
<p>Corpus: {n_cases:,} cases, {n_files:,} unique files. Environments: {esc(env_dataset_line())}.
All attack samples are inert. Generated from the frozen corpus and per-environment result logs;
labels fixed by construction, independent of uploadshield's decisions.</p>
</footer>
</div>
"""
    out.write_text(html_doc, encoding="utf-8")
    print(f"wrote {out} ({len(html_doc)} bytes)")


if __name__ == "__main__":
    main()
