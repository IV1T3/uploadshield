# uploadshield adversarial evaluation

An independent, academic-style evaluation of uploadshield's detection capability: a
large labelled corpus of upload cases scored as a binary detector across Python
versions and extra combinations, with confusion matrices, confidence intervals, timing,
and a bypass hunt.

This directory is versioned in git but **excluded from the published package** (wheel
and sdist): see `.gitignore` here and the `wheel-exclude`/`source-exclude` entries in
`pyproject.toml`. It is tooling for maintainers, not part of the library.

## Why it is built this way

A validator either accepts or refuses each `(policy, file)` pair, so it is a binary
classifier. The positive class is *should be refused* (malicious or disallowed); the
negative class is *should be accepted* (benign and allowed).

| | predicted refuse | predicted accept |
|---|---|---|
| should refuse | TP | **FN — bypass** |
| should accept | **FP** | TN |

Two rules keep the measurement honest:

1. **Labels are assigned by construction, never by asking uploadshield.** Each case is
   built to be either a legitimate accept or a known-bad refuse, so a false negative is
   evidence against the system, not a tautology.
2. **The clean set is verified by an independent oracle.** Real files sampled from the
   host are confirmed with `/usr/bin/file` (libmagic) before being labelled clean; a
   file whose bytes disagree with its extension is moved to an observational bucket
   rather than counted as a false positive.

Cases that need an optional extra to catch (image integrity needs Pillow; disguised
scripts need Magika; the EICAR signature needs a YARA rule) are tagged `requires_extra`
and scored only where that extra is present. A miss on a purely structural case
(`requires_extra` is `None`) is a true bypass; a miss on a capability case without its
extra is expected.

**Categories.** `security`, `clean`, `policy_enforcement` are scored in the confusion
matrix. `observational` (real active-capable files, plugin-dependent formats) and
`probe` (extractor- or interpreter-dependent, or debatable, adversarial cases) are
reported with their decisions but kept out of the matrix, so a maybe is never counted
as a definite bypass. Accepted probes are listed for manual triage — that is where the
most interesting findings tend to surface.

All attack samples are **inert**: placeholder scripts, the standard EICAR test string,
and structural tricks whose contents are harmless.

## Files

| File | Role |
|---|---|
| `eval_policies.py` | The policies cases are scored against (shared by generator and runner). |
| `gen_corpus.py` | Builds and freezes the labelled corpus to `corpus/` + `manifest.jsonl`. |
| `adversarial.py` | Out-of-the-box adversarial case builders (code-in-text edges, polyglots, PDF actions, SVG vectors, office internals, archive differentials, name tricks, bombs, scanner evasion). |
| `run_eval.py` | Scores the corpus under the current interpreter + extras → `results/<env>.jsonl`. |
| `run_all.sh` | Runs the environment matrix (Python 3.11–3.15 × base/images/yara/magika/all). |
| `analyze.py` | Aggregates results → confusion matrices, Wilson CIs, MCC, per-class rates, consistency, timing → `summary.json`. |
| `report.py` | Renders `summary.json` into a self-contained HTML report. |

`corpus/`, `results/`, `summary.json`, `report.html`, and `*.log` are generated
artifacts and are git-ignored (the corpus is hundreds of MB and must never be committed
or published).

## Running it

From the repository root, with [uv](https://docs.astral.sh/uv/):

```sh
# 1. Build the corpus once (needs Pillow; samples real files from the host).
uv run python evaluation/gen_corpus.py evaluation/corpus --fresh \
  --real-root /System/Library --real-root /Applications --max-real-per-ext 40

# 2. Build a wheel and score every environment.
uv build --no-sources -o dist
bash evaluation/run_all.sh dist/uploadshield-*.whl

# 3. Aggregate and render.
uv run python evaluation/analyze.py evaluation/results evaluation/summary.json
uv run python evaluation/report.py evaluation/summary.json \
  evaluation/corpus/manifest.jsonl evaluation/report.html
```

`run_all.sh` installs each environment in isolation, so "base" genuinely has no Pillow,
Magika, or YARA; the runner records which extras are actually present. yara-python has
no wheels for Python 3.14+ and Magika none for 3.15, so those rows carry fewer extras.

## Reading the output

`analyze.py` prints a per-environment table (N, recall with 95% CI, specificity, FP,
FN, MCC, errors, p95 latency) and the counts of structural bypasses, accepted probes,
false positives, engine errors, and cross-version disagreements. `summary.json` holds
the full detail, including every bypass, false positive, accepted probe, and the
per-attack-class detection rates. `report.html` presents it all with confusion matrices
and charts.

**A false negative on a scored `security` case is a bypass and must be triaged and
fixed.** An accepted `probe` is a lead to investigate, not an automatic defect.
