"""Score a frozen corpus under the current interpreter and installed extras.

Reads manifest.jsonl, runs uploadshield.validate on every case, and writes one
result row per case to results/<env>.jsonl. Pure stdlib + uploadshield, so it runs
under a base install; it detects which extras are present and records them. When a
case needs a scanner (requires_extra magika/yara) and it is available, the policy is
augmented with that scanner, so the scanner study measures the scanner's real effect.

Usage: python run_eval.py CORPUS_DIR RESULTS_DIR [--label NAME] [--repeats N]
"""

from __future__ import annotations

import argparse
import gc
import importlib.util
import json
import platform
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from eval_policies import POLICIES  # noqa: E402

from uploadshield import Upload, __version__, validate  # noqa: E402
from uploadshield.policy import Policy  # noqa: E402


def available_extras() -> dict[str, bool]:
    def has(mod: str) -> bool:
        try:
            return importlib.util.find_spec(mod) is not None
        except (ImportError, ValueError):
            return False

    return {"images": has("PIL"), "magika": has("magika"), "yara": has("yara"), "magic": has("magic")}


def augment(policy: Policy, requires_extra: str | None, extras: dict[str, bool]) -> Policy:
    """Add the scanner a case needs, when present; otherwise leave the policy as is."""
    if requires_extra == "magika" and extras["magika"]:
        from uploadshield.checks import MagikaCheck

        return policy.extend(checks=(MagikaCheck(),))
    if requires_extra == "yara" and extras["yara"]:
        from uploadshield.checks import YaraRules

        rule = 'rule eicar { strings: $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $e }'
        return policy.extend(checks=(YaraRules(source=rule),))
    return policy


def score_one(content: bytes, case: dict, policy: Policy, repeats: int) -> dict:
    name = case["name"]
    declared = case["declared_type"]
    best = float("inf")
    result = None
    for _ in range(repeats):
        upload = Upload.from_bytes(content, name=name, declared_type=declared)
        gc.disable()
        start = time.perf_counter()
        try:
            result = validate(upload, policy)
            error = None
        except Exception as exc:  # the engine should never raise; record it if it does
            result, error = None, f"{type(exc).__name__}: {exc}"
        elapsed = time.perf_counter() - start
        gc.enable()
        best = min(best, elapsed)
        if error:
            return {"decision": "error", "error": error, "codes": [], "seconds": best}
    assert result is not None
    decision = "accept" if result.ok else "refuse"
    return {
        "decision": decision,
        "error": None,
        "codes": sorted({str(v.code) for v in result.violations}),
        "seconds": best,
        "size": len(content),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus", type=Path)
    ap.add_argument("results", type=Path)
    ap.add_argument("--label", default=None)
    ap.add_argument("--repeats", type=int, default=3)
    args = ap.parse_args()

    extras = available_extras()
    pyver = ".".join(map(str, sys.version_info[:3]))
    active = "+".join(k for k, v in extras.items() if v) or "base"
    label = args.label or f"py{pyver}-{active}"
    args.results.mkdir(parents=True, exist_ok=True)

    manifest = [json.loads(line) for line in (args.corpus / "manifest.jsonl").read_text().splitlines()]
    env = {
        "label": label,
        "python": pyver,
        "implementation": platform.python_implementation(),
        "uploadshield": __version__,
        "platform": platform.platform(),
        "extras": extras,
        "repeats": args.repeats,
    }
    out_path = args.results / f"{label}.jsonl"
    rows = 0
    with out_path.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps({"_env": env}) + "\n")
        for case in manifest:
            content = (args.corpus / case["file"]).read_bytes()
            policy = augment(POLICIES[case["policy"]], case["requires_extra"], extras)
            scored = score_one(content, case, policy, args.repeats)
            row = {
                "id": case["id"],
                "policy": case["policy"],
                "expected": case["expected"],
                "category": case["category"],
                "attack_class": case["attack_class"],
                "requires_extra": case["requires_extra"],
                "template": case["template"],
                "note": case["note"],
                **scored,
            }
            fh.write(json.dumps(row) + "\n")
            rows += 1
    print(f"{label}: {rows} cases -> {out_path}")


if __name__ == "__main__":
    main()
