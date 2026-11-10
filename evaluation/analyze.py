"""Aggregate results/*.jsonl into metrics, confusion matrices and a JSON summary.

Positive class = "should be refused". For each environment only the cases whose
required extra is present are scored, so a scanner case never penalises an
environment that lacks the scanner. A miss on a purely structural case
(requires_extra is None) is a bypass candidate and is listed explicitly.

Usage: python analyze.py RESULTS_DIR OUT_JSON
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path


def wilson(k: int, n: int) -> tuple[float, float]:
    """95% Wilson score interval for a proportion k/n."""
    if n == 0:
        return (0.0, 0.0)
    z = 1.959963984540054
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    n = tp + fp + tn + fn
    rec = tp / (tp + fn) if tp + fn else float("nan")  # detection rate / recall / TPR
    spec = tn / (tn + fp) if tn + fp else float("nan")  # TNR
    prec = tp / (tp + fp) if tp + fp else float("nan")
    acc = (tp + tn) / n if n else float("nan")
    bal = (rec + spec) / 2 if not (math.isnan(rec) or math.isnan(spec)) else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else float("nan")
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / denom if denom else float("nan")
    rec_lo, rec_hi = wilson(tp, tp + fn)
    spec_lo, spec_hi = wilson(tn, tn + fp)
    return {
        "n": n, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "recall": rec, "recall_ci": [rec_lo, rec_hi],
        "specificity": spec, "specificity_ci": [spec_lo, spec_hi],
        "precision": prec, "accuracy": acc, "balanced_accuracy": bal,
        "f1": f1, "mcc": mcc,
        "fpr": 1 - spec if not math.isnan(spec) else float("nan"),
        "fnr": 1 - rec if not math.isnan(rec) else float("nan"),
    }


def percentiles(values: list[float], ps: tuple[float, ...]) -> dict[str, float]:
    if not values:
        return {f"p{int(p * 100)}": float("nan") for p in ps}
    s = sorted(values)
    out = {}
    for p in ps:
        idx = min(len(s) - 1, int(math.ceil(p * len(s))) - 1)
        out[f"p{int(p * 100)}"] = s[max(0, idx)]
    return out


def load(results_dir: Path) -> dict[str, dict]:
    envs: dict[str, dict] = {}
    for path in sorted(results_dir.glob("*.jsonl")):
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        env = rows[0]["_env"]
        envs[env["label"]] = {"env": env, "rows": rows[1:]}
    return envs


def applicable(row: dict, extras: dict[str, bool]) -> bool:
    req = row["requires_extra"]
    return req is None or extras.get(req, False)


SCORED = {"clean", "security", "policy_enforcement"}  # observational and probe are not scored


def confusion(rows: list[dict], extras: dict[str, bool], *, only_structural: bool) -> dict:
    tp = fp = tn = fn = err = 0
    for r in rows:
        if r["category"] not in SCORED:  # observational/probe: either decision may be right
            continue
        if not applicable(r, extras):
            continue
        if only_structural and r["requires_extra"] is not None:
            continue
        if r["decision"] == "error":
            err += 1
            continue
        want_refuse = r["expected"] == "refuse"
        did_refuse = r["decision"] == "refuse"
        if want_refuse and did_refuse:
            tp += 1
        elif want_refuse and not did_refuse:
            fn += 1
        elif not want_refuse and did_refuse:
            fp += 1
        else:
            tn += 1
    m = metrics(tp, fp, tn, fn)
    m["errors"] = err
    return m


def per_class(rows: list[dict], extras: dict[str, bool]) -> dict:
    classes: dict[str, dict] = {}
    for r in rows:
        if r["category"] not in SCORED or not applicable(r, extras) or r["expected"] != "refuse":
            continue
        cl = classes.setdefault(r["attack_class"], {"caught": 0, "total": 0, "missed": []})
        cl["total"] += 1
        if r["decision"] == "refuse":
            cl["caught"] += 1
        else:
            cl["missed"].append({"id": r["id"], "note": r["note"], "policy": r["policy"],
                                 "decision": r["decision"]})
    for cl in classes.values():
        lo, hi = wilson(cl["caught"], cl["total"])
        cl["rate"] = cl["caught"] / cl["total"] if cl["total"] else float("nan")
        cl["rate_ci"] = [lo, hi]
    return classes


def main() -> None:
    results_dir = Path(sys.argv[1])
    out_json = Path(sys.argv[2])
    envs = load(results_dir)

    summary: dict = {"environments": {}, "bypasses": [], "false_positives": [], "errors": [],
                     "probe_accepted": []}
    for label, data in envs.items():
        extras = data["env"]["extras"]
        rows = data["rows"]
        full = confusion(rows, extras, only_structural=False)
        structural = confusion(rows, extras, only_structural=True)
        times = [r["seconds"] * 1000 for r in rows if r["decision"] != "error"]
        clean_times = [r["seconds"] * 1000 for r in rows
                       if r["decision"] != "error" and r["attack_class"] == "clean"]
        obs = [r for r in rows if r["category"] == "observational"]
        obs_refused = sum(1 for r in obs if r["decision"] == "refuse")
        summary["environments"][label] = {
            "env": data["env"],
            "full": full,
            "structural": structural,
            "per_class": per_class(rows, extras),
            "observational": {"total": len(obs), "refused": obs_refused},
            "timing_ms": {
                "all": percentiles(times, (0.5, 0.95, 0.99)),
                "clean": percentiles(clean_times, (0.5, 0.95, 0.99)),
                "count": len(times),
            },
        }
        # Bypass candidates: a scored structural case that should be refused but was accepted.
        for r in rows:
            if (r["category"] in SCORED and r["requires_extra"] is None
                    and r["expected"] == "refuse" and r["decision"] == "accept"):
                summary["bypasses"].append({"env": label, **{k: r[k] for k in
                    ("id", "attack_class", "policy", "template", "note", "codes")}})
            if (r["category"] == "probe" and r["expected"] == "refuse"
                    and r["decision"] == "accept" and applicable(r, extras)):
                summary["probe_accepted"].append({"env": label, **{k: r[k] for k in
                    ("id", "attack_class", "policy", "note", "codes")}})
            if (r["expected"] == "accept" and r["decision"] == "refuse"
                    and r["category"] != "observational" and applicable(r, extras)):
                summary["false_positives"].append({"env": label, **{k: r[k] for k in
                    ("id", "attack_class", "policy", "note", "codes")}})
            if r["decision"] == "error":
                summary["errors"].append({"env": label, **{k: r[k] for k in
                    ("id", "attack_class", "policy", "note", "error")}})

    # Cross-version consistency: do all envs agree on the structural cases they share?
    labels = list(envs)
    disagreements = []
    if labels:
        ids = {r["id"] for r in envs[labels[0]]["rows"] if r["requires_extra"] is None}
        decisions: dict[str, dict[str, str]] = {lab: {r["id"]: r["decision"]
                     for r in envs[lab]["rows"]} for lab in labels}
        for cid in sorted(ids):
            seen = {decisions[lab].get(cid) for lab in labels}
            if len(seen) > 1:
                disagreements.append({"id": cid, "by_env": {lab: decisions[lab].get(cid)
                                      for lab in labels}})
    summary["consistency"] = {"structural_cases": len(ids) if labels else 0,
                              "disagreements": disagreements}

    out_json.write_text(json.dumps(summary, indent=2))

    # A compact console summary.
    print(f"{'environment':28} {'N':>5} {'recall':>8} {'spec':>7} {'FP':>4} {'FN':>4} "
          f"{'MCC':>6} {'err':>4}  p95ms")
    for label, e in summary["environments"].items():
        f = e["full"]
        print(f"{label:28} {f['n']:5d} {f['recall']:8.4f} {f['specificity']:7.4f} "
              f"{f['fp']:4d} {f['fn']:4d} {f['mcc']:6.3f} {f['errors']:4d}  "
              f"{e['timing_ms']['all']['p95']:.3f}")
    print(f"\nstructural bypass candidates (scored): {len(summary['bypasses'])}")
    print(f"probe cases accepted (triage): {len(summary['probe_accepted'])}")
    print(f"false positives (all envs): {len(summary['false_positives'])}")
    print(f"engine errors: {len(summary['errors'])}")
    print(f"cross-env disagreements on structural cases: {len(disagreements)}")


if __name__ == "__main__":
    main()
