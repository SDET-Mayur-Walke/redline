"""Tables for docs/results/confirmation.md: recommended.yaml (runs/confirm) beside default and hardened (runs/ablation).

    python scripts/confirmation_report.py [runs/ablation] [runs/confirm]

Same helpers as scripts/ablation_report.py, so a rate here is computed exactly as it is there. Rows hold verdicts,
not reply text, so no canary can appear.
"""

from __future__ import annotations

import json
import statistics
import sys
from collections import Counter
from pathlib import Path

from ablation_report import p95, rate

from redline.ablation import final_rows


def load(folder: str) -> list[dict]:
    return final_rows([json.loads(x) for x in (Path(folder) / "results.jsonl").read_text().splitlines() if x])


def main(step11: str = "runs/ablation", confirm: str = "runs/confirm") -> None:
    rows = load(step11) + load(confirm)
    cfgs = ("default", "recommended", "hardened")
    commits = {c: sorted({r["commit"][:8] for r in rows if r["config"] == c}) for c in cfgs}
    print(f"commits {commits}\n")

    def sel(cfg, kind):
        return [r for r in rows if r["config"] == cfg and r["kind"] == kind
                and (kind == "benign" or not r["is_control"])]

    A = {c: sel(c, "attack") for c in cfgs}
    B = {c: sel(c, "benign") for c in cfgs}

    print("## Headline\n")
    print("| | Default | Recommended | Hardened |\n|---|---|---|---|")
    print("| Attack ASR (95% CI) | " + " | ".join(rate(sum(r["fired"] for r in A[c]), len(A[c])) for c in cfgs) + " |")
    print("| ₹ lost | " + " | ".join(f"₹{sum(r['rupees_lost'] for r in A[c]):,.0f}" for c in cfgs) + " |")
    print("| Attack trials with any canary in a reply | " + " | ".join(
        f"{sum(r['any_canary'] for r in A[c])}/{len(A[c])}" for c in cfgs) + " |")
    print("| Benign pass rate (95% CI) | " + " | ".join(rate(sum(r["passed"] for r in B[c]), len(B[c])) for c in cfgs)
          + " |")
    print("| Benign trials with a canary | " + " | ".join(f"{sum(r['canary'] for r in B[c])}/{len(B[c])}" for c in cfgs)
          + " |")
    for kind, D in (("benign", B), ("attack", A)):
        print(f"| {kind.capitalize()} trial latency, median / p95 | " + " | ".join(
            f"{statistics.median([r['seconds'] for r in D[c]]):.1f} s / {p95([r['seconds'] for r in D[c]]):.1f} s"
            for c in cfgs) + " |")

    print("\n## By module\n")
    print("| Module | Default | Recommended | Hardened |\n|---|---|---|---|")
    for m in sorted({r["module"] for r in A["default"]}):
        print(f"| {m} | " + " | ".join(
            rate(sum(r["fired"] for r in A[c] if r["module"] == m), sum(r["module"] == m for r in A[c]))
            for c in cfgs) + " |")

    print("\n## Attacks that fired on recommended\n")
    print("| Attack | Module | Default | Recommended | Hardened | Fired checks (recommended) |")
    print("|---|---|---|---|---|---|")
    fired = sorted({r["task_id"] for r in A["recommended"] if r["fired"]})
    for t in fired:
        cells = [f"{sum(r['fired'] for r in A[c] if r['task_id'] == t)}/{sum(r['task_id'] == t for r in A[c])}"
                 for c in cfgs]
        checks = Counter(ch for r in A["recommended"] if r["task_id"] == t and r["fired"] for ch in r["fired_checks"])
        mod = next(r["module"] for r in A["recommended"] if r["task_id"] == t)
        print(f"| `{t}` | {mod} | " + " | ".join(cells) + " | " + ", ".join(checks) + " |")

    print("\n## Layers that acted on recommended (trials)\n")
    for kind, D in (("attack", A), ("benign", B)):
        c = Counter(layer for r in D["recommended"] for layer in r["layers"])
        print(f"- {kind}: " + (", ".join(f"{k} {v}" for k, v in c.most_common()) or "none"))
    pend = sum(bool(r.get("pending")) for r in A["recommended"])
    print(f"- attack trials left pending a click: {pend}")

    print("\n## Benign tasks: recommended vs default (passes out of 3)\n")
    def passes(cfg):
        out: Counter = Counter()
        for r in B[cfg]:
            out[r["task_id"]] += r["passed"]
        return out
    d, rec = passes("default"), passes("recommended")
    worse = sorted(t for t in d if rec[t] < d[t])
    better = sorted(t for t in d if rec[t] > d[t])
    print("| Task | Default | Recommended | Recommended layers that acted |\n|---|---|---|---|")
    for t in worse + better:
        layers = Counter(la for r in B["recommended"] if r["task_id"] == t for la in r["layers"])
        print(f"| `{t}` | {d[t]}/3 | {rec[t]}/3 | {', '.join(f'{k} {v}' for k, v in layers.items()) or '-'} |")
    always = [t for t in d if d[t] == 3]
    print(f"\nTasks the default passes 3/3: {len(always)}; of those, recommended passes 3/3: "
          f"{sum(rec[t] == 3 for t in always)}, and breaks at least once: {sum(rec[t] < 3 for t in always)}.")


if __name__ == "__main__":
    main(*sys.argv[1:])
