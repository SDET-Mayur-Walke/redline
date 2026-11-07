"""Tables for docs/results/ablation.md from the step 11 run (runs/ablation/results.jsonl).

    python scripts/ablation_report.py [runs/ablation]

Prints markdown sections; the write-up copies them and adds the reading. The rule's own table comes from
`python -m redline.ablation --rule`, not from here, so the pre-registered code stays the only implementation of it.
Canaries never appear: rows hold verdicts, not reply text.
"""

from __future__ import annotations

import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

from redline.ablation import ALL_SWITCHES, final_rows
from redline.attacks.run import wilson


def pct(x: float) -> str:
    return f"{x * 100:.0f}%"


def rate(k: int, n: int) -> str:
    p, lo, hi = wilson(k, n)
    return f"{pct(p)} ({pct(lo)}–{pct(hi)}, {k}/{n})"


def p95(xs: list[float]) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, round(0.95 * (len(xs) - 1)))] if xs else 0.0


def main(folder: str = "runs/ablation") -> None:
    rows = final_rows([json.loads(x) for x in (Path(folder) / "results.jsonl").read_text().splitlines() if x])
    commits = {r["commit"] for r in rows}
    print(f"rows {len(rows)}, commits {sorted(c[:8] for c in commits)}\n")

    def sel(cfg, kind, controls=False):
        return [r for r in rows if r["config"] == cfg and r["kind"] == kind
                and (kind == "benign" or r["is_control"] == controls)]

    # ----- headline
    print("## Headline\n")
    print("| | Default | Hardened |\n|---|---|---|")
    A = {c: sel(c, "attack") for c in ("default", "hardened")}
    B = {c: sel(c, "benign") for c in ("default", "hardened")}
    print("| Attack ASR (95% CI) | " + " | ".join(rate(sum(r["fired"] for r in A[c]), len(A[c])) for c in A) + " |")
    print("| ₹ lost | " + " | ".join(f"₹{sum(r['rupees_lost'] for r in A[c]):,.0f}" for c in A) + " |")
    print("| Attack trials with any canary in a reply | " + " | ".join(
        f"{sum(r['any_canary'] for r in A[c])}/{len(A[c])}" for c in A) + " |")
    print("| Benign pass rate (95% CI) | " + " | ".join(rate(sum(r["passed"] for r in B[c]), len(B[c])) for c in B)
          + " |")
    print("| Benign trials with a canary | " + " | ".join(f"{sum(r['canary'] for r in B[c])}/{len(B[c])}" for c in B)
          + " |")
    for kind, D in (("benign", B), ("attack", A)):
        print(f"| {kind.capitalize()} trial latency, median / p95 | " + " | ".join(
            f"{statistics.median([r['seconds'] for r in D[c]]):.1f} s / {p95([r['seconds'] for r in D[c]]):.1f} s"
            for c in D) + " |")

    # ----- modules
    print("\n## By module\n\n| Module | Default ASR | Hardened ASR | ₹ lost (default / hardened) |\n|---|---|---|---|")
    for m in sorted({r["module"] for r in A["default"]}):
        cells = []
        for c in A:
            xs = [r for r in A[c] if r["module"] == m]
            cells.append(rate(sum(r["fired"] for r in xs), len(xs)))
        lost = " / ".join(f"₹{sum(r['rupees_lost'] for r in A[c] if r['module'] == m):,.0f}" for c in A)
        print(f"| {m} | {cells[0]} | {cells[1]} | {lost} |")

    # ----- per attack
    print("\n## Every attack, default vs hardened\n")
    print("| Attack | Module | Default | Hardened | Hardened fired checks | Hardened layers (trials) | "
          "Any canary d / h |\n|---|---|---|---|---|---|---|")
    per = defaultdict(lambda: defaultdict(list))
    for c in A:
        for r in A[c]:
            per[r["task_id"]][c].append(r)
    for aid in sorted(per, key=lambda a: (per[a]["default"][0]["module"], a)):
        d, h = per[aid]["default"], per[aid]["hardened"]
        checks = sorted({x for r in h if r["fired"] for x in r["fired_checks"]})
        lay = Counter(x for r in h for x in r["layers"])
        print(f"| `{aid}` | {d[0]['module']} | {sum(r['fired'] for r in d)}/{len(d)} | "
              f"{sum(r['fired'] for r in h)}/{len(h)} | {', '.join(checks) or '—'} | "
              f"{', '.join(f'{k} {v}' for k, v in lay.most_common()) or '—'} | "
              f"{sum(r['any_canary'] for r in d)} / {sum(r['any_canary'] for r in h)} |")

    # ----- blocked by (hardened)
    held = [r for r in A["hardened"] if not r["fired"]]
    print(f"\n## Blocked by, hardened attack run ({len(held)} held of {len(A['hardened'])})\n")
    first, anyl = Counter(), Counter()
    none = pend = 0
    for r in held:
        lay = [x for x in r["layers"] if x != "pending_confirmation"]
        pend += r["pending"]
        if lay:
            first[lay[0]] += 1
            anyl.update(lay)
        elif not r["pending"]:
            none += 1
    print("| Layer | Trials it acted in | Trials it acted first in |\n|---|---|---|")
    for k, v in anyl.most_common():
        print(f"| {k} | {v} | {first[k]} |")
    print(f"| *left pending a click* | {pend} | |\n| *no layer acted (the model declined)* | {none} | |")
    sole = Counter(r["layers"][0] for r in held if len(r["layers"]) == 1 and r["layers"][0] != "pending_confirmation")
    print("\nsole stopper:", dict(sole.most_common()))

    # ----- evasion verdicts
    print("\n## Evasion vs control\n\n| Attack | Default (ev / ctrl) | Hardened (ev / ctrl) |\n|---|---|---|")
    for aid in sorted({r["task_id"] for r in A["default"] if r["module"] == "evasion"}):
        cells = []
        for c in ("default", "hardened"):
            e = [r for r in sel(c, "attack") if r["task_id"] == aid]
            k = [r for r in sel(c, "attack", True) if r["task_id"] == aid + "~control"]
            ef, kf = sum(r["fired"] for r in e), sum(r["fired"] for r in k)
            v = "success" if ef else "blocked" if kf else "inert"
            cells.append(f"{v} ({ef}/{len(e)} / {kf}/{len(k)})")
        print(f"| `{aid}` | {cells[0]} | {cells[1]} |")

    # ----- benign
    print("\n## Benign, default vs hardened\n\n| Task | Category | Kind | Default | Hardened | "
          "Hardened layers (trials) |\n|---|---|---|---|---|---|")
    bt = defaultdict(lambda: defaultdict(list))
    for c in B:
        for r in B[c]:
            bt[r["task_id"]][c].append(r)
    for tid in bt:
        d, h = bt[tid]["default"], bt[tid]["hardened"]
        lay = ", ".join(f"{k} {v}" for k, v in Counter(x for r in h for x in r["layers"]).most_common()) or "—"
        print(f"| `{tid}` | {d[0]['category']} | {d[0]['task_kind']} | {sum(r['passed'] for r in d)}/{len(d)} | "
              f"{sum(r['passed'] for r in h)}/{len(h)} | {lay} |")
    fp = Counter(x for r in B["hardened"] for x in r["layers"])
    print("\nhardened benign trials each layer fired in:", dict(fp.most_common()))
    print("hardened benign trials with any layer firing:", sum(bool(r["layers"]) for r in B["hardened"]), "/",
          len(B["hardened"]))
    print("benign by kind:")
    for k in ("answer", "act", "refusal"):
        print(" ", k, *(f"{c} {sum(r['passed'] for r in B[c] if r['task_kind'] == k)}/"
                        f"{sum(r['task_kind'] == k for r in B[c])}" for c in B))

    # ----- single-switch detail
    print("\n## Single-switch detail\n")
    for x in ALL_SWITCHES:
        a = sel(f"only-{x}", "attack")
        b = sel(f"only-{x}", "benign")
        fired = sum(r["fired"] for r in a)
        print(f"{x}: ASR {fired}/{len(a)}, ₹{sum(r['rupees_lost'] for r in a):,.0f}, canary "
              f"{sum(r['any_canary'] for r in a)}, benign {sum(r['passed'] for r in b)}/{len(b)}, "
              f"benign median {statistics.median([r['seconds'] for r in b]):.1f} s, "
              f"layer fired on benign {sum(bool(r['layers']) for r in b)}")
    da = sel("default", "attack")
    print(f"default per-trial: ASR {sum(r['fired'] for r in da) / 3:.1f}/41, benign "
          f"{sum(r['passed'] for r in B['default']) / 3:.1f}/47")


if __name__ == "__main__":
    main(*sys.argv[1:])
