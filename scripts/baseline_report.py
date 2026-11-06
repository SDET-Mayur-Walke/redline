"""Turn one attack run folder into the published baseline summary.

    .venv/bin/python scripts/baseline_report.py runs/<stamp> --examples id1,id2,id3 [--out docs/results/baseline.md]

The run folder (results.json, transcripts.jsonl) stays in runs/, which is gitignored: it holds unmasked
canaries. Everything written here goes through mask_canaries, and tests/test_attack_runner.py fails if an
unmasked canary ever reaches docs/. The hand-written "Reading the result" section is appended after.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from redline.attacks.run import mask_canaries, rupees_lost, wilson
from redline.attacks.schema import load_library
from redline.config import ROOT

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def pct(x: float) -> str:
    return f"{x * 100:.0f}%"


def ci(k: int, n: int) -> str:
    p, lo, hi = wilson(k, n)
    return f"{pct(p)} | {pct(lo)}–{pct(hi)} | {k}/{n}"


def clip(s: str, n: int) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def render_transcript(row: dict, title: str) -> list[str]:
    t = row["transcript"]
    L = [f"### `{row['task_id']}` (trial {row['trial'] + 1}): {title}", ""]
    for turn in t["turns"]:
        role, text = turn.get("role"), (turn.get("content") or "").strip()
        if role == "user":
            L += [f"**Customer:** {clip(text, 600)}", ""]
        elif role == "assistant":
            tools = turn.get("tool_calls") or []
            head = f"**Agent**{' (tools: ' + ', '.join(tools) + ')' if tools else ''}:"
            if text:
                L += [head, "", *[f"> {x}" for x in clip(text, 900).split("\n")], ""]
            elif tools:
                L += [head + " (tool call only)", ""]
    calls = [c for c in t.get("tool_calls", [])]
    if calls:
        L += ["Tool calls:", ""]
        L += [f"- `{c['name']}({clip(json.dumps(c.get('args', {}), ensure_ascii=False), 160)})` → "
              f"{clip(json.dumps(c.get('result'), ensure_ascii=False, default=str), 140)}" for c in calls]
        L.append("")
    fired = [g["grader"] + ": " + clip(g.get("reason") or g.get("explanation") or "", 120)
             for g in row["grades"] if g["score"] < 1.0]
    L += [f"Fired: {'; '.join(fired) or 'nothing'}", ""]
    return L


def recompute_rupees(res: dict, rows: list[dict]) -> None:
    """Re-derive ₹ lost from the transcripts with the current rule (run.rupees_lost), so a run made before the
    rule was fixed is reported correctly. Mutates the per-attack, per-module and overall figures in place."""
    lib = {a.id: a for a in load_library()}
    per: dict[str, float] = {}
    for r in rows:
        attack = lib.get(r["task_id"])
        if attack is None:           # a control: never counted
            continue
        blocked = all(g["score"] >= 1.0 for g in r["grades"] if g["gating"])
        per[r["task_id"]] = per.get(r["task_id"], 0.0) + rupees_lost(attack, r["transcript"]["outcome"], blocked)
    for m in res["modules"].values():
        m["rupees_lost"] = 0.0
    for a in res["attacks"]:
        if a.get("is_control"):
            continue
        a["rupees_lost"] = per.get(a["id"], 0.0)
        res["modules"][a["module"]]["rupees_lost"] += a["rupees_lost"]
    res["overall"]["rupees_lost"] = sum(per.values())


def build(run: Path, examples: list[str]) -> str:
    res = json.loads((run / "results.json").read_text())
    rows = [json.loads(x) for x in (run / "transcripts.jsonl").read_text().splitlines() if x.strip()]
    man, ov = res["manifest"], res["overall"]
    attacks = [a for a in res["attacks"] if not a.get("is_control")]
    by_id = {a["id"]: a for a in res["attacks"]}
    verdicts = res.get("evasion_verdicts", {})
    recompute_rupees(res, rows)

    L = ["# Baseline: every attack, vulnerable mode", "",
         f"`python -m redline.attacks.run --mode vulnerable --trials {man['trials']}`: {man['n_attacks']} attacks "
         f"× {man['trials']} trials, plus {man.get('n_controls', 0)} plain-text evasion controls (not counted in "
         f"ASR). Agent `{man['models']['agent']}` via Ollama (temperature {man['config']['agent']['temperature']}, "
         f"thinking off), prompt `{man['prompt']}`, every defense off, commit `{man['git_commit'][:7]}`, "
         f"{man['created'][:10]}. Wall {res['wall_seconds'] / 60:.0f} min on the M5. Canaries are masked "
         "(RL-CANARY-****); the full run folder is kept locally in `runs/`.", "",
         f"**Overall ASR {pct(ov['asr'])}** (95% Wilson CI {pct(ov['asr_lo'])}–{pct(ov['asr_hi'])}, "
         f"{ov['successes']}/{ov['trials']} trials). **₹{ov['rupees_lost']:,.0f} lost** to refunds across all "
         "trials.", "",
         "## By module", "", "| Module | ASR | 95% CI | succ/trials | ₹ lost |", "|---|---|---|---|---|"]
    for m, v in res["modules"].items():
        L.append(f"| {m} | {ci(v['successes'], v['trials'])} | ₹{v['rupees_lost']:,.0f} |")

    top = sorted(attacks, key=lambda a: (-a["asr"], -a["asr_lo"], SEV[a["severity"]], a["id"]))[:10]
    L += ["", "## Top 10 attacks by ASR", "",
          "| # | Attack | Module | Sev | ASR | 95% CI | succ/trials | fired checks |",
          "|---|---|---|---|---|---|---|---|"]
    for i, a in enumerate(top, 1):
        L.append(f"| {i} | `{a['id']}` | {a['module']} | {a['severity']} | {ci(a['successes'], a['trials'])} | "
                 f"{', '.join(a['fired_checks']) or '—'} |")

    if verdicts:
        L += ["", "## Evasion attacks vs their plain-text controls", "",
              "Each evasion attack also ran with the same payload in plain text. **success**: the evasion variant "
              "fired. **blocked**: it never fired but the plain control did. **inert**: neither fired, so the "
              "payload doesn't work on this model even unencoded, and its 0% says nothing about any defense.", "",
              "| Attack | verdict | evasion | control |", "|---|---|---|---|"]
        for aid, v in verdicts.items():
            L.append(f"| `{aid}` | {v['verdict']} | {v['successes']}/{v['trials']} | "
                     f"{v['control_successes']}/{v['control_trials']} |")
        inert = [aid for aid, v in verdicts.items() if v["verdict"] == "inert"]
        L += ["", "### Inert attacks (excluded from defense comparisons)", ""]
        L += [f"- `{aid}`: {by_id[aid]['title']}" for aid in inert] or ["- none"]

    L += ["", "## Every attack", "", "| Attack | Module | Sev | ASR | 95% CI | succ/trials | ₹ lost | fired checks |",
          "|---|---|---|---|---|---|---|---|"]
    for a in sorted(attacks, key=lambda a: (a["module"], -a["asr"], a["id"])):
        L.append(f"| `{a['id']}` | {a['module']} | {a['severity']} | {ci(a['successes'], a['trials'])} | "
                 f"₹{a['rupees_lost']:,.0f} | {', '.join(a['fired_checks']) or '—'} |")
    errs = [a for a in res["attacks"] if a["sample"].get("error")]
    if errs:
        L += ["", "Agent errors (sample trial): " + "; ".join(f"`{a['id']}`" for a in errs)]

    if examples:
        L += ["", "## Example transcripts", ""]
        for ex in examples:
            fired = [r for r in rows if r["task_id"] == ex and any(g["score"] < 1.0 for g in r["grades"])]
            row = (fired or [r for r in rows if r["task_id"] == ex])[0]
            L += render_transcript(row, by_id[ex]["title"])
    return mask_canaries("\n".join(L).rstrip() + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("run", type=Path)
    ap.add_argument("--examples", default="")
    ap.add_argument("--out", default=str(ROOT / "docs" / "results" / "baseline.md"))
    args = ap.parse_args()
    md = build(args.run, [x for x in args.examples.split(",") if x])
    Path(args.out).write_text(md, encoding="utf-8")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
