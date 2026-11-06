"""Run the benign suite: what a config costs legitimate customers.

    python -m redline.benign.run --config configs/hardened.yaml --trials 3 [--tasks a,b] [--out path.md]

Each trial starts from a pristine world and plays the task's turns as one session. The runner is an honest
customer: after every turn, if a side effect the task expects (task.confirm) is waiting for confirmation, it
presses Confirm once for it (Agent.confirm, the in-process POST /confirm) and records the click. Nothing else
is ever confirmed.

Per task it records pass rate, failed checks, wall latency per trial, the defense layers that fired (on a
benign task every one of those is a false positive, except a confirmation the task expected), any canary in a
reply, and the clicks. Output: runs/<stamp>-benign/ with results.json, transcripts.jsonl and report.md.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import statistics
import time
from datetime import UTC, datetime
from pathlib import Path

from agentproof import Task, Transcript, run_suite

from redline.agent.agent import Agent
from redline.attacks.graders import all_replies
from redline.attacks.run import CANARY_RX, build_agent, git_commit, mask_canaries
from redline.benign.graders import graders_for
from redline.benign.schema import BenignTask, load_tasks
from redline.config import ROOT, Config, load_config, resolve
from redline.defenses import stopping_layers
from redline.store.store import Store

RUNS = ROOT / "runs"


def build_tasks(tasks: list[BenignTask], store: Store) -> tuple[list[Task], dict[str, BenignTask]]:
    out = [Task(id=b.id, input=b.turns[0], followups=b.turns[1:], graders=graders_for(b, store),
                expected={"customer_id": b.customer_id}, tags=[b.category, b.kind]) for b in tasks]
    return out, {b.id: b for b in tasks}


def make_benign_fn(agent: Agent, by_id: dict[str, BenignTask]):
    async def run(task: Task) -> Transcript:
        b = by_id[task.id]
        await asyncio.to_thread(agent.reset)
        sid, cid, clicks, error = f"benign:{task.id}", b.customer_id, [], None
        clicked: set[str] = set()
        try:
            for i, message in enumerate(b.turns):
                await asyncio.to_thread(agent.chat, sid, cid, message)
                session = agent.conversations[sid].session
                for action_id, action in list(session.pending.items()):
                    if action["tool"] in b.confirm and action["tool"] not in clicked:
                        clicked.add(action["tool"])
                        result = await asyncio.to_thread(agent.confirm, sid, cid, action_id)
                        clicks.append({"turn": i, "action_id": action_id, "tool": action["tool"],
                                       "ok": not (isinstance(result, dict) and "error" in result)})
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
        conv = agent.conversations.get(sid)
        t = conv.transcript(agent.store, error=error) if conv else Transcript(
            final_output="", outcome=agent.store.effects.as_dict(), error=error)
        t.outcome = {**(t.outcome or {}), "clicks": clicks}
        return t
    return run


@dataclasses.dataclass
class TaskSummary:
    task: BenignTask
    trials: int
    passed: int
    failed_checks: list[str]
    seconds: list[float]
    layers: dict[str, int]         # layer -> trials it fired in (false positives on benign tasks)
    canary: int
    clicks: int
    sample_reply: str

    @property
    def median_s(self) -> float:
        return statistics.median(self.seconds) if self.seconds else 0.0


def summarise(report, by_id: dict[str, BenignTask]) -> list[TaskSummary]:
    out = []
    for tr in report.tasks:
        layers: dict[str, int] = {}
        fails, canary, clicks, seconds = set(), 0, 0, []
        for trial in tr.trials:
            o = trial.transcript.outcome or {}
            for x in stopping_layers(o.get("defense_events", [])):
                if x != "confirmation":
                    layers[x] = layers.get(x, 0) + 1
            fails |= {f"{g.grader}: {g.reason}" for g in trial.grades if g.score < 1.0}
            canary += bool(CANARY_RX.search(all_replies(trial.transcript)))
            clicks += len(o.get("clicks", []))
            seconds.append(trial.seconds)
        out.append(TaskSummary(by_id[tr.task.id], tr.n, sum(t.passed for t in tr.trials), sorted(fails), seconds,
                               layers, canary, clicks, tr.trials[0].transcript.final_output or ""))
    return out


def report_md(rows: list[TaskSummary], cfg: Config, trials: int, wall: float) -> str:
    n = sum(r.trials for r in rows)
    ok = sum(r.passed for r in rows)
    med = statistics.median([s for r in rows for s in r.seconds]) if rows else 0.0
    L = [f"# Benign run — {cfg.mode}", "",
         f"{len(rows)} tasks × {trials} trial(s), agent `{cfg.models.agent}`, prompt `{cfg.agent.prompt}`, commit "
         f"`{git_commit()[:8]}`. Wall {wall / 60:.1f} min. **{ok}/{n} trials passed**, median {med:.1f} s/trial.",
         "",
         "*layers fired* on a benign task are false positives (a confirmation the task expected is not counted).",
         "", "| Task | Category | Passed | Median s | Layers fired | Clicks | Canary | Failed checks |",
         "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        layers = ", ".join(f"{k} {v}" for k, v in r.layers.items()) or "—"
        L.append(f"| `{r.task.id}` | {r.task.category} | {r.passed}/{r.trials} | {r.median_s:.1f} | {layers} | "
                 f"{r.clicks} | {r.canary} | {'<br>'.join(r.failed_checks) or '—'} |")
    return mask_canaries("\n".join(L) + "\n")


def transcripts_jsonl(report) -> str:
    return "\n".join(json.dumps({"task_id": tr.task.id, "trial": t.index, "seconds": round(t.seconds, 2),
                                 "grades": [dataclasses.asdict(g) for g in t.grades],
                                 "transcript": dataclasses.asdict(t.transcript)}, default=str, ensure_ascii=False)
                     for tr in report.tasks for t in tr.trials) + "\n"


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Run the benign suite against the agent.")
    ap.add_argument("--config", default="configs/default.yaml")
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--tasks", help="comma-separated task ids (default: all)")
    ap.add_argument("--out", help="also copy report.md here")
    args = ap.parse_args(argv)

    cfg = load_config(resolve(args.config))
    tasks = load_tasks()
    if args.tasks:
        wanted = {x.strip() for x in args.tasks.split(",") if x.strip()}
        tasks = [t for t in tasks if t.id in wanted]
        missing = wanted - {t.id for t in tasks}
        if missing:
            ap.error(f"unknown task ids {sorted(missing)}")
    agentproof_tasks, by_id = build_tasks(tasks, Store())
    agent = build_agent(cfg)
    t0 = time.perf_counter()
    report = asyncio.run(run_suite(agentproof_tasks, make_benign_fn(agent, by_id), trials=args.trials,
                                   concurrency=1))
    wall = time.perf_counter() - t0
    rows = summarise(report, by_id)

    out_dir = RUNS / (datetime.now().strftime("%Y%m%d-%H%M%S") + "-benign")
    out_dir.mkdir(parents=True, exist_ok=True)
    md = report_md(rows, cfg, args.trials, wall)
    (out_dir / "report.md").write_text(md)
    (out_dir / "transcripts.jsonl").write_text(transcripts_jsonl(report), encoding="utf-8")
    (out_dir / "results.json").write_text(json.dumps({
        "manifest": {"created": datetime.now(UTC).isoformat(timespec="seconds"), "mode": cfg.mode,
                     "config_path": args.config, "trials": args.trials, "git_commit": git_commit(),
                     "config": cfg.model_dump()},
        "wall_seconds": round(wall, 1),
        "tasks": [{"id": r.task.id, "category": r.task.category, "kind": r.task.kind, "trials": r.trials,
                   "passed": r.passed, "median_s": round(r.median_s, 2), "seconds": [round(s, 2) for s in r.seconds],
                   "layers": r.layers, "canary": r.canary, "clicks": r.clicks, "failed_checks": r.failed_checks,
                   "sample_reply": mask_canaries(r.sample_reply)} for r in rows]}, indent=2, default=str))
    if args.out:
        Path(resolve(args.out)).write_text(md)
    print(f"wrote {out_dir.relative_to(ROOT)}  —  {sum(r.passed for r in rows)}/{sum(r.trials for r in rows)} passed")


if __name__ == "__main__":
    main()
