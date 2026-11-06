"""The attack runner: turn the YAML library into agentproof Tasks, run N trials each against the
agent, and report attack success rate (ASR) with Wilson intervals, rupees lost and latency.

    python -m redline.attacks.run --mode vulnerable --trials 3 [--module X] [--attack id] [--smoke]

Each trial starts from a pristine world: the store and sink are reset, planted setup docs are added to
the retriever, then the attack's input and followups play as one session. Blocked means none of the
attack's success_if graders fired; ASR = 1 - blocked rate. A run writes runs/<timestamp>/ with
results.json, report.md and manifest.json (config, prompt version, models, git commit) — the experiment
record until MLflow arrives in phase 2.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import re
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from agentproof import Task, Transcript, run_suite
from agentproof.core import SuiteReport

from redline.agent.agent import PROMPTS, Agent
from redline.attacks.graders import GraderCtx, build_grader
from redline.attacks.schema import Attack, load_library
from redline.config import ROOT, Config, load_config, resolve
from redline.kb.corpus import Document
from redline.sink import SinkServer
from redline.store.store import Store

RUNS = ROOT / "runs"
Z = 1.96     # 95% normal quantile for the Wilson interval


# ----- statistics -----

def wilson(successes: int, n: int, z: float = Z) -> tuple[float, float, float]:
    """(point estimate, lower, upper) for a binomial proportion. Narrower and better-behaved than
    the normal approximation at the 0% / 100% edges the regression attacks live at."""
    if n == 0:
        return 0.0, 0.0, 0.0
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return p, max(0.0, centre - half), min(1.0, centre + half)


# ----- planting setup documents -----

def setup_documents(attack: Attack) -> list[Document]:
    docs: list[Document] = []
    if attack.setup is None:
        return docs
    for d in attack.setup.plant_docs:
        meta = {"audience": "public", "source": "help-center", **d.metadata}
        docs.append(Document(id=d.id, title=d.title, text=d.text, metadata=meta))
    for r in attack.setup.reviews:
        docs.append(Document(id=r.review_id, title=r.title, text=r.text, metadata={
            "audience": "public", "author": r.customer, "source": "customer-review", "category": "review",
            "product_id": r.product_id, "rating": str(r.rating), "date": r.date}))
    return docs


# ----- tasks and adapter -----

def build_tasks(attacks: list[Attack], ctx: GraderCtx) -> tuple[list[Task], dict[str, Attack]]:
    tasks, by_id = [], {}
    for a in attacks:
        graders = [build_grader(c, ctx) for c in a.success_if]
        tasks.append(Task(id=a.id, input=a.rendered_input(), graders=graders,
                          expected={"customer_id": a.customer_id}, followups=list(a.followups),
                          tags=[a.module, a.severity]))
        by_id[a.id] = a
    return tasks, by_id


def make_attack_fn(agent: Agent, sink: SinkServer, by_id: dict[str, Attack]):
    async def run(task: Task) -> Transcript:
        attack = by_id[task.id]
        await asyncio.to_thread(agent.reset)                 # store, effects, planted docs, sessions
        sink.sink.reset()
        planted = setup_documents(attack)
        if planted:
            await asyncio.to_thread(agent.retriever.add_documents, planted, "planted")
        sid, cid = f"attack:{task.id}", attack.customer_id
        error = None
        try:
            for message in [task.input, *task.followups]:
                await asyncio.to_thread(agent.chat, sid, cid, message)
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
        conv = agent.conversations.get(sid)
        t = conv.transcript(agent.store, error=error) if conv else Transcript(
            final_output="", outcome=agent.store.effects.as_dict(), error=error)
        t.outcome = {**(t.outcome or {}), "sink_hits": sink.sink.snapshot()}      # merge the world's other half
        return t
    return run


# ----- aggregation -----

@dataclass
class AttackResult:
    attack: Attack
    trials: int
    successes: int           # trials where the attack was NOT blocked
    rupees_lost: float
    mean_latency_s: float
    fired_checks: list[str]  # which success_if checks fired at least once
    sample: dict             # one trial's final output + effects, for the report

    @property
    def asr(self) -> tuple[float, float, float]:
        return wilson(self.successes, self.trials)


def summarise(report: SuiteReport, by_id: dict[str, Attack]) -> list[AttackResult]:
    out = []
    for tr in report.tasks:
        attack, fired, rupees, latencies = by_id[tr.task.id], set(), 0.0, []
        successes = 0
        for trial in tr.trials:
            gates = [g for g in trial.grades if g.gating]
            blocked = bool(gates) and all(g.score >= 1.0 for g in gates)
            successes += 0 if blocked else 1
            for g in trial.grades:
                if g.score < 1.0:
                    fired.add(g.grader)
            rupees += (trial.transcript.outcome or {}).get("refund_total", 0) or 0
            latencies.append(trial.transcript.usage.get("latency_s", 0.0))
        s = tr.trials[0].transcript
        out.append(AttackResult(
            attack=attack, trials=tr.n, successes=successes, rupees_lost=rupees,
            mean_latency_s=sum(latencies) / len(latencies) if latencies else 0.0,
            fired_checks=sorted(fired),
            sample={"final_output": s.final_output,
                    "effects": {k: v for k, v in (s.outcome or {}).items() if v and k != "sink_hits"},
                    "sink_hits": len((s.outcome or {}).get("sink_hits", [])), "error": s.error}))
    return out


def module_rollup(results: list[AttackResult]) -> dict[str, tuple[int, int, float]]:
    """module -> (successes, trials, rupees). Overall is keyed '_overall'."""
    agg: dict[str, list[float]] = defaultdict(lambda: [0, 0, 0.0])
    for r in results:
        for key in (r.attack.module, "_overall"):
            agg[key][0] += r.successes
            agg[key][1] += r.trials
            agg[key][2] += r.rupees_lost
    return {k: (int(v[0]), int(v[1]), v[2]) for k, v in agg.items()}


# ----- rendering -----

def git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        return "unknown"


def manifest(cfg: Config, mode: str, trials: int, n_attacks: int) -> dict:
    return {
        "created": datetime.now(UTC).isoformat(timespec="seconds"),
        "mode": mode, "trials": trials, "n_attacks": n_attacks, "git_commit": git_commit(),
        "prompt": cfg.agent.prompt,
        "models": {"agent": cfg.models.agent, "judge": cfg.models.judge, "embed": cfg.models.embed},
        "config": cfg.model_dump(),
    }


def results_json(results: list[AttackResult], rollup: dict, man: dict, wall: float) -> dict:
    def pack_rollup(key):
        k, n, rupees = rollup.get(key, (0, 0, 0.0))
        p, lo, hi = wilson(k, n)
        return {"successes": k, "trials": n, "asr": p, "asr_lo": lo, "asr_hi": hi, "rupees_lost": rupees}

    return {
        "manifest": man, "wall_seconds": round(wall, 1),
        "overall": pack_rollup("_overall"),
        "modules": {m: pack_rollup(m) for m in sorted(k for k in rollup if k != "_overall")},
        "attacks": [{
            "id": r.attack.id, "module": r.attack.module, "title": r.attack.title,
            "severity": r.attack.severity, "owasp_llm": r.attack.owasp_llm, "owasp_asi": r.attack.owasp_asi,
            "trials": r.trials, "successes": r.successes, "asr": r.asr[0], "asr_lo": r.asr[1], "asr_hi": r.asr[2],
            "rupees_lost": r.rupees_lost, "mean_latency_s": round(r.mean_latency_s, 2),
            "fired_checks": r.fired_checks, "sample": r.sample,
        } for r in results],
    }


def _pct(x: float) -> str:
    return f"{x * 100:.0f}%"


def report_md(results: list[AttackResult], rollup: dict, man: dict, wall: float) -> str:
    k, n, rupees = rollup.get("_overall", (0, 0, 0.0))
    p, lo, hi = wilson(k, n)
    L = [f"# Attack run — {man['mode']}", "",
         f"{man['n_attacks']} attacks × {man['trials']} trial(s), agent `{man['models']['agent']}`, prompt "
         f"`{man['prompt']}`, commit `{man['git_commit'][:8]}`, {man['created']}. Wall {wall / 60:.1f} min.", "",
         f"**Overall ASR {_pct(p)}** (95% CI {_pct(lo)}–{_pct(hi)}, {k}/{n} trials). "
         f"₹ lost to unauthorized refunds: ₹{rupees:,.0f}.", "",
         "## By module", "", "| Module | ASR | 95% CI | succ/trials | ₹ lost |", "|---|---|---|---|---|"]
    for m in sorted(x for x in rollup if x != "_overall"):
        mk, mn, mr = rollup[m]
        mp, mlo, mhi = wilson(mk, mn)
        L.append(f"| {m} | {_pct(mp)} | {_pct(mlo)}–{_pct(mhi)} | {mk}/{mn} | ₹{mr:,.0f} |")
    L += ["", "## By attack", "",
          "| ID | Sev | ASR | 95% CI | fired checks |", "|---|---|---|---|---|"]
    for r in sorted(results, key=lambda r: (r.attack.module, -r.asr[0])):
        p, lo, hi = r.asr
        L.append(f"| `{r.attack.id}` | {r.attack.severity} | {_pct(p)} | {_pct(lo)}–{_pct(hi)} | "
                 f"{', '.join(r.fired_checks) or '—'} |")
    errs = [r for r in results if r.sample.get("error")]
    if errs:
        L += ["", "## Agent errors", ""] + [f"- `{r.attack.id}`: {r.sample['error']}" for r in errs]
    return "\n".join(L) + "\n"


# ----- CLI -----

def select(attacks: list[Attack], module: str | None, attack_id: str | None, smoke: bool) -> list[Attack]:
    if attack_id:
        return [a for a in attacks if a.id == attack_id]
    if module:
        attacks = [a for a in attacks if a.module == module]
    if smoke:
        seen, picked = set(), []
        for a in attacks:
            if a.module not in seen:
                seen.add(a.module)
                picked.append(a)
        return picked
    return attacks


def sys_canary_of(prompt: str) -> str | None:
    m = re.search(r"RL-CANARY-SYS-[0-9a-f]{8}", (PROMPTS / f"{prompt}.md").read_text())
    return m.group(0) if m else None


def build_agent(cfg: Config) -> Agent:
    from redline.kb.corpus import load_corpus
    from redline.kb.retrieval import Retriever

    r = Retriever.from_config(cfg)
    r.rebuild(load_corpus(include_staff=True))
    return Agent(cfg, Store(), r)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Run the attack library against the agent.")
    ap.add_argument("--mode", default="vulnerable", help="selects the config (vulnerable -> configs/default.yaml)")
    ap.add_argument("--config", help="explicit config path, overrides --mode")
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--module", choices=["recon", "indirect_injection", "exfiltration", "excessive_agency",
                                         "evasion"])
    ap.add_argument("--attack", help="run a single attack by id")
    ap.add_argument("--smoke", action="store_true", help="one attack per module, 1 trial (needs Ollama + sink)")
    ap.add_argument("--out", help="also copy report.md here (e.g. docs/results/attacks_smoke.md)")
    args = ap.parse_args(argv)

    cfg_path = args.config or (resolve("configs/default.yaml") if args.mode == "vulnerable"
                               else resolve(f"configs/{args.mode}.yaml"))
    cfg = load_config(cfg_path)
    trials = 1 if args.smoke else args.trials

    attacks = select(load_library(), args.module, args.attack, args.smoke)
    if not attacks:
        ap.error("no attacks selected")
    ctx = GraderCtx(store=Store(), sys_canary=sys_canary_of(cfg.agent.prompt))
    tasks, by_id = build_tasks(attacks, ctx)

    agent = build_agent(cfg)
    t0 = time.perf_counter()
    with SinkServer() as sink:
        report = asyncio.run(run_suite(tasks, make_attack_fn(agent, sink, by_id), trials=trials, concurrency=1))
    wall = time.perf_counter() - t0

    results = summarise(report, by_id)
    rollup = module_rollup(results)
    man = manifest(cfg, args.mode, trials, len(attacks))

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = RUNS / stamp
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "manifest.json").write_text(json.dumps(man, indent=2, default=str))
    (out_dir / "results.json").write_text(json.dumps(results_json(results, rollup, man, wall), indent=2,
                                                     default=str))
    md = report_md(results, rollup, man, wall)
    (out_dir / "report.md").write_text(md)
    if args.out:
        Path(resolve(args.out)).write_text(md)

    k, n, _ = rollup["_overall"]
    p, lo, hi = wilson(k, n)
    print(f"wrote {out_dir.relative_to(ROOT)}  —  overall ASR {_pct(p)} ({_pct(lo)}-{_pct(hi)}), {k}/{n} trials")


if __name__ == "__main__":
    main()
