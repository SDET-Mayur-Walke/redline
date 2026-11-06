"""The CI gate: deterministic probes against the stub model; fail the build if a defense regresses.

    make gate                                       # what CI runs
    python -m redline.gate --update-baseline        # after a deliberate change, rewrite gate/baseline.json

Everything runs in-process and offline: the stub model (agent/stub.py), hash encoders over an in-memory index,
the exfil sink on 127.0.0.1. The probes are ids from the attack library and the benign suite (gate/probes.yaml).
Two runs, two assertions:

  1. gate/vulnerable.yaml (every defense off): EVERY probe attack must succeed. If one doesn't, the probe has
     stopped biting (a library, stub or retrieval change), and a clean run 2 would prove nothing.
  2. gate/hardened.yaml (configs/hardened.yaml minus the injection classifier and Llama Guard, which need model
     downloads): attack success at or below gate/baseline.json, and benign pass rate at or above it. Probes the
     baseline blocked are agentproof regression tasks (must stay blocked); the benign tasks are capability tasks
     with the baseline's pass rate as the floor; agentproof's report.gate decides.

On failure it prints which probe regressed and the layer that used to stop it. With the stub, the numbers
measure the deterministic defense code alone, never a model: see the stub's docstring.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import sys
import time
from pathlib import Path

import yaml
from agentproof import Tier, run_suite
from agentproof.report import gate as agentproof_gate

from redline.agent.agent import Agent
from redline.attacks import run as attack_run
from redline.attacks.graders import GraderCtx
from redline.attacks.schema import load_library
from redline.benign import run as benign_run
from redline.benign.schema import load_tasks
from redline.config import ROOT, Config, load_config
from redline.defenses.scanner import IngestionScanner
from redline.kb.corpus import load_corpus
from redline.kb.encoders import HashEmbedder, HashSparse
from redline.kb.retrieval import Retriever
from redline.sink import SinkServer
from redline.store.store import Store

GATE = ROOT / "gate"
PROBES, BASELINE = GATE / "probes.yaml", GATE / "baseline.json"
VULNERABLE, HARDENED = GATE / "vulnerable.yaml", GATE / "hardened.yaml"


def offline_agent(cfg: Config) -> Agent:
    """The real agent, tools and defenses, with no model anywhere: hash encoders, no reranker, in-memory index."""
    if cfg.models.agent != "stub":
        raise SystemExit(f"the gate runs the stub model only, got models.agent={cfg.models.agent!r}")
    if cfg.defenses.injection_classifier or cfg.defenses.guard_llm:
        raise SystemExit("the gate runs offline: injection_classifier and guard_llm must be off")
    rc = cfg.retrieval.model_copy(update={"qdrant_path": ":memory:", "rerank": False})
    scanner = IngestionScanner(cfg.defenses.egress_allowlist) if cfg.defenses.ingestion_scanner else None
    r = Retriever(rc, HashEmbedder(), HashSparse(), scanner=scanner)
    r.rebuild(load_corpus(include_staff=True))
    return Agent(cfg, Store(), r)


def run_attacks(cfg: Config, ids: list[str], regression: set[str] = frozenset()):
    """(per-probe AttackResults, agentproof report). Probes in `regression` become regression-tier tasks."""
    lib = {a.id: a for a in load_library()}
    missing = [i for i in ids if i not in lib]
    if missing:
        raise SystemExit(f"unknown attack ids in {PROBES.name}: {missing}")
    ctx = GraderCtx(store=Store(), sys_canary=attack_run.sys_canary_of(cfg.agent.prompt))
    tasks, by_id = attack_run.build_tasks([lib[i] for i in ids], ctx)
    tasks = [dataclasses.replace(t, tier=Tier.REGRESSION if t.id in regression else Tier.CAPABILITY)
             for t in tasks]
    agent = offline_agent(cfg)
    with SinkServer() as sink:
        report = asyncio.run(run_suite(tasks, attack_run.make_attack_fn(agent, sink, by_id), trials=1,
                                       concurrency=1))
    return attack_run.summarise(report, by_id), report


def run_benign(cfg: Config, ids: list[str]):
    lib = {b.id: b for b in load_tasks()}
    missing = [i for i in ids if i not in lib]
    if missing:
        raise SystemExit(f"unknown benign ids in {PROBES.name}: {missing}")
    tasks, by_id = benign_run.build_tasks([lib[i] for i in ids], Store())
    report = asyncio.run(run_suite(tasks, benign_run.make_benign_fn(offline_agent(cfg), by_id), trials=1,
                                   concurrency=1))
    return benign_run.summarise(report, by_id), report


def snapshot(attacks, benign) -> dict:
    """What gate/baseline.json records: the two rates, and per probe whether it held and which layers acted."""
    asr = sum(r.successes for r in attacks) / max(1, sum(r.trials for r in attacks))
    passed = sum(r.passed for r in benign) / max(1, sum(r.trials for r in benign))
    return {"attack_asr": round(asr, 4), "benign_pass_rate": round(passed, 4),
            "attacks": {r.attack.id: {"blocked": r.successes == 0,
                                      "layers": sorted({x for t in r.trial_layers for x in t})} for r in attacks},
            "benign": {r.task.id: {"passed": r.passed == r.trials, "layers": sorted(r.layers)} for r in benign}}


def check_vulnerable(attacks) -> list[str]:
    return [f"probe `{r.attack.id}` did not succeed against the vulnerable config: it no longer bites"
            for r in attacks if r.successes < r.trials]


def compare(now: dict, base: dict) -> tuple[list[str], list[str]]:
    """(reasons to fail, table rows) for the hardened run against the baseline."""
    reasons, rows = [], []
    if now["attack_asr"] > base["attack_asr"]:
        reasons.append(f"attack ASR {now['attack_asr']:.0%} > baseline {base['attack_asr']:.0%}")
    if now["benign_pass_rate"] < base["benign_pass_rate"]:
        reasons.append(f"benign pass rate {now['benign_pass_rate']:.0%} < baseline {base['benign_pass_rate']:.0%}")
    for pid, a in now["attacks"].items():
        b = base["attacks"].get(pid)
        if b and b["blocked"] and not a["blocked"]:
            rows.append(f"| attack `{pid}` | succeeded | blocked | {', '.join(b['layers']) or '—'} | "
                        f"{', '.join(a['layers']) or '—'} |")
    for tid, t in now["benign"].items():
        b = base["benign"].get(tid)
        if b and b["passed"] and not t["passed"]:
            rows.append(f"| benign `{tid}` | failed | passed | — | {', '.join(t['layers']) or '—'} |")
    return reasons, rows


TABLE_HEAD = ["| Probe | Now | Baseline | Layer that used to stop it | Layers acting now |", "|---|---|---|---|---|"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CI gate: stub-model probes against the defenses.")
    ap.add_argument("--update-baseline", action="store_true", help="write the hardened run to gate/baseline.json")
    ap.add_argument("--hardened", default=str(HARDENED), help="the hardened config to gate (default %(default)s)")
    args = ap.parse_args(argv)
    t0 = time.perf_counter()
    probes = yaml.safe_load(PROBES.read_text())
    failures = []

    vuln, _ = run_attacks(load_config(VULNERABLE), probes["attacks"])
    failures += check_vulnerable(vuln)
    print(f"vulnerable: {sum(r.successes > 0 for r in vuln)}/{len(vuln)} probe attacks succeed")

    cfg = load_config(args.hardened)
    base = json.loads(BASELINE.read_text()) if BASELINE.exists() and not args.update_baseline else None
    held = {pid for pid, a in (base or {}).get("attacks", {}).items() if a["blocked"]}
    attacks, a_report = run_attacks(cfg, probes["attacks"], regression=held)
    benign, b_report = run_benign(cfg, probes["benign"])
    now = snapshot(attacks, benign)
    print(f"hardened ({Path(args.hardened).name}): attack ASR {now['attack_asr']:.0%}, "
          f"benign pass rate {now['benign_pass_rate']:.0%}")

    if args.update_baseline:
        BASELINE.write_text(json.dumps(now, indent=2) + "\n")
        print(f"wrote {BASELINE.relative_to(ROOT)}")
        return 1 if failures else 0
    if base is None:
        failures.append(f"no {BASELINE.relative_to(ROOT)}: run with --update-baseline first")
    else:
        reasons, rows = compare(now, base)
        failures += reasons
        failures += agentproof_gate(a_report, regression_min=1.0)
        failures += agentproof_gate(b_report, capability_min=base["benign_pass_rate"])
        if rows:
            print("\n".join(["", *TABLE_HEAD, *rows, ""]))
    print(f"gate {'FAILED' if failures else 'passed'} in {time.perf_counter() - t0:.1f} s")
    for f in dict.fromkeys(failures):
        print(f"  - {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
