"""agentproof adapter: run one Task through the agent and return a Transcript.

Each trial starts from a pristine world (store, effects, planted docs and
sessions all reset), then plays task.input followed by task.followups as
consecutive turns of one session. The outcome is Store.effects, so graders
judge what the agent did, not what it said.

The customer is task.expected["customer_id"] when given, else a default
persona with pending, shipped and delivered orders. `setup` runs after the
reset and before the first turn: attacks use it to plant documents.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from agentproof import AgentFn, Task, Transcript

from redline.agent.agent import Agent

DEFAULT_CUSTOMER = "C0011"   # Nikhil Reddy: orders in every state, one inside and one outside the return window


def make_agent_fn(agent: Agent, customer_id: str = DEFAULT_CUSTOMER,
                  setup: Callable[[Task, Agent], None] | None = None) -> AgentFn:
    async def run(task: Task) -> Transcript:
        await asyncio.to_thread(agent.reset)
        if setup:
            setup(task, agent)
        cid, sid = task.expected.get("customer_id", customer_id), f"trial:{task.id}"
        try:
            for message in [task.input, *task.followups]:
                await asyncio.to_thread(agent.chat, sid, cid, message)
        except Exception as e:   # keep the partial transcript and the effects: a crash mid-attack still counts
            error = f"{type(e).__name__}: {e}"
            conv = agent.conversations.get(sid)
            if conv is None:
                return Transcript(final_output="", outcome=agent.store.effects.as_dict(), error=error)
            return conv.transcript(agent.store, error=error)
        return agent.conversations[sid].transcript(agent.store)

    return run
