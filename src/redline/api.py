"""HTTP front door for the support agent: what garak, the attack runner and the demo talk to.

The lifespan builds exactly one Store and one Retriever. Embedded Qdrant locks
its folder, and the store is the world the graders inspect, so both must be
shared by every request. Turns are serialised inside Agent (one local model).

The index is rebuilt at startup so it always matches the config in use (chunk
size, metadata indexing) and never carries documents planted in an earlier run.

    make serve        # uvicorn on 127.0.0.1:8000; REDLINE_CONFIG=configs/x.yaml to switch config
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from redline.agent.agent import LLM, Agent
from redline.config import Config, load_config
from redline.store.store import Store, StoreError


class ChatIn(BaseModel):
    session_id: str
    customer_id: str
    message: str


class ToolCallOut(BaseModel):
    name: str
    args: dict
    result: object = None


class ChatOut(BaseModel):
    reply: str
    tool_calls: list[ToolCallOut]
    citations: list[str]
    steps: int
    stopped: str
    usage: dict


def create_app(cfg: Config | None = None, store: Store | None = None, retriever=None,
               llm: LLM | None = None) -> FastAPI:
    """Everything is injectable so tests can run the real app with a fake LLM and an in-memory index."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        c = cfg or load_config(os.environ.get("REDLINE_CONFIG"))
        r = retriever
        if r is None:
            from redline.kb.corpus import load_corpus
            from redline.kb.retrieval import Retriever

            r = Retriever.from_config(c)
            r.rebuild(load_corpus(include_staff=True))
        app.state.agent = Agent(c, store or Store(), r, llm=llm)
        yield

    app = FastAPI(title="redline: SaffronCart support agent", lifespan=lifespan)

    def agent(request: Request) -> Agent:
        return request.app.state.agent

    @app.post("/chat", response_model=ChatOut)
    def chat(body: ChatIn, request: Request) -> ChatOut:
        a = agent(request)
        try:
            a.store.customer(body.customer_id)
            t = a.chat(body.session_id, body.customer_id, body.message)
        except StoreError as e:
            raise HTTPException(404, str(e)) from None
        except ValueError as e:                  # session already bound to another customer
            raise HTTPException(409, str(e)) from None
        return ChatOut(reply=t.reply, citations=t.citations, steps=t.steps, stopped=t.stopped, usage=t.usage,
                       tool_calls=[ToolCallOut(name=c.name, args=c.args, result=c.result) for c in t.tool_calls])

    @app.post("/reset")
    def reset(request: Request) -> dict:
        agent(request).reset()
        return {"status": "reset"}

    @app.get("/effects")
    def effects(request: Request) -> dict:
        return agent(request).store.effects.as_dict()

    @app.get("/health")
    def health(request: Request) -> dict:
        a = agent(request)
        return {"status": "ok", "mode": a.cfg.mode, "chunks": a.retriever.count(), "config": a.cfg.model_dump()}

    return app


app = create_app()
