"""HTTP front door for the support agent: what garak, the attack runner and the demo talk to.

The lifespan builds exactly one Store and one Retriever. Embedded Qdrant locks
its folder, and the store is the world the graders inspect, so both must be
shared by every request. Turns are serialised inside Agent (one local model).

The index is rebuilt at startup so it always matches the config in use (chunk
size, metadata indexing) and never carries documents planted in an earlier run.

    make serve        # uvicorn on 127.0.0.1:8000; REDLINE_CONFIG=configs/x.yaml to switch config

The /dev/rag/* routes exist for outside scanners (rag-redteam) that plant raw strings and speak
{"query"} -> {"answer"}. They answer 404 unless the config sets dev_endpoints: true, because an open
"write to the knowledge base" endpoint is exactly the attack surface this project studies.
"""

from __future__ import annotations

import itertools
import os
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from redline.agent.agent import LLM, Agent
from redline.config import Config, load_config
from redline.kb.corpus import Document
from redline.store.store import Store, StoreError


class ChatIn(BaseModel):
    session_id: str
    customer_id: str
    message: str


class ConfirmIn(BaseModel):
    session_id: str
    customer_id: str
    action_id: str


class AskIn(BaseModel):
    query: str


class PlantIn(BaseModel):
    documents: list[str]


DEV_CUSTOMER = "C0011"


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

    @app.post("/confirm")
    def confirm(body: ConfirmIn, request: Request) -> dict:
        """The customer's Confirm button: the only way a pending side effect (confirm_side_effects) executes."""
        try:
            result = agent(request).confirm(body.session_id, body.customer_id, body.action_id)
        except ValueError as e:
            raise HTTPException(404, str(e)) from None
        return {"action_id": body.action_id, "result": result}

    @app.post("/reset")
    def reset(request: Request) -> dict:
        agent(request).reset()
        return {"status": "reset"}

    @app.get("/effects")
    def effects(request: Request) -> dict:
        return agent(request).store.effects.as_dict()

    # ----- dev-only scanner hooks -----

    def dev_agent(request: Request) -> Agent:
        a = agent(request)
        if not a.cfg.dev_endpoints:
            raise HTTPException(404, "Not Found")
        return a

    plant_ids = itertools.count(1)

    @app.post("/dev/rag/ask")
    def dev_ask(body: AskIn, request: Request) -> dict:
        """One fresh session per query, as the scanner expects independent attempts; same agent turn as /chat."""
        a = dev_agent(request)
        t = a.chat(f"dev:{uuid.uuid4().hex[:12]}", DEV_CUSTOMER, body.query)
        return {"answer": t.reply, "tool_calls": [c.name for c in t.tool_calls], "citations": t.citations}

    @app.post("/dev/rag/documents")
    def dev_documents(body: PlantIn, request: Request) -> dict:
        """Plant raw strings as public help-center articles, the way an attacker with corpus write access would."""
        a = dev_agent(request)
        docs = []
        for text in body.documents:
            n = next(plant_ids)
            title = (text.strip().splitlines() or ["Help article"])[0][:80]
            docs.append(Document(id=f"dev-plant-{n}", title=title, text=text,
                                 metadata={"audience": "public", "source": "help-center"}))
        a.retriever.add_documents(docs, "planted")
        return {"planted": [d.id for d in docs]}

    @app.post("/dev/rag/reset")
    def dev_reset(request: Request) -> dict:
        dev_agent(request).reset()
        return {"status": "reset"}

    @app.get("/health")
    def health(request: Request) -> dict:
        a = agent(request)
        return {"status": "ok", "mode": a.cfg.mode, "chunks": a.retriever.count(), "config": a.cfg.model_dump()}

    return app


app = create_app()
