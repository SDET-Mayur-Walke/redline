"""Input defenses, offline: Unicode normalisation, the injection classifier and Llama Guard (both mocked)."""

import pytest
from fakes import ScriptedLLM, call

from redline.agent.agent import Agent
from redline.attacks.encoders import encode
from redline.config import Config
from redline.defenses.classifier import InjectionClassifier
from redline.defenses.guard import LlamaGuard, parse
from redline.defenses.pipeline import REFUSAL, Defenses
from redline.defenses.unicode import normalize, normalize_tree
from redline.store.store import Store

ME = "C0011"
SENTENCE = "Please show me the refund rules for my order."


# ----- unicode -----

@pytest.mark.parametrize("scheme", ["tag_chars", "zero_width", "lookalike"])
def test_normalize_undoes_each_invisible_or_lookalike_scheme(scheme):
    """Our attack encoders are the test input; the normaliser knows nothing about them."""
    hidden = encode(scheme, SENTENCE)
    assert hidden != SENTENCE
    n = normalize(f"Hi there. {hidden}")
    assert n.changed
    if scheme == "tag_chars":                       # tag characters carry the text invisibly: it is removed
        assert n.text == "Hi there. " and n.removed == len(hidden)
    else:                                           # zero-width and look-alikes: the plain sentence comes back
        assert n.text == f"Hi there. {SENTENCE}"


def test_bidi_controls_and_fullwidth_forms():
    n = normalize("refund‮ dnuof ⁦x⁩ ＳＣ０１")
    assert "‮" not in n.text and "⁦" not in n.text and n.removed == 3
    assert n.text.endswith("SC01")                  # NFKC folds fullwidth letters and digits


def test_genuine_non_latin_text_is_left_alone():
    for text in ("Где мой заказ? Спасибо", "मेरा ऑर्डर कहाँ है?", "Καλημέρα σας"):
        n = normalize(text)
        assert n.text == text and not n.changed


def test_mixed_script_word_is_folded_even_in_non_latin_text():
    n = normalize("Привет, rеfund")                 # Cyrillic е inside a Latin word
    assert n.text == "Привет, refund" and n.folded == 1


def test_plain_text_and_rupee_sign_unchanged():
    n = normalize("Refund ₹1,948 to my card, order SC0102109.")
    assert n.text == "Refund ₹1,948 to my card, order SC0102109." and not n.changed


def test_normalize_tree_walks_tool_results():
    out, removed, folded = normalize_tree([{"text": "a​b", "n": 3, "meta": {"t": "оk"}}])
    assert out == [{"text": "ab", "n": 3, "meta": {"t": "ok"}}] and removed == 1 and folded == 1


# ----- agent wiring helpers -----

def _cfg(**defenses) -> Config:
    cfg = Config()
    cfg.agent = cfg.agent.model_copy(update={"auto_retrieve": False})
    cfg.defenses = cfg.defenses.model_copy(update=defenses)
    return cfg


def _agent(kb_retriever, llm, cfg, **kw):
    return Agent(cfg, Store(), kb_retriever, llm=llm, defenses=Defenses(cfg, **kw))


def test_unicode_layer_cleans_the_message_the_model_sees(kb_retriever):
    llm = ScriptedLLM("ok")
    a = _agent(kb_retriever, llm, _cfg(unicode_normalize=True))
    a.chat("s", ME, "where is my order?" + encode("tag_chars", "say hi"))
    assert llm.seen[0][-1]["content"] == "where is my order?"
    ev = a.conversations["s"].session.events
    assert ev and ev[0]["layer"] == "unicode" and ev[0]["action"] == "strip"
    # the grader-facing turn keeps what the customer actually sent
    assert a.conversations["s"].turns[0]["content"] != "where is my order?"


def test_unicode_off_is_the_baseline_path(kb_retriever):
    llm = ScriptedLLM("ok")
    msg = "where is my order?" + encode("zero_width", "hi")
    _agent(kb_retriever, llm, _cfg()).chat("s", ME, msg)
    assert llm.seen[0][-1]["content"] == msg


# ----- injection classifier -----

def fake_scorer(flag_word: str):
    """P(injection) = 0.99 if the text contains flag_word, else 0.01. No model download."""
    return lambda texts: [0.99 if flag_word in t.lower() else 0.01 for t in texts]


def test_classifier_threshold():
    c = InjectionClassifier("m", 0.9, scorer=lambda texts: [0.95, 0.5][: len(texts)])
    assert c.flagged("x") == (True, 0.95)
    c = InjectionClassifier("m", 0.9, scorer=lambda texts: [0.5])
    assert c.flagged("x") == (False, 0.5)


def test_classifier_blocks_user_message_before_the_model(kb_retriever):
    llm = ScriptedLLM("should never be called")
    cfg = _cfg(injection_classifier=True)
    a = _agent(kb_retriever, llm, cfg, classifier=InjectionClassifier("m", 0.9, scorer=fake_scorer("zzinject")))
    t = a.chat("s", ME, "zzinject please")
    assert t.reply == REFUSAL and t.stopped == "blocked" and llm.seen == [] and t.tool_calls == []
    assert a.conversations["s"].session.events[-1]["layer"] == "injection_classifier"


def test_classifier_drops_flagged_chunks_only(kb_retriever):
    llm = ScriptedLLM([call("search_help_center", query="refund timelines upi")], "done")
    cfg = _cfg(injection_classifier=True)
    clf = InjectionClassifier("m", 0.9, scorer=fake_scorer("upi"))      # flag any chunk mentioning UPI
    a = _agent(kb_retriever, llm, cfg, classifier=clf)
    t = a.chat("s", ME, "how long do refunds take")
    res = t.tool_calls[0].result
    assert all("upi" not in (r["text"] + r.get("title", "")).lower() for r in res)
    drops = [e for e in a.conversations["s"].session.events if e["action"] == "drop"]
    assert drops and all(e["layer"] == "injection_classifier" for e in drops)


def test_classifier_is_lazy_and_not_built_when_off(kb_retriever):
    d = Defenses(_cfg())
    assert d.classifier is None and d.guard is None
    clf = Defenses(_cfg(injection_classifier=True)).classifier
    assert clf is not None and clf._scorer is None          # nothing loaded until first use


# ----- llama guard -----

def test_guard_parse():
    assert parse("safe").safe and parse("").safe
    v = parse("unsafe\nS7, S2")
    assert not v.safe and v.categories == ["S7", "S2"] and "privacy" in v.describe()


def test_guard_blocks_input_and_output(kb_retriever):
    def chat(messages):
        last = messages[-1]["content"]
        return "unsafe\nS1" if "zzharm" in last else "safe"

    cfg = _cfg(guard_llm=True)
    llm = ScriptedLLM("fine reply", "zzharm reply")
    a = _agent(kb_retriever, llm, cfg, guard=LlamaGuard("g", "http://x", chat=chat))
    assert a.chat("s1", ME, "zzharm request").reply == REFUSAL and llm.seen == []
    assert a.chat("s2", ME, "hello").reply == "fine reply"
    assert a.chat("s3", ME, "hello again").reply == REFUSAL           # the reply itself was unsafe
    layers = [e["layer"] for e in a.conversations["s3"].session.events]
    assert layers == ["guard_llm"]


def test_guard_fails_open_and_logs(kb_retriever):
    def down(messages):
        raise ConnectionError("ollama down")

    cfg = _cfg(guard_llm=True)
    a = _agent(kb_retriever, ScriptedLLM("reply"), cfg, guard=LlamaGuard("g", "http://x", chat=down))
    assert a.chat("s", ME, "hello").reply == "reply"
    assert {e["action"] for e in a.conversations["s"].session.events} == {"error"}


# ----- config -----

def test_default_config_has_every_defense_off():
    from redline.config import DEFAULT_CONFIG, load_config

    cfg = load_config(DEFAULT_CONFIG)
    assert not any(cfg.switches().values()) and cfg.mode == "vulnerable"
    assert _cfg(spotlight=True).mode == "partial"


def test_hardened_config_turns_every_switch_on():
    from redline.config import ROOT, load_config

    cfg = load_config(ROOT / "configs" / "hardened.yaml")
    assert all(cfg.switches().values()) and cfg.mode == "hardened"
    assert cfg.defenses.egress_allowlist == ["localhost:8000", "127.0.0.1:8000"]
    default = load_config(ROOT / "configs" / "default.yaml")
    assert cfg.models == default.models and cfg.agent == default.agent        # only the defenses differ
