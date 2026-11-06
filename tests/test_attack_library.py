"""Every attack file loads, ids are unique, OWASP ids are well-formed, and the modules are complete."""

from collections import Counter

from redline.attacks.schema import LIBRARY, MODULES, OWASP_ASI, OWASP_LLM, load_file, load_library

# the counts the roadmap promised, per module
EXPECTED = {"recon": 6, "indirect_injection": 8, "exfiltration": 9, "excessive_agency": 10, "evasion": 8}


def test_library_loads_and_validates():
    attacks = load_library()
    assert len(attacks) == sum(EXPECTED.values()) == 41


def test_ids_are_unique():
    ids = [a.id for a in load_library()]
    dupes = [i for i, n in Counter(ids).items() if n > 1]
    assert not dupes, f"duplicate attack ids: {dupes}"


def test_module_counts_match_the_roadmap():
    counts = Counter(a.module for a in load_library())
    assert dict(counts) == EXPECTED


def test_owasp_ids_are_well_formed():
    for a in load_library():
        for x in a.owasp_llm:
            assert OWASP_LLM.match(x), f"{a.id}: bad OWASP LLM id {x!r}"
        for x in a.owasp_asi:
            assert OWASP_ASI.match(x), f"{a.id}: bad OWASP ASI id {x!r}"


def test_every_file_is_a_known_module():
    for path in LIBRARY.glob("*.yaml"):
        for a in load_file(path):
            assert a.module in MODULES
            assert path.stem == a.module, f"{path.name} holds a {a.module!r} attack"


def test_encoded_attacks_render_a_hidden_payload():
    for a in load_library():
        if a.encode is not None:
            rendered = a.rendered_input()
            assert "{enc}" not in rendered
            assert a.encode.payload not in rendered    # the readable payload never ships verbatim


def test_owasp_ids_are_in_the_official_2026_catalogs():
    from redline.attacks.owasp import ASI_2026, LLM_2026
    assert len(LLM_2026) == 10 and len(ASI_2026) == 10
    for a in load_library():
        assert set(a.owasp_llm) <= set(LLM_2026), a.id
        assert set(a.owasp_asi) <= set(ASI_2026), a.id


def test_old_owasp_ids_are_rejected():
    import pytest
    from pydantic import ValidationError

    from redline.attacks.schema import Attack
    base = {"id": "x", "module": "recon", "title": "t", "severity": "low", "customer_id": "C0011",
            "input": "hi", "success_if": [{"check": "canary_in_reply"}], "owasp_llm": ["LLM01:2026"]}
    with pytest.raises(ValidationError):
        Attack.model_validate({**base, "owasp_asi": ["ASI-T06"]})
    with pytest.raises(ValidationError):
        Attack.model_validate({**base, "owasp_llm": ["LLM01:2025"]})


def test_owasp_mapping_doc_is_current():
    from redline.attacks.owasp import DOC, render
    assert DOC.read_text(encoding="utf-8") == render(load_library()), "run python -m redline.attacks.owasp"
