"""Every attack file loads, ids are unique, OWASP ids are well-formed, and the modules are complete."""

from collections import Counter

from redline.attacks.schema import LIBRARY, MODULES, OWASP_ASI, OWASP_LLM, load_file, load_library

# the counts the roadmap promised, per module
EXPECTED = {"recon": 6, "indirect_injection": 8, "exfiltration": 8, "excessive_agency": 10, "evasion": 8}


def test_library_loads_and_validates():
    attacks = load_library()
    assert len(attacks) == sum(EXPECTED.values()) == 40


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
