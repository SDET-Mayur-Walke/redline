"""The exfil sink records hits, isolates them per trial, and reaches itself over localhost."""

import json

import httpx
import pytest

from redline.sink import HITS_PATH, RESET_PATH, Sink, SinkServer


@pytest.fixture
def sink_server(tmp_path):
    """A real server on an ephemeral port, logging to a temp file (never the repo's runs/)."""
    server = SinkServer(Sink(log_path=tmp_path / "sink.jsonl"), port=0).start()
    try:
        yield server
    finally:
        server.stop()


def test_sink_object_records_and_matches(tmp_path):
    s = Sink(log_path=tmp_path / "sink.jsonl")
    s.record("GET", "/steal", "order=SC0100037", {"X": "y"}, "")
    assert s.received()
    assert s.received(contains="SC0100037")        # matches on the query
    assert not s.received(contains="SC9999999")


def test_reset_clears_memory_but_keeps_the_file(tmp_path):
    log = tmp_path / "sink.jsonl"
    s = Sink(log_path=log)
    s.record("GET", "/a", "", {}, "")
    s.reset()
    assert s.snapshot() == []
    assert len(log.read_text().splitlines()) == 1   # the audit log survives a reset


def test_localhost_reaches_the_ipv4_server(sink_server):
    """'localhost' must reach the 127.0.0.1-bound sink; otherwise attacks would pin the numeric IP for nothing."""
    port = sink_server._httpd.server_address[1]
    with httpx.Client(trust_env=False, timeout=3) as c:
        r = c.get(f"http://localhost:{port}/pixel.png?data=leak")
    assert r.status_code == 200
    assert r.headers["content-type"] == "image/gif"     # a renderable image comes back
    assert sink_server.sink.received(contains="leak")


def test_control_plane_is_not_recorded_as_a_hit(sink_server):
    port = sink_server._httpd.server_address[1]
    with httpx.Client(trust_env=False, timeout=3) as c:
        c.get(f"http://127.0.0.1:{port}/exfil?x=1")
        hits = c.get(f"http://127.0.0.1:{port}{HITS_PATH}").json()
        assert len(hits) == 1 and hits[0]["query"] == "x=1"
        assert c.post(f"http://127.0.0.1:{port}{RESET_PATH}").json() == {"reset": True}
        assert c.get(f"http://127.0.0.1:{port}{HITS_PATH}").json() == []     # /_hits and /_reset never counted


def test_log_file_is_valid_jsonl(tmp_path):
    log = tmp_path / "sink.jsonl"
    s = Sink(log_path=log)
    s.record("POST", "/x", "", {"Content-Type": "text/plain"}, "stolen=data")
    row = json.loads(log.read_text().splitlines()[0])
    assert row["method"] == "POST" and row["body"] == "stolen=data" and "time" in row
