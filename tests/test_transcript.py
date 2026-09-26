from __future__ import annotations

from joltprobe.connection import (
    OCPPConnection,
    ScanConfig,
    ScanSession,
    _MAX_FRAME_CHARS,
    _MAX_TRANSCRIPT_ENTRIES,
)


def _conn(cid: str = "CP1") -> OCPPConnection:
    return OCPPConnection(base_url="ws://x", charger_id=cid, version="2.0.1")


def test_record_captures_direction_and_frame():
    c = _conn()
    c._record("send", [2, "id", "Heartbeat", {}])
    c._record("recv", [3, "id", {}])
    assert [e["dir"] for e in c.transcript] == ["send", "recv"]
    assert c.transcript[0]["frame"][2] == "Heartbeat"
    assert c.transcript[0]["cid"] == "CP1"


def test_record_truncates_long_string_frames():
    c = _conn()
    c._record("send", "A" * (_MAX_FRAME_CHARS + 500))
    assert c.transcript[0]["frame"].endswith("…[truncated]")
    assert len(c.transcript[0]["frame"]) <= _MAX_FRAME_CHARS + len("…[truncated]")


def test_record_caps_entry_count():
    c = _conn()
    for i in range(_MAX_TRANSCRIPT_ENTRIES + 50):
        c._record("send", str(i))
    assert len(c.transcript) == _MAX_TRANSCRIPT_ENTRIES


def _session() -> ScanSession:
    cfg = ScanConfig(
        target="ws://x",
        charger_id="CP1",
        version="2.0.1",
        username=None,
        password=None,
        timeout=1.0,
        security_profile=None,
        enable_dos=False,
        credential_list=None,
    )
    return ScanSession(cfg)


def test_collect_merges_and_orders_by_time():
    s = _session()
    a = _conn("A")
    b = _conn("B")
    s._shared = a
    s._owned = [b]
    a.transcript.append({"t": 2.0, "dir": "send", "cid": "A", "frame": "second"})
    b.transcript.append({"t": 1.0, "dir": "send", "cid": "B", "frame": "first"})
    merged = s.collect_transcript()
    assert [e["frame"] for e in merged] == ["first", "second"]


def test_reset_clears_all_connections():
    s = _session()
    a = _conn("A")
    s._shared = a
    a.transcript.append({"t": 1.0, "dir": "send", "cid": "A", "frame": "x"})
    s.reset_transcripts()
    assert a.transcript == []
    assert s.collect_transcript() == []
