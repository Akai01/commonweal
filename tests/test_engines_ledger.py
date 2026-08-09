import pytest

from commonweal.engines import GenerationParams, MockEngine, Usage, build_engine
from commonweal.engines.openai_compat import _sse_delta
from commonweal.ledger import Ledger


async def _collect(engine, prompt="hello"):
    """Text only -- engines may also yield a trailing `Usage`."""
    msgs = [{"role": "user", "content": prompt}]
    return "".join(
        [c async for c in engine.stream(msgs, GenerationParams()) if not isinstance(c, Usage)]
    )


# --- engines ------------------------------------------------------------

async def test_mock_engine_is_deterministic():
    a = await _collect(MockEngine())
    b = await _collect(MockEngine())
    assert a == b and a


async def test_mock_engine_varies_with_prompt():
    assert await _collect(MockEngine(), "one") != await _collect(MockEngine(), "two")


async def test_mock_engine_respects_max_tokens():
    engine = MockEngine(tokens=100)
    msgs = [{"role": "user", "content": "hi"}]
    chunks = [
        c
        async for c in engine.stream(msgs, GenerationParams(max_tokens=3))
        if not isinstance(c, Usage)
    ]
    assert len(chunks) == 3


async def test_mock_engine_reports_exact_usage():
    """The mock reports real counts so ledger assertions test plumbing rather
    than the accuracy of an estimator."""
    engine = MockEngine(tokens=100)
    msgs = [{"role": "user", "content": "one two three"}]
    usage = [
        c
        async for c in engine.stream(msgs, GenerationParams(max_tokens=5))
        if isinstance(c, Usage)
    ]
    assert usage == [Usage(prompt_tokens=3, completion_tokens=5, finish_reason="length")]


async def test_mock_engine_health():
    assert await MockEngine().health() is True


def test_build_engine_mock():
    assert build_engine({"kind": "mock", "model": "m"}).model == "m"


def test_build_engine_openai_requires_fields():
    with pytest.raises(ValueError, match="base_url"):
        build_engine({"kind": "openai"})


def test_build_engine_unknown_kind():
    with pytest.raises(ValueError, match="unknown engine kind"):
        build_engine({"kind": "nope"})


# --- SSE parsing --------------------------------------------------------

def test_sse_extracts_content():
    line = 'data: {"choices":[{"delta":{"content":"hi"}}]}'
    assert _sse_delta(line) == "hi"


@pytest.mark.parametrize(
    "line",
    [
        "",
        "   ",
        ": keep-alive",
        "data: [DONE]",
        "data: {malformed",
        'data: {"choices":[]}',
        'data: {"choices":[{"delta":{}}]}',
        "event: ping",
    ],
)
def test_sse_tolerates_non_content_frames(line):
    """A malformed or empty frame is skipped, not fatal -- one bad line should
    not kill an otherwise good stream."""
    assert _sse_delta(line) is None


# --- ledger -------------------------------------------------------------

def test_ledger_records_contribution_and_consumption():
    led = Ledger()
    led.record_contribution("bob-ws", "bob", resident_gb=62.0, seconds=3600)
    led.record_consumption(
        member_id="bob", request_id="r1", peer_id="bob-ws", completion_tokens=500
    )
    bal = led.balance("bob")
    assert bal.gb_hours == pytest.approx(62.0)
    assert bal.ktokens == pytest.approx(0.5)


def test_contributor_outranks_consumer():
    led = Ledger()
    led.record_contribution("a-ws", "alice", resident_gb=100.0, seconds=3600)
    led.record_consumption(
        member_id="bob", request_id="r1", peer_id="a-ws", completion_tokens=50_000
    )
    scores = led.fair_share(["alice", "bob"])
    assert scores["alice"] > scores["bob"]


def test_newcomer_is_not_starved():
    """Priors mean a member who has neither contributed nor consumed starts at
    a usable score, so joining does not require earning credit first."""
    led = Ledger()
    assert led.fair_share(["newbie"])["newbie"] == pytest.approx(1.0)


def test_duplicate_request_billed_once():
    """Retried delivery must not double-bill."""
    led = Ledger()
    for _ in range(3):
        led.record_consumption(
            member_id="bob", request_id="same", peer_id="p", completion_tokens=100
        )
    assert led.totals()["requests"] == 1
    assert led.totals()["tokens"] == 100


def test_zero_duration_contribution_ignored():
    led = Ledger()
    led.record_contribution("p", "bob", resident_gb=62.0, seconds=0)
    assert led.totals()["gb_hours"] == 0.0


def test_ledger_persists_to_disk(tmp_path):
    path = tmp_path / "sub" / "ledger.db"
    led = Ledger(path)
    led.record_contribution("p", "bob", resident_gb=10.0, seconds=3600)
    led.close()
    assert Ledger(path).balance("bob").gb_hours == pytest.approx(10.0)


def test_divergence_fields_recorded():
    """ARCHITECTURE §9: every served request stamps engine and hardware class so
    output divergence across a heterogeneous federation can be traced."""
    led = Ledger()
    led.record_consumption(
        member_id="bob",
        request_id="r1",
        peer_id="p",
        engine="sglang",
        engine_version="0.4",
        hw_class="cuda-sm90",
    )
    row = led._conn.execute("SELECT engine, hw_class FROM consumptions").fetchone()
    assert row["engine"] == "sglang" and row["hw_class"] == "cuda-sm90"
