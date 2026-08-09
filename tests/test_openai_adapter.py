"""OpenAICompatEngine against a real HTTP server.

These are the tests that would have caught an adapter that works only against
the in-process mock.
"""

from __future__ import annotations

import pytest

from commonweal.engines import EngineError, GenerationParams, OpenAICompatEngine
from commonweal.engines.base import Usage

from .fake_openai import DEFAULT_WORDS, create_fake_openai
from .harness import free_port, serve


async def _drain(engine, *, max_tokens=512):
    text, usage = [], None
    msgs = [{"role": "user", "content": "hi"}]
    async for item in engine.stream(msgs, GenerationParams(max_tokens=max_tokens)):
        if isinstance(item, Usage):
            usage = item
        else:
            text.append(item)
    return "".join(text), usage


async def test_streams_real_sse():
    port = free_port()
    async with serve(create_fake_openai(), port) as url:
        engine = OpenAICompatEngine(f"{url}/v1", "fake-1b")
        text, usage = await _drain(engine)
    assert text == "".join(DEFAULT_WORDS)
    assert usage == Usage(
        prompt_tokens=11, completion_tokens=len(DEFAULT_WORDS), finish_reason="stop"
    )


async def test_keepalives_and_role_frame_ignored():
    """Comment lines and the opening role delta must not appear as output."""
    port = free_port()
    async with serve(create_fake_openai(emit_keepalives=True), port) as url:
        text, _ = await _drain(OpenAICompatEngine(f"{url}/v1", "fake-1b"))
    assert "keep-alive" not in text
    assert "assistant" not in text


async def test_usage_frame_with_empty_choices_is_parsed():
    """The shape that breaks naive parsers: usage arrives with choices == []."""
    port = free_port()
    async with serve(create_fake_openai(include_usage=True), port) as url:
        _, usage = await _drain(OpenAICompatEngine(f"{url}/v1", "fake-1b"))
    assert usage is not None and usage.prompt_tokens == 11


async def test_backend_without_usage_yields_none():
    """Ollama-class backends omit usage; the adapter must not invent it."""
    port = free_port()
    async with serve(create_fake_openai(include_usage=False), port) as url:
        text, usage = await _drain(OpenAICompatEngine(f"{url}/v1", "fake-1b"))
    assert text and usage is None


async def test_max_tokens_is_forwarded():
    port = free_port()
    async with serve(create_fake_openai(), port) as url:
        text, _ = await _drain(OpenAICompatEngine(f"{url}/v1", "fake-1b"), max_tokens=2)
    assert text == "".join(DEFAULT_WORDS[:2])


async def test_error_status_becomes_engine_error():
    port = free_port()
    async with serve(create_fake_openai(fail_status=500), port) as url:
        engine = OpenAICompatEngine(f"{url}/v1", "fake-1b")
        with pytest.raises(EngineError, match="engine returned 500"):
            await _drain(engine)


async def test_unreachable_backend_becomes_engine_error():
    engine = OpenAICompatEngine(f"http://127.0.0.1:{free_port()}/v1", "fake-1b", timeout=2)
    with pytest.raises(EngineError, match="unreachable"):
        await _drain(engine)


async def test_truncated_backend_returns_partial_without_usage():
    """A backend that dies mid-stream yields what arrived and no usage.

    The peer's own final-marker frame is what tells the client the answer was
    complete, so a truncated backend must not be able to fake completeness."""
    port = free_port()
    async with serve(create_fake_openai(die_after=2), port) as url:
        text, usage = await _drain(OpenAICompatEngine(f"{url}/v1", "fake-1b"))
    assert text == "".join(DEFAULT_WORDS[:2])
    assert usage is None


async def test_health_true_when_up_false_when_down():
    port = free_port()
    async with serve(create_fake_openai(), port) as url:
        assert await OpenAICompatEngine(f"{url}/v1", "fake-1b").health() is True
    assert await OpenAICompatEngine(f"{url}/v1", "fake-1b").health() is False


# --- reasoning models ---------------------------------------------------
#
# Every test below encodes something a live backend did that the spec-faithful
# fake never did on its own. llama.cpp b10242 and Ollama 0.32.5 both serve Qwen3
# with thinking on by default, under different field names, and both spend the
# caller's `max_tokens` on it. See docs/ENGINE-NOTES.md.

# Deliberately share no substring with DEFAULT_WORDS, so "the thinking did not
# leak into the answer" is a real assertion rather than a coincidence.
THOUGHTS = ["Hmm", "-let", "-me", "-think", "-about", "-this"]


@pytest.mark.parametrize("key", ["reasoning_content", "reasoning"])
async def test_reasoning_is_not_mixed_into_the_answer(key):
    """llama.cpp calls it `reasoning_content`, Ollama calls it `reasoning`.

    Either way the chain of thought is not the answer and must not be
    concatenated into it.
    """
    port = free_port()
    fake = create_fake_openai(reasoning=THOUGHTS, reasoning_key=key)
    async with serve(fake, port) as url:
        text, usage = await _drain(OpenAICompatEngine(f"{url}/v1", "fake-1b"))
    assert text == "".join(DEFAULT_WORDS)
    assert not any(t.strip() in text for t in THOUGHTS if t.strip())
    assert usage is not None and usage.finish_reason == "stop"


@pytest.mark.parametrize("key", ["reasoning_content", "reasoning"])
async def test_budget_spent_entirely_on_reasoning_raises(key):
    """The live failure: a cap small enough to be eaten by thinking.

    The engine bills for the tokens and there is no answer to show, so the
    adapter must fail loudly rather than hand back a blank success -- a blank
    that looks successful is the failure most likely to go unnoticed.
    """
    port = free_port()
    fake = create_fake_openai(reasoning=THOUGHTS, reasoning_key=key)
    async with serve(fake, port) as url:
        engine = OpenAICompatEngine(f"{url}/v1", "fake-1b")
        with pytest.raises(EngineError, match="reasoning and returned no answer"):
            await _drain(engine, max_tokens=len(THOUGHTS))


async def test_include_reasoning_surfaces_the_thinking_instead_of_failing():
    """Opt in and the thinking becomes output, so nothing is lost or raised."""
    port = free_port()
    fake = create_fake_openai(reasoning=THOUGHTS)
    async with serve(fake, port) as url:
        engine = OpenAICompatEngine(f"{url}/v1", "fake-1b", include_reasoning=True)
        text, _ = await _drain(engine, max_tokens=len(THOUGHTS))
    assert text == "".join(THOUGHTS)


async def test_finish_reason_length_is_reported_with_the_counts():
    """A capped answer is complete-looking and incomplete; say which it was."""
    port = free_port()
    async with serve(create_fake_openai(), port) as url:
        _, usage = await _drain(OpenAICompatEngine(f"{url}/v1", "fake-1b"), max_tokens=2)
    assert usage is not None and usage.finish_reason == "length"


async def test_truncation_reported_even_when_backend_omits_usage():
    """No counts to report is not a reason to stay quiet about truncation.

    The zero counts are the signal to the peer that it should fall back to its
    own estimator rather than bill the request as zero tokens.
    """
    port = free_port()
    async with serve(create_fake_openai(include_usage=False), port) as url:
        text, usage = await _drain(OpenAICompatEngine(f"{url}/v1", "fake-1b"), max_tokens=2)
    assert text
    assert usage == Usage(prompt_tokens=0, completion_tokens=0, finish_reason="length")


async def test_models_lists_what_the_backend_advertises():
    """Peer startup uses this to catch a peer configured for a model its engine
    is not serving -- llama-server answers with whatever it has loaded."""
    port = free_port()
    async with serve(create_fake_openai(model_id="served-model"), port) as url:
        engine = OpenAICompatEngine(f"{url}/v1", "roster-claims-this")
        assert await engine.models() == ["served-model"]
        assert engine.model not in await engine.models()


async def test_models_returns_empty_when_backend_is_down():
    """A backend that will not say is not the same as one serving nothing, so
    the caller gets an empty list and must not treat it as a mismatch."""
    engine = OpenAICompatEngine(f"http://127.0.0.1:{free_port()}/v1", "m", timeout=2)
    assert await engine.models() == []
