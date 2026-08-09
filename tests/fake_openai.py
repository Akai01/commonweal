"""A faithful OpenAI-compatible server, used to exercise the real HTTP path.

`MockEngine` bypasses HTTP entirely, so it cannot catch the things that
actually break an engine adapter: SSE framing, keep-alive comments, terminal
markers, usage frames arriving with an empty `choices` list, mid-stream
failures, and error bodies.

This is not a substitute for a live run against Ollama or SGLang. It is the
next best thing, and it turns "never tested against a real backend" into
"tested against a backend that behaves like the spec".

The reasoning options exist because a live run found what "behaves like the
spec" missed: reasoning models spend `max_tokens` on a chain of thought that is
not the answer, under two different field names, and a budget that runs out
mid-thought yields a response with no answer in it at all. Both real backends
tested (llama.cpp b10242, Ollama 0.32.5) do this by default with Qwen3.
`docs/ENGINE-NOTES.md` records what each one actually emitted.
"""

from __future__ import annotations

import asyncio
import json

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

DEFAULT_WORDS = ["Hello", " from", " a", " real", " SSE", " stream"]


def create_fake_openai(
    *,
    words: list[str] | None = None,
    include_usage: bool = True,
    emit_keepalives: bool = True,
    fail_status: int | None = None,
    die_after: int | None = None,
    delay: float = 0.0,
    reasoning: list[str] | None = None,
    reasoning_key: str = "reasoning_content",
    model_id: str = "fake-1b",
) -> FastAPI:
    """Build a configurable OpenAI-compatible backend.

    `die_after` truncates the stream mid-flight without a terminal marker,
    which is how a real backend crashing looks from the client side.

    `reasoning` emits chain-of-thought deltas before the answer, charged against
    the same `max_tokens` budget the way a real reasoning model charges them --
    so a small enough cap produces reasoning, `finish_reason: "length"`, and no
    answer. `reasoning_key` selects the field name: `reasoning_content` for
    llama.cpp/vLLM/SGLang, `reasoning` for Ollama/OpenRouter.
    """
    app = FastAPI()
    tokens = words if words is not None else DEFAULT_WORDS
    thoughts = reasoning or []

    @app.get("/v1/models")
    async def models():
        return {"object": "list", "data": [{"id": model_id, "object": "model"}]}

    @app.post("/v1/chat/completions")
    async def completions(request: Request):
        body = await request.json()
        if fail_status is not None:
            return JSONResponse(
                {"error": {"message": "backend is unhappy", "type": "server_error"}},
                status_code=fail_status,
            )

        wants_usage = include_usage and bool(
            (body.get("stream_options") or {}).get("include_usage")
        )
        limit = int(body.get("max_tokens", 512))

        async def sse():
            # Real servers open with a role delta carrying no content.
            yield _frame({"choices": [{"index": 0, "delta": {"role": "assistant"}}]})
            emitted = 0

            # Thinking is charged against the same budget as the answer, which
            # is the whole reason a capped request can come back empty.
            for thought in thoughts[:limit]:
                if delay:
                    await asyncio.sleep(delay)
                yield _frame({"choices": [{"index": 0, "delta": {reasoning_key: thought}}]})
                emitted += 1

            for i, word in enumerate(tokens[: max(0, limit - emitted)]):
                if die_after is not None and emitted >= die_after:
                    return  # truncated: no [DONE], no usage
                if delay:
                    await asyncio.sleep(delay)
                if emit_keepalives and i and i % 2 == 0:
                    yield ": keep-alive\n\n"
                yield _frame({"choices": [{"index": 0, "delta": {"content": word}}]})
                emitted += 1

            stopped = "length" if emitted >= limit else "stop"
            yield _frame({"choices": [{"index": 0, "delta": {}, "finish_reason": stopped}]})
            if wants_usage:
                # Usage arrives in its own frame with an EMPTY choices list --
                # the shape that breaks naive parsers.
                yield _frame({
                    "choices": [],
                    "usage": {
                        "prompt_tokens": 11,
                        "completion_tokens": emitted,
                        "total_tokens": 11 + emitted,
                    },
                })
            yield "data: [DONE]\n\n"

        return StreamingResponse(sse(), media_type="text/event-stream")

    return app


def _frame(obj: dict) -> str:
    return f"data: {json.dumps(obj)}\n\n"
