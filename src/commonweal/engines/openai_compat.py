"""One adapter covering nearly every engine worth running.

SGLang, vLLM, Ollama, llama-server, TGI, LMDeploy and LM Studio all expose an
OpenAI-compatible HTTP surface, so a single client against `base_url` reaches
any of them. Point it wherever the member's engine lives; nothing here is
specific to one backend.

Robustness is the point of this module. Backends disagree about keep-alives,
comment frames, terminal markers, and whether `usage` appears at all -- so a
frame we cannot parse is skipped rather than allowed to kill a good stream.

They also disagree about **reasoning models**, which was the finding that a
live run against llama.cpp and Ollama produced and the spec-faithful fake never
could. A reasoning model splits its output in two: the chain of thought and the
answer. The thought does not belong in the answer, but it is spent from the
same `max_tokens` budget -- so at a modest cap the entire budget can go to
thinking and the answer arrives *empty*. Dropping those deltas silently turns
that into a blank response with a full token charge, which is precisely the
silent failure mode this project refuses to ship. So reasoning is parsed,
optionally surfaced, and never silently swallowed whole.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx

from .base import EngineError, GenerationParams, NoAnswerError, Usage

# Backends disagree about the key, and a missed one is not a cosmetic loss --
# it is an answer that arrives empty. llama.cpp, vLLM, SGLang and DeepSeek use
# `reasoning_content`; Ollama and OpenRouter use `reasoning`. Read both.
_REASONING_KEYS = ("reasoning_content", "reasoning")


class OpenAICompatEngine:
    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        name: str = "openai-compat",
        version: str = "unknown",
        api_key: str | None = None,
        timeout: float = 300.0,
        request_usage: bool = True,
        include_reasoning: bool = False,
        verify=True,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.name = name
        self.version = version
        self._headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._timeout = timeout
        self._request_usage = request_usage
        self._include_reasoning = include_reasoning
        self._verify = verify

    async def health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=self._verify) as client:
                resp = await client.get(f"{self.base_url}/models", headers=self._headers)
            return resp.status_code < 500
        except httpx.HTTPError:
            return False

    async def models(self) -> list[str]:
        """Model ids this backend advertises; empty if it will not say.

        Used at peer startup to catch a peer configured for a model its engine
        is not serving. llama-server, for one, ignores the `model` field in the
        request and answers with whatever it happens to have loaded -- so
        without this check a peer can stamp provenance for a model it does not
        run, and the federation's equivalence claim quietly becomes false.
        """
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=self._verify) as client:
                resp = await client.get(f"{self.base_url}/models", headers=self._headers)
            if resp.status_code >= 400:
                return []
            data = resp.json().get("data")
        except (httpx.HTTPError, json.JSONDecodeError, ValueError, AttributeError):
            return []
        if not isinstance(data, list):
            return []
        return [m["id"] for m in data if isinstance(m, dict) and isinstance(m.get("id"), str)]

    async def stream(
        self, messages: list[dict[str, str]], params: GenerationParams
    ) -> AsyncIterator[str | Usage]:
        body: dict = {
            "model": self.model,
            "messages": messages,
            "max_tokens": params.max_tokens,
            "temperature": params.temperature,
            "top_p": params.top_p,
            "stream": True,
        }
        if self._request_usage:
            # Supported by vLLM/SGLang/OpenAI, and by current llama.cpp and
            # Ollama -- both were verified live to emit a usage frame. Backends
            # that do not know the field ignore it; we fall back to an estimate
            # when no usage frame arrives, so asking costs nothing.
            body["stream_options"] = {"include_usage": True}

        answer_chars = 0
        reasoning_chars = 0
        usage: Usage | None = None
        finish_reason = ""

        try:
            async with httpx.AsyncClient(timeout=self._timeout, verify=self._verify) as client:
                async with client.stream(
                    "POST",
                    f"{self.base_url}/chat/completions",
                    json=body,
                    headers=self._headers,
                ) as resp:
                    if resp.status_code >= 400:
                        detail = (await resp.aread()).decode("utf-8", "replace")[:400]
                        raise EngineError(f"engine returned {resp.status_code}: {detail}")
                    async for line in resp.aiter_lines():
                        frame = _parse_sse(line)
                        if frame.finish_reason:
                            finish_reason = frame.finish_reason
                        if frame.usage is not None:
                            usage = frame.usage
                        if frame.reasoning:
                            reasoning_chars += len(frame.reasoning)
                            if self._include_reasoning:
                                yield frame.reasoning
                        if frame.text:
                            answer_chars += len(frame.text)
                            yield frame.text
        except httpx.HTTPError as exc:
            raise EngineError(f"engine unreachable at {self.base_url}: {exc}") from exc

        if reasoning_chars and not answer_chars and not self._include_reasoning:
            # The request was served, billed, and produced nothing usable. Fail
            # loudly: a blank answer that looks like a successful one is worse
            # than an error, and the operator can act on this message. Note the
            # subclass -- the engine is healthy, so a readiness probe hitting
            # this must not conclude the peer is broken.
            raise NoAnswerError(
                f"engine spent its budget on reasoning and returned no answer "
                f"({reasoning_chars} characters of reasoning, "
                f"finish_reason={finish_reason or 'unset'}); raise max_tokens, or set "
                f'"include_reasoning": true on the engine spec to keep the thinking'
            )

        # The engine's own counts are authoritative; `finish_reason` rides out
        # with them so the peer can stamp it on the receipt.
        if usage is not None:
            yield Usage(usage.prompt_tokens, usage.completion_tokens, finish_reason)
        elif finish_reason == "length":
            # No counts to report, but the answer was cut off -- and staying
            # quiet about that is the one thing we will not do. The peer reads a
            # zero count as "not reported" and falls back to its estimator.
            yield Usage(finish_reason=finish_reason)


@dataclass(frozen=True)
class _Frame:
    """What one SSE line carried. Every field is independently optional.

    Independent rather than either/or because real frames mix them: a usage
    frame carries an empty `choices` list, and a final choice frame carries a
    `finish_reason` with no content at all.
    """

    text: str = ""
    reasoning: str = ""
    usage: Usage | None = None
    finish_reason: str = ""


def _parse_sse(line: str) -> _Frame:
    """Decode one SSE line. An unparseable line yields an empty frame."""
    line = line.strip()
    if not line or line.startswith(":") or not line.startswith("data:"):
        return _Frame()
    payload = line[len("data:"):].strip()
    if payload == "[DONE]":
        return _Frame()
    try:
        obj = json.loads(payload)
    except json.JSONDecodeError:
        return _Frame()
    if not isinstance(obj, dict):
        return _Frame()

    text = reasoning = finish_reason = ""
    choices = obj.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        choice = choices[0]
        reason = choice.get("finish_reason")
        if isinstance(reason, str):
            finish_reason = reason
        delta = choice.get("delta")
        if isinstance(delta, dict):
            content = delta.get("content")
            if isinstance(content, str):
                text = content
            for key in _REASONING_KEYS:
                value = delta.get(key)
                if isinstance(value, str) and value:
                    reasoning = value
                    break

    usage = None
    raw = obj.get("usage")
    if isinstance(raw, dict):
        prompt = raw.get("prompt_tokens")
        completion = raw.get("completion_tokens")
        if isinstance(prompt, int) or isinstance(completion, int):
            usage = Usage(
                prompt_tokens=prompt if isinstance(prompt, int) else 0,
                completion_tokens=completion if isinstance(completion, int) else 0,
            )
    return _Frame(text=text, reasoning=reasoning, usage=usage, finish_reason=finish_reason)


# Retained for the focused unit tests of delta extraction.
def _sse_delta(line: str) -> str | None:
    return _parse_sse(line).text or None
