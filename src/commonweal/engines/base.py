"""The engine seam.

Inference engines are **external processes**. We start or discover them, health
check them, and speak a protocol to them; no engine source lives in this repo.
That keeps this project to a control plane and leaves kernels, batching, and
expert placement to the people who specialise in them.

The surface is deliberately tiny -- health plus a token stream. Everything a
federation does (identity, routing, accounting, failover) sits above it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


class EngineError(Exception):
    """The backing engine failed or is unreachable."""


class NoAnswerError(EngineError):
    """The engine served the request but produced no answer.

    A subclass rather than a message variant because the two say opposite
    things about the engine's *health*. A failed request means something is
    wrong; a token budget spent entirely on a reasoning model's chain of
    thought means the engine is working exactly as configured. The readiness
    probe must not confuse a thinking engine for a broken one, and a caller
    that only wants to know "did this request work" still catches EngineError.
    """


@dataclass(frozen=True)
class Usage:
    """What the engine said about the completion it just produced.

    Yielded into the stream rather than stashed on the engine instance: one
    engine serves many concurrent requests, and per-instance state would race
    between them the moment batching does what it is supposed to do.

    `finish_reason` is the engine's own word for why generation stopped --
    `"stop"` for a finished answer, `"length"` for one cut off by `max_tokens`.
    It rides along with the counts because a capped answer is exactly the
    silently-short response this project refuses to hand back unlabelled.

    A count of zero means *not reported*, not "zero tokens": a backend may
    describe why it stopped without reporting counts at all.
    """

    prompt_tokens: int = 0
    completion_tokens: int = 0
    finish_reason: str = ""


@dataclass(frozen=True)
class GenerationParams:
    max_tokens: int = 512
    temperature: float = 0.7
    top_p: float = 1.0

    @classmethod
    def from_request(cls, body: dict[str, Any]) -> GenerationParams:
        return cls(
            max_tokens=int(body.get("max_tokens", 512)),
            temperature=float(body.get("temperature", 0.7)),
            top_p=float(body.get("top_p", 1.0)),
        )


@runtime_checkable
class Engine(Protocol):
    """Minimal contract every backend satisfies."""

    name: str
    version: str
    model: str

    async def health(self) -> bool:
        """True if the engine can currently serve. Used for heartbeats."""
        ...

    def stream(
        self, messages: list[dict[str, str]], params: GenerationParams
    ) -> AsyncIterator[str | Usage]:
        """Yield response text incrementally, optionally ending with a `Usage`.

        An engine that reports real token counts yields exactly one `Usage`;
        one that does not yields only text and the caller falls back to an
        estimate. Raise EngineError on failure.
        """
        ...
