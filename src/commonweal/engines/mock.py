"""A deterministic engine for tests and control-plane development.

Testing a request router should not require 372 GB on disk and multi-second
inference. This backend makes the whole federation exercisable in milliseconds,
and being deterministic it lets end-to-end tests assert on exact output.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import AsyncIterator

from .base import GenerationParams, Usage

_WORDS = (
    "alpha bravo charlie delta echo foxtrot golf hotel india juliet "
    "kilo lima mike november oscar papa quebec romeo sierra tango"
).split()


class MockEngine:
    name = "mock"
    version = "0"

    def __init__(self, model: str = "mock-1b", *, delay: float = 0.0, tokens: int = 8):
        self.model = model
        self._delay = delay
        self._tokens = tokens

    async def health(self) -> bool:
        return True

    async def stream(
        self, messages: list[dict[str, str]], params: GenerationParams
    ) -> AsyncIterator[str | Usage]:
        prompt = "\n".join(m.get("content", "") for m in messages)
        seed = hashlib.sha256(prompt.encode("utf-8")).digest()
        count = min(self._tokens, params.max_tokens)
        for i in range(count):
            if self._delay:
                await asyncio.sleep(self._delay)
            word = _WORDS[seed[i % len(seed)] % len(_WORDS)]
            yield word if i == 0 else f" {word}"
        # Exact counts, so ledger assertions in tests are about the plumbing
        # rather than about the accuracy of an estimator. The finish reason is
        # real too: a mock that always claimed "stop" would let the truncation
        # path go untested end to end.
        yield Usage(
            prompt_tokens=len(prompt.split()),
            completion_tokens=count,
            finish_reason="length" if count < self._tokens else "stop",
        )
