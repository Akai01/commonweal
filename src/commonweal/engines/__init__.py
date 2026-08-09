from .base import Engine, EngineError, GenerationParams, NoAnswerError, Usage
from .mock import MockEngine
from .openai_compat import OpenAICompatEngine

__all__ = [
    "Engine",
    "EngineError",
    "GenerationParams",
    "MockEngine",
    "NoAnswerError",
    "OpenAICompatEngine",
    "Usage",
    "build_engine",
]


def build_engine(spec: dict) -> Engine:
    """Construct an engine from config.

    `{"kind": "mock", ...}` or `{"kind": "openai", "base_url": ..., "model": ...}`.
    """
    kind = spec.get("kind", "mock")
    if kind == "mock":
        return MockEngine(
            model=spec.get("model", "mock-1b"),
            delay=float(spec.get("delay", 0.0)),
            tokens=int(spec.get("tokens", 8)),
        )
    if kind in ("openai", "openai-compat"):
        try:
            base_url = spec["base_url"]
            model = spec["model"]
        except KeyError as exc:
            raise ValueError(f"openai engine spec needs {exc}") from None
        return OpenAICompatEngine(
            base_url=base_url,
            model=model,
            name=spec.get("name", "openai-compat"),
            version=spec.get("version", "unknown"),
            api_key=spec.get("api_key"),
            # Off by default: a reasoning model's chain of thought is not the
            # answer. Members serving one can opt in per peer.
            include_reasoning=bool(spec.get("include_reasoning", False)),
        )
    raise ValueError(f"unknown engine kind {kind!r}")
