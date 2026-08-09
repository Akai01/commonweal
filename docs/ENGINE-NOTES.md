# Engine notes — what real backends actually do

> Evidence from running `OpenAICompatEngine` against live engines on 2026-08-03.
> This closes the codebase's last untested assumption: the adapter had only ever
> been run against `tests/fake_openai.py`.

Engines are external processes, so their behaviour is not ours to fix — it is ours to
survive. This file records what each one emitted, so the next person does not have to
rediscover it.

## Tested

| backend | version | model | transport |
|---|---|---|---|
| llama.cpp `llama-server` | `b10242` (CPU x64 build) | Qwen3-0.6B-Q8_0 GGUF | `http://…/v1` |
| Ollama | `0.32.5` (docker) | `qwen3:0.6b` | `http://…/v1` |

Both were driven end to end: client → coordinator → peer → engine → back, with real
encryption, real HTTP, two-round leases, and the ledger recording real token counts.

## What matched the spec-faithful fake

- **Usage frames arrive.** It was an open question whether Ollama emits one at all.
  It does, and so does llama.cpp: a trailing frame with `"choices": []` and a `usage`
  object, exactly the shape the adapter was written for, followed by `data: [DONE]`.
  The char/4 fallback estimator is therefore not on the hot path for either.
- **`finish_reason` sits on `choices[0]`**, in its own frame with an empty delta.
- **SSE framing**, keep-alive tolerance, and terminal markers matched.
- **Error bodies** are JSON with an `error.message`; a 400 becomes an `EngineError`
  that reaches the client as an error frame, not as a short answer. Verified by
  overflowing the context window (`3009 tokens > n_ctx 1024`).
- **Concurrency works.** Four simultaneous streams through one adapter against
  llama-server's four slots, no cross-talk.

## What did not — and what it cost

### 1. Reasoning output is a separate field, named differently per backend

| backend | field |
|---|---|
| llama.cpp, vLLM, SGLang, DeepSeek | `delta.reasoning_content` |
| Ollama, OpenRouter | `delta.reasoning` |

Qwen3 thinks by default on both. Of ~200 deltas in a typical response, 199 were
reasoning. The adapter read only `delta.content`, so it dropped all of them.

Dropping them is correct — the chain of thought is not the answer. The damage was what
happened next: **thinking is charged against the same `max_tokens` budget**, so a modest
cap is spent entirely on it and the answer arrives *empty*. Before the fix:

```
$ commonweal chat "Name one color." --model qwen3-0.6b --max-tokens 48
$ echo $?
0
```

No output, no error, exit 0 — and the ledger charged 48 tokens. Three of four concurrent
200-token requests came back with zero visible characters. That is exactly the silent
failure this project refuses to ship, arriving through the one component that had never
been run against a real engine.

Now: reasoning is parsed under both names, and a stream that produces reasoning and no
answer raises rather than returning a blank success.

```
error: engine spent its budget on reasoning and returned no answer (188 characters of
reasoning, finish_reason=length); raise max_tokens, or set "include_reasoning": true
on the engine spec to keep the thinking
```

`"include_reasoning": true` in the engine spec streams the thinking instead of dropping
it, and then nothing is raised because nothing was lost.

### 2. `finish_reason: "length"` was invisible to the client

A capped answer stops mid-sentence and looks exactly like a finished one. With reasoning
models this is the *common* outcome, not an edge case. `Chunk.final` already covers
"the stream was cut off"; nothing covered "the answer was cut off".

The receipt now carries `finish_reason`, `Completion.truncated` exposes it, and the CLI
warns on stderr in both streaming and quiet modes.

### 3. llama-server ignores the request's `model` field

It answers with whatever it has loaded. A peer configured for `llama-3.1-405b-instruct`
against a server holding Qwen3-0.6B got a cheerful `'ok'` — and would have stamped
provenance for a model it does not run, quietly voiding the equivalence claim in
`ARCHITECTURE.md` §9. Ollama, by contrast, returns `model 'x' not found`.

Two startup checks now:

- roster-advertised model ≠ engine's configured model → **refuse to start** (local,
  certain, and a typo away at any time);
- engine's `/v1/models` does not list the configured model → **warn** (some gateways do
  not enumerate everything they serve, so this signal is softer).

### 4. A `Usage` may report a reason without reporting counts

So the peer reads a count of `0` as "not reported" and falls back to its estimator.
Billing a request that produced text as zero tokens would have understated the ledger
in the serving peer's own favour.

## Reproducing

```bash
# llama.cpp: prebuilt CPU binary, ~16 MB, no sudo, no GPU
curl -sL -o llama.tgz https://github.com/ggml-org/llama.cpp/releases/download/b10242/llama-b10242-bin-ubuntu-x64.tar.gz
tar xzf llama.tgz
curl -sL -o q.gguf https://huggingface.co/ggml-org/Qwen3-0.6B-GGUF/resolve/main/Qwen3-0.6B-Q8_0.gguf
LD_LIBRARY_PATH=llama-b10242 llama-b10242/llama-server -m q.gguf --port 18080 \
    -c 4096 -np 4 --alias qwen3-0.6b

# Ollama: docker, no sudo
docker run -d --name ollama -p 11434:11434 ollama/ollama
docker exec ollama ollama pull qwen3:0.6b
```

Then point a peer at either one:

```bash
--engine '{"kind":"openai","base_url":"http://127.0.0.1:18080/v1","model":"qwen3-0.6b"}'
--engine '{"kind":"openai","base_url":"http://127.0.0.1:11434/v1","model":"qwen3:0.6b"}'
```

## Still untested against a live backend

- **SGLang and vLLM.** Both were designed for `stream_options.include_usage` and are the
  likeliest real deployment, but neither was run here (no GPU on the test machine).
  They are closer to the spec than either backend above, so the risk is low — but
  "closer to the spec" is exactly what was assumed about Ollama before this.
- **A reasoning model large enough to matter.** Qwen3-0.6B thinks briefly. GLM-5.2 will
  think for hundreds of tokens, which makes `max_tokens` budgeting a real operational
  question rather than a test fixture.
