"""Talking to Ollama: one chat call that must return JSON, and one embed call.

Plain `urllib` rather than `httpx` or the `ollama` package. Two requests, both
JSON in and JSON out, against a server on loopback -- a dependency would buy
nothing, and this stage otherwise needs no third-party code at all.

## Why `format` matters more than the prompt

Ollama's `format` field takes a JSON Schema and constrains decoding to match it.
That is not the same as asking nicely for JSON: a schema whose `type` field is an
enum of seven strings makes an eighth value *unrepresentable*, so the ontology in
`ontology.py` is enforced by the decoder rather than by the model's goodwill.
The same trick keeps the alignment judge from inventing a node id -- its
`match_id` enum contains only ids that were actually offered to it.

## Determinism

`temperature: 0` and a fixed `seed`, because this is a paper reproduction and a
number that changes between runs cannot be reported. TRACE does the same thing
for a different reason (section 5.2.1 runs each experiment three times with fixed
seeds and unions the results). Note that identical output is still not
guaranteed across Ollama versions, model quantisations or GPU counts -- record
the tag you ran, as the README says.

## Thinking

`qwen3` is a reasoning model and thinks before answering unless told not to.
Measured on this server, on the same extraction: thinking on took 11.8s and 460
tokens, thinking off took 4.7s and 101 tokens, **for an identical answer**. At
roughly fifteen chunks plus relation batches per report that is the difference
between a four-minute job and a ten-minute one, so it is off by default and
`EXTRACT_THINK=true` turns it back on. Worth re-measuring per stage rather than
assuming: this was one easy sentence, and the relation-validation prompt asks a
harder question than the extraction prompt does.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, Sequence

from .config import Settings

# Kept out of config: this is not a knob, it is "make it repeatable".
SEED = 42


class LLMError(RuntimeError):
    """Ollama could not be reached, or did not answer in the shape we asked for."""


def _post(url: str, payload: dict, timeout: int, attempts: int = 2) -> dict:
    """POST JSON, get JSON. One retry, because a cold model load can time out once."""
    body = json.dumps(payload).encode("utf-8")
    last: Exception | None = None
    for attempt in range(attempts):
        request = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # A 4xx is our fault -- a bad schema, a model that is not pulled --
            # and will fail again identically, so do not spend a retry on it.
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise LLMError(f"{url} returned {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last = exc
            if attempt + 1 < attempts:
                time.sleep(2)
    raise LLMError(
        f"{url} did not answer after {attempts} attempts ({last}). "
        "Is `ollama serve` running, and is OLLAMA_URL right?"
    ) from last


def chat_json(
    cfg: Settings,
    *,
    system: str,
    user: str,
    schema: dict[str, Any],
    model: str | None = None,
) -> dict:
    """One turn, answered as JSON matching `schema`.

    The schema is enforced during decoding, so the result parses -- but a model
    can still satisfy a schema with empty lists, and callers must treat "valid"
    and "useful" as different questions.
    """
    payload = {
        "model": model or cfg.extract_model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "think": cfg.think,
        "format": schema,
        "options": {"temperature": 0, "seed": SEED},
    }
    response = _post(f"{cfg.ollama_url}/api/chat", payload, cfg.timeout)
    content = (response.get("message") or {}).get("content", "")
    if not content.strip():
        raise LLMError(
            f"{payload['model']} returned an empty message. "
            "This usually means the model is not pulled, or ran out of context."
        )
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        # Should be impossible with `format` set, so say so plainly rather than
        # silently salvaging -- a model ignoring the schema is worth knowing about.
        raise LLMError(
            f"{payload['model']} returned content that is not JSON despite a schema "
            f"being set: {content[:300]!r}"
        ) from exc
    if not isinstance(parsed, dict):
        raise LLMError(f"expected a JSON object, got {type(parsed).__name__}")
    return parsed


def embed(cfg: Settings, texts: Sequence[str], *, model: str | None = None) -> list[list[float]]:
    """Embed a batch. Order matches the input; an empty input is an empty list."""
    if not texts:
        return []
    payload = {"model": model or cfg.embed_model, "input": list(texts)}
    response = _post(f"{cfg.ollama_url}/api/embed", payload, cfg.timeout)
    vectors = response.get("embeddings")
    if not isinstance(vectors, list) or len(vectors) != len(texts):
        raise LLMError(
            f"{payload['model']} returned {len(vectors or [])} embeddings for "
            f"{len(texts)} inputs. If this model is not an embedding model, set EMBED_MODEL."
        )
    return vectors


def installed_models(cfg: Settings) -> list[str]:
    """Model tags Ollama has locally. Used by `/extract/health`."""
    try:
        with urllib.request.urlopen(f"{cfg.ollama_url}/api/tags", timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 -- reported as "down", not raised
        raise LLMError(f"cannot reach Ollama at {cfg.ollama_url}: {exc}") from exc
    return sorted(m.get("model", "") for m in data.get("models", []))
