"""Cleaning free-text that came from somewhere else before it is echoed on.

Engine error text originates in an inference engine's error body -- backend
output that nobody in this project wrote. It travels four ways from there, and
all four end at somebody's terminal:

* the peer returns it on its own `/health` as `detail`;
* the heartbeat carries it to the coordinator, which echoes it to every member
  on `/v1/stats`;
* the peer emits it mid-stream as an `error` frame when an engine fails after
  the status code is already spent;
* the coordinator emits its own `error` frame, which embeds up to 400
  characters of the peer's raw HTTP response body.

So it is sanitised at each point it is *emitted*, not once at some point in the
middle. A backend that puts an ANSI escape, a control character, or a kilobyte
of JSON in an error message must not be able to reach through a diagnostic field
into whoever is reading it.

The last two matter for a second reason as well: an `error` frame is **not**
encrypted -- it has to be readable by a client that may never establish a
session key -- so it crosses the untrusted coordinator in clear. Bounding it
keeps an engine's error body from saying more about a request there than the
receipt already concedes.

Two bounds, because the two fields do different jobs -- see `MAX_MESSAGE_CHARS`.
"""

from __future__ import annotations

MAX_DETAIL_CHARS = 200

# Error frames get a larger bound than `detail`, and the difference is not
# cosmetic. `detail` is a status blurb next to a `healthy` flag that already
# carries the decision; an error frame is the *last* thing a caller gets and has
# to stay actionable on its own. The adapter's reasoning-model guidance -- the
# one message in this project whose whole job is to tell an operator what to do
# next -- is 203 characters, so a 200-character bound truncated the instruction
# and left the diagnosis. 400 matches the cap the adapter already puts on an
# engine's raw error body, so nothing arrives here longer than this by design.
MAX_MESSAGE_CHARS = 400


def _clean(text: object, limit: int) -> str:
    """Printable characters only, whitespace collapsed, bounded length.

    A non-string is not an error worth raising over -- it is a peer sending
    something malformed in an optional diagnostic field, and dropping it is the
    proportionate answer.
    """
    if not isinstance(text, str):
        return ""
    cleaned = " ".join(text.split())
    cleaned = "".join(ch for ch in cleaned if ch.isprintable())
    return cleaned[:limit]


def sanitise_detail(detail: object) -> str:
    """For the `detail` field on a heartbeat and on a peer's `/health`."""
    return _clean(detail, MAX_DETAIL_CHARS)


def sanitise_message(message: object) -> str:
    """For the `message` on a terminal error frame, which must stay actionable."""
    return _clean(message, MAX_MESSAGE_CHARS)
