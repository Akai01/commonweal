"""Cleaning free-text that came from somewhere else before it is echoed on.

`detail` strings originate in an inference engine's error body -- backend output
that nobody in this project wrote. They travel two ways from there, and both end
at somebody's terminal: the peer returns one on its own `/health`, and the
heartbeat carries one to the coordinator, which echoes it to every member on
`/v1/stats`.

So it is sanitised at each point it is *emitted*, not once at some point in the
middle. A backend that puts an ANSI escape, a control character, or a kilobyte
of JSON in an error message must not be able to reach through a diagnostic field
into whoever is reading it.
"""

from __future__ import annotations

MAX_DETAIL_CHARS = 200


def sanitise_detail(detail: object) -> str:
    """Printable characters only, whitespace collapsed, bounded length.

    A non-string is not an error worth raising over -- it is a peer sending
    something malformed in an optional diagnostic field, and dropping it is the
    proportionate answer.
    """
    if not isinstance(detail, str):
        return ""
    cleaned = " ".join(detail.split())
    cleaned = "".join(ch for ch in cleaned if ch.isprintable())
    return cleaned[:MAX_DETAIL_CHARS]
