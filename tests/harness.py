"""Run coordinator and peer as real HTTP servers on ephemeral ports.

Deliberately not ASGI-transport shortcuts: the properties under test are
streaming, chunk ordering, and relay failure behaviour, all of which live in
the actual HTTP path.
"""

from __future__ import annotations

import asyncio
import socket
from contextlib import asynccontextmanager

import uvicorn


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@asynccontextmanager
async def serve(app, port: int):
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    try:
        for _ in range(200):
            if server.started:
                break
            await asyncio.sleep(0.02)
        else:
            raise RuntimeError(f"server on port {port} did not start")
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(task, timeout=5)
        except (TimeoutError, asyncio.TimeoutError):
            task.cancel()
