"""Start portainer-mcp with an additional read-only tool `docker_get`.

`docker_proxy` forwards any HTTP method to the Docker API unless the whole
server runs with PORTAINER_READ_ONLY=1. `docker_get` sends GET requests only,
so one server can serve a read-only agent (`docker_get` and the GET tools) and
a read-write agent (all tools) with the same per-user Portainer key.

For `/containers/{id}/logs` it sets stdout, stderr and tail when the caller
gives none, never follows the stream, and removes Docker's 8-byte frame
headers from multiplexed output. `grep` keeps only the log lines that match a
regular expression; without tail or since it then searches the last
GREP_TAIL lines. Logs longer than LOG_CHARS keep their newest lines: the cap
of portainer-mcp would cut off the end, and its hint (JMESPath `select`) does
not apply to text. LOG_CHARS is below that cap because a few raw logs of
long-line applications fill the context of the model. For `/containers/{id}/stats` it
requests a single sample.
"""

from __future__ import annotations

import os
import re
import struct
from typing import Annotated

from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BeforeValidator, Field

from portainer_mcp import proxy, server
from portainer_mcp.shaping import DEFAULT_MAX_RESPONSE_CHARS, SELECT_DESCRIPTION

DEFAULT_TAIL = "200"
GREP_TAIL = "100000"
LOG_CHARS = 20_000
# Room below the cap of the server for the note in front of the lines.
NOTE_ROOM = 600
_MULTIPLEXED = "application/vnd.docker.multiplexed-stream"


def _demultiplex(data: bytes) -> str:
    """Join the payloads of Docker's stdout/stderr frames.

    Each frame is an 8-byte header (stream type, three zero bytes, payload
    size as big-endian uint32) followed by the payload. Data that does not
    parse as frames is returned unchanged.
    """
    out = bytearray()
    pos = 0
    while pos < len(data):
        if len(data) - pos < 8 or data[pos] not in (0, 1, 2) or data[pos + 1 : pos + 4] != b"\0\0\0":
            return data.decode("utf-8", "replace")
        (size,) = struct.unpack(">I", data[pos + 4 : pos + 8])
        out += data[pos + 8 : pos + 8 + size]
        pos += 8 + size
    return out.decode("utf-8", "replace")


def _max_chars() -> int:
    return int(os.environ.get("PORTAINER_MAX_RESPONSE_CHARS") or DEFAULT_MAX_RESPONSE_CHARS)


def _shape_logs(text: str, pattern: re.Pattern[str] | None) -> str:
    """Filter log lines by `pattern` and keep the newest lines that fit the cap."""
    lines = [line.rstrip("\r") for line in text.split("\n")]
    if lines and lines[-1] == "":
        lines.pop()
    notes = []
    if pattern is not None:
        total = len(lines)
        lines = [line for line in lines if pattern.search(line)]
        notes.append(f"grep {pattern.pattern!r}: {len(lines)} of {total} lines match")
    if not lines:
        if pattern is None:
            notes.append("no log lines in the requested range")
        return "[" + "; ".join(notes) + "]"
    budget = max(min(LOG_CHARS, _max_chars() - NOTE_ROOM), 1000)
    kept, size = [], 0
    for line in reversed(lines):
        size += len(line) + 1
        if size > budget and kept:
            break
        kept.append(line[-budget:])
    kept.reverse()
    if len(kept) < len(lines):
        notes.append(
            f"{len(lines) - len(kept)} older lines omitted, the newest {len(kept)} follow; "
            "narrow with grep (e.g. ERROR|WARN|Exception), since/until or a smaller tail"
        )
    head = "[" + "; ".join(notes) + "]\n" if notes else ""
    return head + "\n".join(kept)


def _query(path: str, query_params: dict[str, str] | None, grep: bool = False) -> dict[str, str]:
    params = dict(query_params or {})
    if path.endswith("/logs"):
        params["follow"] = "false"
        if "stdout" not in params and "stderr" not in params:
            params["stdout"] = params["stderr"] = "true"
        if "tail" not in params and "since" not in params:
            params["tail"] = GREP_TAIL if grep else DEFAULT_TAIL
    if path.endswith("/stats"):
        params["stream"] = "false"
    return params


_register = proxy.register


def register(mcp, client, *, read_only: bool) -> None:
    _register(mcp, client, read_only=read_only)

    @mcp.tool(
        name="docker_get",
        annotations=ToolAnnotations(readOnlyHint=True),
        description=(
            "Read from the Docker Engine API of a Portainer environment (GET only). "
            "The `path` is forwarded to the Docker daemon, e.g. /containers/json, "
            "/containers/{id}/json, /containers/{id}/logs, /containers/{id}/stats, "
            "/images/json, /networks, /volumes. Logs: stdout and stderr and the last "
            f"{DEFAULT_TAIL} lines unless `query_params` set them (tail, since, until as Unix "
            "timestamps, timestamps); the stream is never followed. To find problems in a log, "
            "pass `grep` (e.g. ERROR|WARN|Exception|Caused by) instead of paging through it: "
            f"it searches the last {GREP_TAIL} lines unless tail or since is set and returns "
            "only the matching lines with their count. A log returns at most "
            f"{LOG_CHARS} characters, its newest lines. Stats: a single sample. Pass a JMESPath "
            "`select` to project JSON responses, e.g. for /containers/json with "
            "query_params {\"all\": \"true\", \"filters\": \"{\\\"name\\\": [\\\"web\\\"]}\"} "
            "(every filter value is a list; name matches a part of the name): "
            "`[].{name:Names[0],state:State,status:Status,image:Image}`."
        ),
    )
    async def docker_get(
        environment_id: Annotated[int, Field(description="Portainer environment ID")],
        path: Annotated[
            str, Field(description="Docker API path with leading slash, e.g. /containers/json")
        ],
        query_params: Annotated[
            dict[str, str] | None,
            BeforeValidator(proxy._coerce_param_map),
            Field(description="Query parameters"),
        ] = None,
        select: Annotated[str | None, Field(description=SELECT_DESCRIPTION)] = None,
        grep: Annotated[
            str | None,
            Field(
                description=(
                    "Logs only: regular expression, case-insensitive; returns only the "
                    "matching log lines, e.g. ERROR|WARN|Exception|Caused by"
                )
            ),
        ] = None,
    ) -> str:
        proxy._validate_path(path)
        logs = path.endswith("/logs")
        pattern = None
        if grep:
            if not logs:
                raise ToolError("grep applies only to /containers/{id}/logs; use select for JSON")
            try:
                pattern = re.compile(grep, re.IGNORECASE)
            except re.error as exc:
                raise ToolError(f"invalid grep expression {grep!r}: {exc}") from exc
        response = await client.request(
            "GET",
            f"/endpoints/{environment_id}/docker{path}",
            params=_query(path, query_params, grep=pattern is not None),
        )
        if response.is_error:
            raise ToolError(
                f"docker API request failed (HTTP {response.status_code}) for "
                f"GET {path}: {response.text[:2000]}"
            )
        if logs:
            return _shape_logs(_demultiplex(response.content), pattern)
        if response.headers.get("content-type", "").startswith(_MULTIPLEXED):
            return _demultiplex(response.content)
        return proxy._apply_select(response.text, select)


proxy.register = register

if __name__ == "__main__":
    server.main()
