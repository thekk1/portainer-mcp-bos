"""Start portainer-mcp with an additional read-only tool `docker_get`.

`docker_proxy` forwards any HTTP method to the Docker API unless the whole
server runs with PORTAINER_READ_ONLY=1. `docker_get` sends GET requests only,
so one server can serve a read-only agent (`docker_get` and the GET tools) and
a read-write agent (all tools) with the same per-user Portainer key.

For `/containers/{id}/logs` it sets stdout, stderr and tail when the caller
gives none, never follows the stream, and removes Docker's 8-byte frame
headers from multiplexed output. For `/containers/{id}/stats` it requests a
single sample.
"""

from __future__ import annotations

import struct
from typing import Annotated

from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BeforeValidator, Field

from portainer_mcp import proxy, server
from portainer_mcp.shaping import SELECT_DESCRIPTION

DEFAULT_TAIL = "200"
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


def _query(path: str, query_params: dict[str, str] | None) -> dict[str, str]:
    params = dict(query_params or {})
    if path.endswith("/logs"):
        params["follow"] = "false"
        if "stdout" not in params and "stderr" not in params:
            params["stdout"] = params["stderr"] = "true"
        if "tail" not in params and "since" not in params:
            params["tail"] = DEFAULT_TAIL
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
            f"{DEFAULT_TAIL} lines unless `query_params` set them (tail, since, timestamps); "
            "the stream is never followed. Stats: a single sample. Pass a JMESPath "
            "`select` to project JSON responses, e.g. for /containers/json with "
            "query_params {\"all\": \"true\"}: `[].{name:Names[0],state:State,status:Status,image:Image}`."
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
    ) -> str:
        proxy._validate_path(path)
        response = await client.request(
            "GET",
            f"/endpoints/{environment_id}/docker{path}",
            params=_query(path, query_params),
        )
        if response.is_error:
            raise ToolError(
                f"docker API request failed (HTTP {response.status_code}) for "
                f"GET {path}: {response.text[:2000]}"
            )
        if path.endswith("/logs") or response.headers.get("content-type", "").startswith(_MULTIPLEXED):
            return _demultiplex(response.content)
        return proxy._apply_select(response.text, select)


proxy.register = register

if __name__ == "__main__":
    server.main()
