"""Start portainer-mcp with an additional read-only tool `docker_get`.

`docker_proxy` forwards any HTTP method to the Docker API unless the whole
server runs with PORTAINER_READ_ONLY=1. `docker_get` sends GET requests only,
so one server can serve a read-only agent (`docker_get` and the GET tools) and
a read-write agent (all tools) with the same per-user Portainer key.

For `/containers/{id}/logs` it sets stdout, stderr and tail when the caller
gives none, never follows the stream, and removes Docker's 8-byte frame
headers from multiplexed output. `grep` keeps only the log lines that match a
regular expression; without tail or since it then searches the last
GREP_TAIL lines. tail, since and until may also be passed as arguments of
their own; since and until take Unix seconds, RFC 3339 or a duration back from
now, and Docker gets Unix seconds. Docker applies tail to the whole log before
since and until, so a window with tail comes back empty unless it lies at the
end; with since or until `docker_get` therefore leaves tail out of the request
and keeps the last lines of the window itself. until without since searches
the UNTIL_WINDOW seconds before until. An empty log range names its period as UTC
dates, so that a wrongly computed timestamp shows. Values of command-line
options and assignments whose name contains passw, secret, token, credential
or api/private/encryption key, `unencrypted:` values, Bearer and Basic tokens
and passwords in URLs are replaced with [REDACTED], as portainer-mcp does for
env values; PORTAINER_EXPOSE_ENV_VALUES=1 disables both. Logs longer than LOG_CHARS keep their newest lines: the cap
of portainer-mcp would cut off the end, and its hint (JMESPath `select`) does
not apply to text. LOG_CHARS is below that cap because a few raw logs of
long-line applications fill the context of the model. For `/containers/{id}/stats` it
requests a single sample.

For `/events` it sets `until` to now when the caller gives none or a time in the
future: Docker would otherwise keep the stream open until then. Docker sends one JSON object per line; `docker_get` returns them as a
list, so that `select` applies. Docker keeps only the last EVENTS_KEPT events of
a host in memory, on a busy host less than an hour. A second request reads that
buffer, and a note in front of the result names its oldest event; if the
requested period starts earlier, the note says that older events are lost.

An empty result of StackList gets a note in front: Portainer lists only the
stacks the account may see, and an empty list was read as "no stacks".
"""

from __future__ import annotations

import json
import os
import re
import struct
import time
from datetime import datetime, timezone
from typing import Annotated

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from mcp.types import TextContent, ToolAnnotations
from pydantic import BeforeValidator, Field

from portainer_mcp import proxy, redaction, server
from portainer_mcp.shaping import DEFAULT_MAX_RESPONSE_CHARS, SELECT_DESCRIPTION

DEFAULT_TAIL = "200"
GREP_TAIL = "100000"
UNTIL_WINDOW = 86400
LOG_CHARS = 20_000
# Room below the cap of the server for the note in front of the lines.
NOTE_ROOM = 600
_MULTIPLEXED = "application/vnd.docker.multiplexed-stream"
# Size of the event buffer of the Docker daemon (eventsLimit in daemon/events).
EVENTS_KEPT = 256
_DURATION = re.compile(r"(\d+(?:\.\d+)?)(h|m|s)")
_SECRET_NAME = r"[\w.-]*(?:passw|pwd|secret|token|credential|api_?key|private_?key|encryption_?key)[\w.-]*"
_SECRETS = [
    (re.compile(r"(?i)\b(" + _SECRET_NAME + r")(\"?\s*[=:]\s*)(?!\[REDACTED\])(\"[^\"]*\"|'[^']*'|[^\s,;&\"']+)"), r"\1\2[REDACTED]"),
    (re.compile(r"(?i)\bunencrypted:(?!\[REDACTED\])\S+"), "unencrypted:[REDACTED]"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)[^/\s@]+@"), r"\1[REDACTED]@"),
]


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


def _redact(line: str) -> str:
    """Replace secrets in a log line with redaction.SENTINEL."""
    for pattern, replacement in _SECRETS:
        line = pattern.sub(replacement, line)
    return line


def _iso(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _period(params: dict[str, str]) -> str | None:
    """The since/until of a log request as UTC dates, None without both."""
    if "since" not in params and "until" not in params:
        return None
    since = _iso(float(params["since"])) if "since" in params else "start"
    until = _iso(float(params["until"])) if "until" in params else "now"
    return f"period {since} to {until}"


def _shape_logs(
    text: str, pattern: re.Pattern[str] | None, period: str | None = None, tail: int | None = None
) -> str:
    """Keep the last `tail` lines, filter them by `pattern`, redact secrets and keep the newest
    lines that fit the cap."""
    lines = [line.rstrip("\r") for line in text.split("\n")]
    if lines and lines[-1] == "":
        lines.pop()
    if tail is not None:
        lines = lines[-tail:] if tail > 0 else []
    notes = []
    total = len(lines)
    if pattern is not None:
        lines = [line for line in lines if pattern.search(line)]
        notes.append(f"grep {pattern.pattern!r}: {len(lines)} of {total} lines match")
    if not lines:
        if pattern is None:
            notes.append("no log lines in the requested range")
        if total == 0 and period:
            notes.append(period)
        return "[" + "; ".join(notes) + "]"
    if not redaction.is_expose_enabled():
        lines = [_redact(line) for line in lines]
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


def _parse_events(text: str) -> list | None:
    """Parse Docker's newline-delimited JSON events; None if a line is no JSON."""
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            return None
    return events


def _timestamp(value: str | None, now: float) -> float | None:
    """Docker's since/until: Unix seconds, RFC 3339 or a duration back from now."""
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        pass
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        pass
    else:
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    parts = _DURATION.findall(value)
    if parts and "".join(n + u for n, u in parts) == value:
        factor = {"h": 3600, "m": 60, "s": 1}
        return now - sum(float(n) * factor[u] for n, u in parts)
    return None


def _events_note(kept: list, since: float | None, now: float) -> str:
    """Name the oldest event Docker still keeps and whether the period starts before it."""
    if not kept:
        return "[Docker keeps no events of this host.]"
    oldest = min(e.get("time", now) for e in kept)
    stamp = datetime.fromtimestamp(oldest, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    minutes = max(int((now - oldest) // 60), 0)
    if len(kept) < EVENTS_KEPT:
        return (
            f"[Docker keeps {len(kept)} events of this host, all since its start; the oldest is "
            f"from {stamp} ({minutes} minutes ago).]"
        )
    note = (
        f"[Docker keeps only the last {EVENTS_KEPT} events of this host; the oldest is from "
        f"{stamp} ({minutes} minutes ago)."
    )
    if since is None or since < oldest:
        note += (
            " The requested period starts earlier: events before that time are lost, so a "
            "missing event does not mean that nothing happened. For a longer history read "
            "State and RestartCount from /containers/{id}/json and the log."
        )
    return note + "]"


def _query(path: str, query_params: dict[str, str] | None, grep: bool = False) -> dict[str, str]:
    params = dict(query_params or {})
    if path.endswith("/logs") or path == "/events":
        now = time.time()
        for key in ("since", "until"):
            if key in params:
                value = _timestamp(params[key], now)
                if value is None:
                    raise ToolError(
                        f"{key} {params[key]!r}: give Unix seconds, RFC 3339 "
                        "(e.g. 2026-01-31T14:30:00Z) or a duration back from now (e.g. 2h)"
                    )
                params[key] = f"{value:.0f}"
    if path.endswith("/logs"):
        params["follow"] = "false"
        if "tail" in params:
            params["tail"] = params["tail"].strip("\"' ")
        if "stdout" not in params and "stderr" not in params:
            params["stdout"] = params["stderr"] = "true"
        if "until" in params and "since" not in params:
            params["since"] = str(int(params["until"]) - UNTIL_WINDOW)
        if "tail" not in params and "since" not in params:
            params["tail"] = GREP_TAIL if grep else DEFAULT_TAIL
    if path.endswith("/stats"):
        params["stream"] = "false"
    if path == "/events":
        now = time.time()
        until = _timestamp(params.get("until"), now)
        if until is None or until > now:
            params["until"] = str(int(now))
    return params


STACKS_NOTE = (
    "[StackList shows only the stacks this account may see; an empty list does not mean "
    "that there are no stacks.]"
)


class EmptyStackListNote(Middleware):
    """Put STACKS_NOTE in front of an empty StackList result."""

    async def on_call_tool(self, context: MiddlewareContext, call_next: CallNext):
        result = await call_next(context)
        if context.message.name != "StackList":
            return result
        texts = [getattr(item, "text", None) for item in result.content]
        if all(isinstance(text, str) and text.strip() in ("", "[]", "null") for text in texts):
            # structured_content stays: a client checks it against the output schema.
            result.content = [TextContent(type="text", text=STACKS_NOTE + "\n[]")]
        return result


_register = proxy.register


def register(mcp, client, *, read_only: bool) -> None:
    _register(mcp, client, read_only=read_only)
    mcp.add_middleware(EmptyStackListNote())

    @mcp.tool(
        name="docker_get",
        annotations=ToolAnnotations(readOnlyHint=True),
        description=(
            "Read from the Docker Engine API of a Portainer environment (GET only). "
            "The `path` is forwarded to the Docker daemon, e.g. /containers/json, "
            "/containers/{id}/json, /containers/{id}/logs, /containers/{id}/stats, "
            "/images/json, /networks, /volumes. Logs: stdout and stderr and the last "
            f"{DEFAULT_TAIL} lines unless set (tail, since, until, as arguments or in "
            "`query_params`; since and until as RFC 3339 like 2026-01-31T14:30:00Z, Unix "
            "seconds or a duration like 2h; tail then counts from the end of that period, until "
            f"alone searches the {UNTIL_WINDOW // 3600} hours before it); the stream is never "
            "followed. An empty range names its period. Secrets in log lines come back as [REDACTED]. To find problems "
            "in a log, "
            "pass `grep` (e.g. ERROR|WARN|Exception|Caused by) instead of paging through it: "
            f"it searches the last {GREP_TAIL} lines unless tail or since is set and returns "
            "only the matching lines with their count. A log returns at most "
            f"{LOG_CHARS} characters, its newest lines. Stats: a single sample. Events: until "
            f"is at most now; Docker keeps only the last {EVENTS_KEPT} events of a host, the "
            "result starts with the time of the oldest one. Pass a JMESPath "
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
        tail: Annotated[
            str | int | None, Field(description="Logs: number of lines from the end")
        ] = None,
        since: Annotated[
            str | int | None,
            Field(description="Logs and events: start, RFC 3339 (UTC with Z), Unix seconds or a duration like 2h"),
        ] = None,
        until: Annotated[
            str | int | None,
            Field(description="Logs and events: end, RFC 3339 (UTC with Z), Unix seconds or a duration like 30m"),
        ] = None,
    ) -> str:
        proxy._validate_path(path)
        logs = path.endswith("/logs")
        extra = {k: str(v).strip("\"' ") for k, v in (("tail", tail), ("since", since), ("until", until)) if v is not None}
        if extra:
            query_params = {**extra, **(query_params or {})}
        pattern = None
        if grep:
            if not logs:
                raise ToolError("grep applies only to /containers/{id}/logs; use select for JSON")
            try:
                pattern = re.compile(grep, re.IGNORECASE)
            except re.error as exc:
                raise ToolError(f"invalid grep expression {grep!r}: {exc}") from exc
        params = _query(path, query_params, grep=pattern is not None)
        window_tail = None
        if logs and "since" in params and "tail" in params:
            value = params.pop("tail")
            window_tail = int(value) if value.isdigit() else None
        response = await client.request(
            "GET", f"/endpoints/{environment_id}/docker{path}", params=params
        )
        if response.is_error:
            raise ToolError(
                f"docker API request failed (HTTP {response.status_code}) for "
                f"GET {path}: {response.text[:2000]}"
            )
        if logs:
            return _shape_logs(_demultiplex(response.content), pattern, _period(params), window_tail)
        if path == "/events":
            return await _events(client, environment_id, response.text, query_params, select)
        if response.headers.get("content-type", "").startswith(_MULTIPLEXED):
            return _demultiplex(response.content)
        return proxy._apply_select(response.text, select)


async def _events(client, environment_id: int, text: str, query_params, select) -> str:
    events = _parse_events(text)
    if events is None:
        return proxy._apply_select(text, select)
    now = time.time()
    params = _query("/events", query_params)
    kept_response = await client.request(
        "GET", f"/endpoints/{environment_id}/docker/events", params={"until": params["until"]}
    )
    kept = None if kept_response.is_error else _parse_events(kept_response.text)
    if kept is None:
        note = f"[Docker keeps only the last {EVENTS_KEPT} events of this host; their age is unknown.]"
    else:
        note = _events_note(kept, _timestamp(params.get("since"), now), now)
    return note + "\n" + proxy._apply_select(json.dumps(events), select)


proxy.register = register

if __name__ == "__main__":
    server.main()
