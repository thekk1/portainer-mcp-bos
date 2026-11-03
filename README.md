# portainer-mcp-bos

[portainer-mcp](https://github.com/portainer/portainer-mcp) 2.45.3 with an additional tool `docker_get`:
reads from the Docker Engine API of a Portainer environment with GET requests only (`bos_get.py`).

`docker_proxy` accepts any HTTP method unless the whole server runs with `PORTAINER_READ_ONLY=1`.
With `docker_get`, one server can serve a read-only agent (`docker_get` and the GET tools) and a
read-write agent (all tools), and each user enters their Portainer API key only once.

- **Logs** (`/containers/{id}/logs`): stdout, stderr and the last 200 lines unless the caller sets
  them; the stream is never followed; Docker's frame headers are removed from multiplexed output.
  - `grep` (regular expression, case-insensitive) returns only the matching lines and their count;
    without `tail` or `since` it searches the last 100000 lines.
  - A log returns at most 20000 characters, its newest lines with a note in front. The cap of the
    server (`PORTAINER_MAX_RESPONSE_CHARS`, default 50000) would keep the oldest lines and suggest
    a JMESPath `select`, which does not apply to text; three raw logs of an application with long
    lines at that size took a subagent past 100000 tokens of context.
- **Stats** (`/containers/{id}/stats`): a single sample.

The image is derived from the upstream image (pinned by digest, see `Dockerfile`). `bos_get.py` wraps
`portainer_mcp.proxy.register` and starts the unchanged server; configuration is the same as upstream.

```bash
docker build -t portainer-mcp-bos .
```
