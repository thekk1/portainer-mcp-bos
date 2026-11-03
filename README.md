# portainer-mcp-bos

[portainer-mcp](https://github.com/portainer/portainer-mcp) 2.45.3 with an additional tool `docker_get`:
reads from the Docker Engine API of a Portainer environment with GET requests only (`bos_get.py`).

`docker_proxy` accepts any HTTP method unless the whole server runs with `PORTAINER_READ_ONLY=1`.
With `docker_get`, one server can serve a read-only agent (`docker_get` and the GET tools) and a
read-write agent (all tools), and each user enters their Portainer API key only once.

- **Logs** (`/containers/{id}/logs`): stdout, stderr and the last 200 lines unless the caller sets
  them; the stream is never followed; Docker's frame headers are removed from multiplexed output.
- **Stats** (`/containers/{id}/stats`): a single sample.

The image is derived from the upstream image (pinned by digest, see `Dockerfile`). `bos_get.py` wraps
`portainer_mcp.proxy.register` and starts the unchanged server; configuration is the same as upstream.

```bash
docker build -t portainer-mcp-bos .
```
