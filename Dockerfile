# portainer-mcp 2.45.3 with the read-only tool docker_get (bos_get.py). bos_get.py wraps the
# proxy registration of the package and then starts the unchanged server.
FROM portainer/portainer-mcp@sha256:3849b2d5d910644b45a2c3dd6facf2b7857d9d22e68059d94139191c390ff7ad
COPY bos_get.py /app/bos_get.py
ENTRYPOINT ["python", "/app/bos_get.py"]
