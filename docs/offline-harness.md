# Offline Harness

Use this harness when you want to inspect the API and UI without allowing the
containers to reach the public internet or configured targets.

```bash
docker compose -f docker-compose.offline.yml up --build
```

The compose file uses an internal Docker network and binds the web UI only to
`127.0.0.1:8000`. It mounts `config.offline.yaml` and
`fixtures/simulation/`, so runner and pivot output is served from local fixture
files instead of real subprocess or internet calls.

The default offline target is `example.invalid`. Manual runs for `subfinder`
and `crtsh` are safe in this mode; they should ingest the fixture hostnames and
enqueue `dns_resolve` pivots, which the pivot worker resolves from the DNS
fixture.

Notes:

- The first build still needs the base images and tool downloads referenced by
  the Dockerfile. If those images and layers are not already cached locally,
  Docker cannot build this harness without temporary registry access.
- Simulation mode skips the startup CISA KEV refresh and scheduled KEV refresh.
- Do not use the checked-in `config.yaml` for isolated testing; it contains
  enabled public targets and discovery runners.
