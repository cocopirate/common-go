# common-go

Shared Go packages for OpenGo services.

This repository contains reusable infrastructure code only. It must not depend on any business service or project repository.

## Packages

| Package | Purpose |
| --- | --- |
| `authx` | JWT claims, identity headers, role and permission helpers |
| `bootstrap` | Common service bootstrap lifecycle |
| `dbx` | Database and migration helpers |
| `httpx` | HTTP server, middleware, and response helpers |
| `logx` | Logging helpers |
| `redisx` | Redis client helpers |
| `telemetry` | Request IDs, metrics, and OpenTelemetry setup |

## Development

```bash
go test ./authx/... ./bootstrap/... ./dbx/... ./httpx/... ./logx/... ./redisx/... ./telemetry/...
```

When this repository is published independently, tag releases and consume them from service repositories instead of using local `replace` directives.
