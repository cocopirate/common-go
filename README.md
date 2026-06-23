# common-go

`common-go` 存放 OpenGo 各 Go 服务共享的基础库。这里的代码只提供通用基础设施能力，不依赖任何业务服务，也不包含项目专属规则。

本目录采用多 Go module 组织，每个子目录都是可独立发布和被服务引用的包；根目录通过 `go.work` 方便本地联调。

## 包列表

| 包 | 说明 |
| --- | --- |
| `authx` | JWT claims、身份透传 header、角色和权限辅助方法。 |
| `bootstrap` | 服务启动、关闭和通用生命周期封装。 |
| `dbx` | 数据库连接、GORM 配置和迁移辅助能力。 |
| `httpx` | HTTP server、Gin middleware、统一响应和公开路由辅助能力。 |
| `logx` | Zap 日志初始化和日志字段辅助方法。 |
| `redisx` | Redis client 创建和配置辅助方法。 |
| `telemetry` | Request ID、指标、OpenTelemetry 和 Gin span 支持。 |

## 目录结构

```text
authx/       # 认证与身份辅助包
bootstrap/   # 服务生命周期辅助包
dbx/         # 数据库与迁移辅助包
httpx/       # HTTP 服务、响应与中间件辅助包
logx/        # 日志辅助包
redisx/      # Redis 辅助包
telemetry/   # 链路追踪与指标辅助包
go.work      # 本地多模块工作区
```

## 使用边界

- 可以放跨服务复用的基础设施代码，例如日志、数据库、HTTP、Redis、鉴权和观测能力。
- 不要依赖 `base-service`、`shan-go` 或任何业务服务。
- 不要放业务模型、项目字段、项目路由、供应商专属业务流程。
- 包 API 应保持小而稳定，避免为了单个服务的临时需求扩大公共接口。

## 本地开发

在 `common-go` 目录下运行测试：

```bash
go test ./authx/... ./bootstrap/... ./dbx/... ./httpx/... ./logx/... ./redisx/... ./telemetry/...
```

格式化变更过的包：

```bash
go fmt ./authx/... ./bootstrap/... ./dbx/... ./httpx/... ./logx/... ./redisx/... ./telemetry/...
```

服务仓库通过 `go.work` 中的 `replace` 指向本地 `common-go` 包，方便联调。独立发布时，请为变更的包打版本标签，并在服务仓库中升级依赖版本，避免长期依赖本地 `replace`。

## 变更建议

- 修改公共函数签名前，先搜索所有服务调用方。
- 新增公共能力时，优先补充最小可验证测试。
- 影响中间件、鉴权、数据库连接或观测行为时，应在引用服务中运行对应 `go test ./...`。
- 对外行为变化需要同步更新服务 README 或接口文档。
