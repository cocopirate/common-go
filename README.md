# common-go

`common-go` 存放 OpenGo 各 Go 服务共享的基础库。这里的代码只提供通用基础设施能力，不依赖任何业务服务，也不包含项目专属规则。

本目录采用多 Go module 组织，每个子目录都是可独立发布和被服务引用的包；根目录通过 `go.work` 方便本地联调。

## 包列表

| 包 | 说明 |
| --- | --- |
| `authx` | JWT claims、身份透传 header、角色和权限辅助方法。 |
| `bootstrap` | 服务启动、关闭和通用生命周期封装。 |
| `configx` | 环境变量读取与配置校验辅助方法：收敛各服务重复的私有 `getEnv` 家族与生产弱密钥校验。刻意保留几处语义分裂（如 `GetEnvSeconds` 是否钳制非正值），由调用方显式选择而非静默统一。 |
| `dbx` | 数据库连接、GORM 配置和迁移辅助能力。 |
| `endpointx` | 服务间地址表（`SERVICE_URLS`）的解析与启动校验：三态语义（未配置 / 可用 / 显式关闭）、封闭名字词表、按服务声明的 Required/Optional。零第三方依赖。 |
| `exportx` | 导出文件的通用机械部分：CSV 骨架（UTF-8 BOM、行数上限与截断提示）、固定 +08:00 时间渲染、日期文件名、Excel 文本包装。 |
| `gwclient` | 通知网关重载公共路由（`POST /internal/gateway/reload`），带 3 次退避重试与失败状态码上报。 |
| `httpx` | HTTP server、Gin middleware、统一响应和公开路由辅助能力。 |
| `jobx` | 后台任务队列的通用机械部分：任务模型与状态、认领（FOR UPDATE SKIP LOCKED）、重试与退避、进度上报、产物描述符、任务查询/取消的 gin handler。任务类型、payload、权限与数据范围规则留在业务服务。 |
| `logx` | Zap 日志初始化和日志字段辅助方法。 |
| `ossx` | 阿里云 OSS 签名 URL 与公共域名 URL 辅助方法。 |
| `redisx` | Redis client 创建和配置辅助方法。 |
| `taskbus` | RabbitMQ 任务总线契约：服务间只交换稳定的 JSON 命令，exchange 声明、publisher confirm、重试队列与死信路由都藏在包内。 |
| `telemetry` | Request ID、指标、OpenTelemetry 和 Gin span 支持。 |
| `yop` | 易宝 YOP OpenAPI 客户端与 Yop-Auth-V2（RSA2048-SHA256）签名。 |

## 目录结构

```text
authx/       # 认证与身份辅助包
bootstrap/   # 服务生命周期辅助包
configx/     # 环境变量与配置校验辅助包
dbx/         # 数据库与迁移辅助包
endpointx/   # 服务间地址表解析与启动校验辅助包
exportx/     # 导出文件机械部分辅助包
gwclient/    # 网关重载通知辅助包
httpx/       # HTTP 服务、响应与中间件辅助包
jobx/        # 后台任务队列辅助包
logx/        # 日志辅助包
ossx/        # 阿里云 OSS 辅助包
redisx/      # Redis 辅助包
taskbus/     # RabbitMQ 任务总线辅助包
telemetry/   # 链路追踪与指标辅助包
yop/         # 易宝 YOP OpenAPI 辅助包
go.work      # 本地多模块工作区
```

## 使用边界

- 可以放跨服务复用的基础设施代码，例如日志、数据库、HTTP、Redis、鉴权和观测能力。
- 不要依赖 `base-service`、`shan-go` 或任何业务服务。
- 不要放业务模型、项目字段、项目路由、供应商专属业务流程。
- 包 API 应保持小而稳定，避免为了单个服务的临时需求扩大公共接口。

## 本地开发

在 `common-go` 目录下运行测试（注意逐个模块列出：`./...` 在 workspace 根目录不可用，因为根目录本身不是 module）：

```bash
go test ./authx/... ./bootstrap/... ./configx/... ./dbx/... ./endpointx/... ./exportx/... \
  ./gwclient/... ./httpx/... ./jobx/... ./logx/... ./ossx/... ./redisx/... \
  ./taskbus/... ./telemetry/... ./yop/...
```

也可以进单个模块目录跑，那也是验证"独立发布后消费者能否构建"的方式：

```bash
cd configx && GOWORK=off go build ./... && GOWORK=off go test ./...
```

格式化变更过的包：

```bash
gofmt -l .   # 列出未格式化的文件；注意 yop/ 有历史遗留未格式化文件
```

服务仓库通过 `go.work` 中的 `replace` 指向本地 `common-go` 包，方便联调。独立发布时，请为变更的包打版本标签，并在服务仓库中升级依赖版本，避免长期依赖本地 `replace`。

## 变更建议

- 修改公共函数签名前，先搜索所有服务调用方。
- 新增公共能力时，优先补充最小可验证测试。
- 影响中间件、鉴权、数据库连接或观测行为时，应在引用服务中运行对应 `go test ./...`。
- 对外行为变化需要同步更新服务 README 或接口文档。
