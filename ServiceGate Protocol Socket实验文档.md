# 网络 Socket 编程实验文档

## ServiceGate Protocol 实验说明

### 1. 实验目的

本实验使用 Python 标准库 `socket` 实现一个小型应用层协议 ServiceGate Protocol（SGP）。实验重点不是做一个生产可用的远程调用平台，而是把 TCP 字节流上的几个基本问题做完整：

- 如何在 TCP 上划分消息边界。
- 如何设计固定帧头和 JSON 消息体。
- 如何让 Client、Relay、Agent 三类程序协同工作。
- 如何完成登录、服务发布、服务发现、服务调用和错误返回。
- 如何把具体服务逻辑放到 handler 中，而不是写死在协议或 Relay 里。

### 2. 程序角色

本实验有三个角色：

| 角色 | 程序 | 作用 |
| --- | --- | --- |
| Relay | `relay.py` | 接收 Agent 和 Client 连接，维护服务目录，校验通用权限和 schema，并转发 `CALL` |
| Agent | `agent.py` | 主动连接 Relay，读取配置文件发布服务，并把调用分发给本地 handler |
| Client | `client.py` | 登录 Relay，查看服务列表，并调用某个服务 |

Relay 不执行具体业务逻辑。比如文件读取、命令执行、HTTP 转发都在 Agent 端 handler 中完成。

### 3. 文件结构

| 文件 | 作用 |
| --- | --- |
| `protocol.py` | 帧头编码/解码、消息收发、认证 proof、简化加密、schema 校验和响应构造 |
| `relay.py` | 中继服务，负责登录、服务目录、权限校验、schema 校验、转发和日志 |
| `agent.py` | 服务发布端，读取 `agent.config.json` 和 `services.json`，加载 handler |
| `client.py` | 交互式客户端，支持 `list`、`help <service>`、`text`、`cmd`、`http`、`file` 等命令 |
| `agent.config.example.json` | Agent 配置示例 |
| `client.config.example.json` | Client 配置示例 |
| `services.example.json` | Service 配置示例 |
| `handlers/text_echo.py` | 文本回显 handler |
| `handlers/command_exec.py` | 白名单命令 handler |
| `handlers/http_bundle.py` | HTTP 转发 handler |
| `handlers/file_transfer.py` | 受限文件访问 handler |

### 4. 协议帧格式

SGP 在 TCP 字节流上增加 24 字节帧头：

```text
24 字节 Frame Header + Body
```

帧头字段：

| 字段 | 说明 |
| --- | --- |
| `magic` | 固定为 `SGP1` |
| `major/minor` | 帧格式版本 |
| `header_len` | 当前为 24 |
| `body_type` | `1` 表示 JSON，`2` 表示认证后的加密 JSON |
| `flags/reserved` | 预留字段 |
| `body_len` | body 字节长度，用于处理 TCP 粘包和半包 |
| `seq` | 帧序号，主要用于调试 |
| `header_crc32` | 帧头 CRC32 校验 |

Body 是 JSON，常见字段如下：

```text
version, type, id, role, cmd, token, service_id, payload, status, message, ext
```

其中 `id` 用于匹配请求和响应。

### 5. 核心命令

| 命令 | 用途 |
| --- | --- |
| `HELLO` | 连接后声明角色，Relay 返回 challenge |
| `AUTH` | 使用共享密钥和 challenge 生成 proof 完成登录 |
| `PUBLISH` | Agent 发布服务列表 |
| `LIST` | Client 查询服务列表 |
| `CALL` | Client 调用服务 |
| `PING` | Relay 和 Agent 间的保活 |

协议层命令只有这些。`text.echo`、`command.exec`、`http.bundle`、`file.transfer` 都是服务类型，不是协议命令。

### 6. 服务配置

Agent 不再默认发布服务。要发布什么服务，由 `agent.config.json` 中的 `services_config` 指向的 JSON 文件决定。

一个服务通常包含：

| 字段 | 说明 |
| --- | --- |
| `service_id` | 服务编号，例如 `file-box` |
| `service_type` | 服务类型，例如 `file.transfer` |
| `auth` | 服务访问 token 或 token hash |
| `policy` | payload 大小、超时、调用频率等限制 |
| `endpoints` | HTTP 类服务的 endpoint 配置 |
| `contract` | 输入 schema、输出 schema 和示例 |
| `metadata` | handler 需要的本地配置 |
| `handler` | Agent 本地 Python handler 文件和函数 |

示例：

```json
{
  "service_id": "file-box",
  "service_type": "file.transfer",
  "auth": {
    "access_token": "service-token"
  },
  "metadata": {
    "root_dir": "shared_files",
    "allow_upload": true
  },
  "handler": {
    "path": "handlers/file_transfer.py",
    "function": "handle"
  }
}
```

Relay 会过滤 `auth` 和 `handler`，Client 在 `LIST` 里看不到这些敏感字段。

### 7. 运行方法

准备配置：

```bash
cp agent.config.example.json agent.config.json
cp client.config.example.json client.config.json
cp services.example.json services.json
```

三个终端分别运行：

```bash
python3 relay.py --host 127.0.0.1 --port 9000
python3 agent.py
python3 client.py
```

Agent 会读取 `agent.config.json`。其中 `services_config` 默认指向 `services.json`，所以要发布服务时需要先准备这个文件。

### 8. Client 交互命令

进入 `python3 client.py` 后，可以使用：

```text
sgp> list
sgp> help file-box
sgp> help custom-command
sgp> text hello
sgp> cmd pwd
sgp> http /
sgp> file ls
sgp> file stat hello.txt
sgp> file read hello.txt
sgp> file write upload.txt hello
sgp> generic file-box '{"op":"list","path":"."}'
sgp> quit
```

`help <service_id>` 会显示该服务的可用命令。`generic` 是底层 JSON 调用入口，主要用于调试或调用没有专门客户端命令的服务。

### 9. file-box 说明

`file-box` 使用 `handlers/file_transfer.py`，访问范围由 `services.json` 里的 `metadata.root_dir` 决定：

```json
"metadata": {
  "root_dir": "shared_files",
  "allow_upload": true
}
```

默认情况下，它看到的是 Agent 运行目录下的：

```text
shared_files/
```

例如 Agent 在本项目目录运行，则 `file ls` 看到的是：

```text
/Users/xqqqwq/2026春/homework-2026spring/计网/Socket/shared_files
```

handler 会做路径限制，Client 传入的路径不能逃出这个根目录。

### 10. 已实现功能

当前代码实现了这些实验功能：

- 固定帧头，能处理 TCP 粘包和半包。
- `HELLO -> AUTH` 登录流程。
- 认证成功后发放 session token。
- 认证后的 JSON body 使用简化方式加密和校验。
- Agent 通过配置文件发布服务。
- Client 查询服务列表并在长连接中反复调用服务。
- Service 级 access proof。
- Endpoint 级 access proof。
- Relay 侧 schema 校验。
- Relay 侧 payload 大小限制、调用频率限制和调用超时。
- Relay 对 Agent 做基础保活，Agent 断开后服务会标记为 offline。
- Relay 使用 `id` 匹配同一 Agent 连接上的并发响应。
- Relay 输出 JSON 行日志，便于观察连接、认证、发布、列表和调用过程。

### 11. 没有实现或只做了原型的部分

这些地方不要理解成生产级能力：

- 没有 TLS、证书校验或中间人防护。
- 加密是课程实验用的 HMAC keystream，不是标准 TLS/AEAD。
- 没有 token 轮换、撤销和用户体系。
- 多 Agent 可以同时连接，但同名 `service_id` 会被后发布者覆盖，没有负载均衡。
- 并发是线程模型，没有全局背压、队列控制和压力测试。
- Relay 服务目录只在内存中，重启后会丢失。
- schema 校验只实现常用 JSON Schema 子集。

### 12. 错误响应格式

错误响应仍保留顶层 `status` 和 `message`，并在 `payload.error` 中给出分层错误信息：

```json
{
  "status": 403,
  "message": "SERVICE_TOKEN_INVALID",
  "payload": {
    "error": {
      "layer": "relay",
      "component": "authz",
      "code": "SERVICE_TOKEN_INVALID",
      "message": "Service access proof validation failed."
    }
  }
}
```

错误只描述协议、Relay、Client、Agent 这些层面能确定的事实。Relay 不会声称理解具体 service 内部为什么失败；handler 返回的错误只作为 Agent 层错误透传。

常见层级：

| layer | 含义 |
| --- | --- |
| `protocol` | 帧格式、版本、JSON、加密校验等问题 |
| `relay` | Relay 认证、鉴权、schema、路由、限流、超时 |
| `agent` | Agent 或 handler 返回的问题 |
| `client` | Client 本地配置或输入问题 |

### 13. Relay 日志

Relay 输出一行一个 JSON，例如：

```json
{"ts":1781090000.123,"component":"relay","event":"call_received","id":"...","service_id":"file-box"}
{"ts":1781090000.140,"component":"relay","event":"call_completed","id":"...","service_id":"file-box","status":200,"message":"OK","duration_ms":17}
```

这些日志用于实验观察，不写入文件。需要保存时可以用 shell 重定向：

```bash
python3 relay.py --host 127.0.0.1 --port 9000 > relay.log
```

### 14. 测试建议

建议按下面顺序测试：

| 编号 | 内容 | 预期 |
| --- | --- | --- |
| T1 | 启动 Relay、Agent、Client | Agent 发布 `services.json` 中的服务 |
| T2 | Client 执行 `list` | 显示服务列表和 online 状态 |
| T3 | `help file-box` | 显示文件服务命令 |
| T4 | `file ls` | 列出 `shared_files/` 内容 |
| T5 | `text hello` | 返回文本回显 |
| T6 | `cmd pwd` | 返回命令输出 |
| T7 | 使用错误 service token | 返回 `SERVICE_TOKEN_INVALID`，Agent 不会收到调用 |
| T8 | 输入不符合 schema | 返回 `SCHEMA_VALIDATION_FAILED` |
| T9 | 停止 Agent 后调用 | 返回 `AGENT_OFFLINE` 或服务显示 offline |

### 15. 录屏建议

录屏建议控制在 5 到 8 分钟，重点展示“协议设计和功能确实跑通”，不要把时间花在解释代码细节上。推荐流程如下：

1. 开场展示目录结构和配置文件。
   - 展示 `protocol.py`、`relay.py`、`agent.py`、`client.py`。
   - 展示 `agent.config.json` 中的 `services_config`。
   - 展示 `services.json` 中的 `file-box`、`custom-note`、`custom-command`、`custom-web`，说明具体能力由 handler 提供。

2. 启动 Relay。
   - 运行 `python3 relay.py --host 127.0.0.1 --port 9000`。
   - 说明 Relay 只负责登录、服务目录、校验、转发和日志。
   - 让屏幕中能看到 Relay 输出的 JSON 行日志。

3. 启动 Agent。
   - 运行 `python3 agent.py`。
   - 展示 Agent 加载了几个 handler，并发布了几个服务。
   - 说明 Agent 没有默认发布服务，发布内容来自 `services.json`。

4. 启动 Client 并查看服务。
   - 运行 `python3 client.py`。
   - 输入 `list`。
   - 输入 `help file-box`，展示服务级帮助。
   - 输入 `help custom-command`，展示命令白名单。

5. 演示正常调用。
   - 输入 `text hello`，展示文本回显。
   - 输入 `cmd pwd`，展示白名单命令输出。
   - 先准备 `shared_files/hello.txt`，再输入 `file ls` 和 `file read hello.txt`，展示文件服务。
   - 如果要展示 HTTP 服务，另开终端运行 `python3 -m http.server 8000`，再输入 `http /`。

6. 演示错误处理。
   - 可以另开一个 Client，用错误 `service_token` 调用，展示 `SERVICE_TOKEN_INVALID`。
   - 或输入不符合 schema 的 `generic` 调用，展示 `SCHEMA_VALIDATION_FAILED`。
   - 同时切到 Relay 终端，展示 `call_rejected` 日志。

7. 演示 Agent 离线。
   - 停止 Agent。
   - Client 再执行一次调用或 `list`，观察 offline 或 `AGENT_OFFLINE`。
   - 说明这是 Relay 通过连接关闭和保活维护的生命周期状态。

录屏时建议使用三个终端窗口并排：

```text
左：Relay 日志
中：Agent 日志
右：Client 交互
```

如果有录音，可以按下面的顺序讲：

```text
这个实验实现了一个基于 TCP socket 的应用层协议。TCP 只提供字节流，所以我在 protocol.py 中定义了 24 字节帧头和 JSON body。系统分为 Relay、Agent、Client 三个角色。Agent 主动连接 Relay 并发布 services.json 中的服务，Client 通过 LIST 发现服务，再通过 CALL 调用。Relay 不理解具体业务，只做认证、schema、policy 和路由检查。具体业务由 Agent 端 handler 完成。
```

### 16. LLM 使用说明

本实验开发过程中使用了 LLM 辅助完成部分代码整理、文档润色和调试建议。具体使用方式如下：

- 使用 LLM 协助梳理协议结构，包括 Relay、Agent、Client 的职责划分。
- 使用 LLM 辅助生成和修改部分 Python 代码，例如 client 交互命令、handler 拆分、错误格式整理和日志格式整理。
- 使用 LLM 辅助检查 README 和实验文档中与当前实现不一致的表述。
- 使用 LLM 辅助设计录屏流程和测试顺序。

本人完成和确认的部分包括：

- 确定协议应用场景和最终功能范围。
- 决定使用 Relay 中继模型，以及 Service、handler、contract、policy 等核心抽象。
- 运行和验证 Relay、Agent、Client 的端到端流程。
- 根据实际运行结果修正文档中夸大或不准确的描述。
- 对最终提交内容进行检查，确保本地配置文件和 token 不被提交。

### 17. 小结

这个实验实现的是一个可观察、可扩展的 socket 协议原型。它展示了应用层协议如何处理消息边界、登录认证、服务目录、调用转发、基础权限控制和错误返回。当前版本适合作为课程实验和演示，不适合作为真实公网生产系统使用。
