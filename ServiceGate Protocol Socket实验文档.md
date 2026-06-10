# 网络 Socket 编程实验文档

## ServiceGate Protocol 实验说明

### 1. 实验目的

本实验使用 Python 标准库 `socket` 实现一个简单的应用层协议 ServiceGate Protocol（SGP）。主要目的如下：

- 练习 TCP socket 编程，理解 TCP 是字节流，需要应用层自己处理消息边界。
- 设计一个有固定帧头和 JSON 消息体的应用层协议。
- 实现一个中继 Relay、一个服务发布端 Agent、一个服务调用端 Client。
- 演示认证、服务发布、服务发现、服务调用和几种错误处理情况。

### 2. 应用场景

实验假设有两台设备：

- 一台内网中的主机运行 Agent，发布本机可用服务。
- 另一台设备运行 Client，通过 Relay 查看服务并发起调用。

这样设计主要是为了模拟“内网机器主动连出，中继服务器负责转发”的场景。实验中默认在本机用多个终端模拟这三类程序。

### 3. 程序结构

| 文件 | 作用 |
| --- | --- |
| `protocol.py` | 负责帧头编码/解码、JSON 收发、认证 proof、简单加密、schema 校验和响应构造 |
| `relay.py` | 中继服务器，维护登录 session、服务列表、调用转发、保活状态 |
| `agent.py` | 服务发布端，登录 Relay 后发布示例服务，并处理 Relay 转发来的 `CALL` |
| `client.py` | 服务调用端，登录 Relay 后执行 `LIST` 或 `CALL` |
| `services.example.json` | 自定义服务配置示例 |
| `handlers/file_transfer.py` | 自定义文件服务 handler 示例 |

### 4. 协议帧格式

SGP 在 TCP 字节流上增加固定 24 字节帧头：

```text
24 字节 Frame Header + Body
```

帧头字段如下：

| 字段 | 说明 |
| --- | --- |
| `magic` | 固定为 `SGP1`，用于识别协议帧 |
| `major/minor` | 帧格式版本 |
| `header_len` | 当前为 24 |
| `body_type` | `1` 为 JSON，`2` 为认证后的加密 JSON |
| `flags/reserved` | 预留字段 |
| `body_len` | body 字节长度，用于处理粘包和半包 |
| `seq` | 帧序号，主要用于调试 |
| `header_crc32` | 帧头校验 |

Body 使用 JSON，常见字段包括：

```text
version, type, id, role, cmd, token, service_id, payload, status, message, ext
```

其中 `id` 用来匹配请求和响应。

### 5. 核心命令

| 命令 | 用途 |
| --- | --- |
| `HELLO` | 连接后声明角色，Relay 返回 challenge |
| `AUTH` | 使用共享密钥派生的 proof 登录 |
| `PUBLISH` | Agent 发布服务列表 |
| `LIST` | Client 查询服务列表 |
| `CALL` | Client 调用某个服务 |
| `PING` | 保活 |

### 6. 服务模型

Agent 发布的每个服务包含这些信息：

| 字段 | 说明 |
| --- | --- |
| `service_id` | 服务编号 |
| `service_type` | 服务类型，例如 `text.echo`、`command.exec`、`http.bundle` |
| `auth` | 服务级访问 token 的哈希 |
| `policy` | payload 大小、超时、调用频率等限制 |
| `endpoints` | 可选，HTTP 服务中用于表示不同入口 |
| `contract` | 输入输出 schema 和示例 |
| `metadata` | 服务实现需要的本地配置 |

目前内置了三个服务：

| Service | 作用 |
| --- | --- |
| `note-box` | 回显短文本 |
| `win-command` | 执行白名单命令 |
| `frontend-workspace` | 访问本机 HTTP endpoint |

### 7. 已实现功能

本实验原型实现了以下功能：

- 固定帧头，能处理 TCP 粘包/半包。
- `HELLO -> AUTH` 登录流程。
- 认证成功后发放 session token。
- 认证后消息体加密，抓包时不直接看到 JSON 明文。
- Agent 通过 `PUBLISH` 发布服务。
- Client 通过 `LIST` 查询服务。
- Client 通过 `CALL` 调用服务。
- Service 级 access proof。
- HTTP endpoint 可选 endpoint 级 access proof。
- Service `contract.input_schema` 校验。
- payload 大小限制、调用频率限制、调用超时。
- Agent 断开后服务标记为 offline。
- Relay 对空闲 Agent 发送 `PING` 保活。
- 多个 Client 可以同时发起调用；同一 Agent 连接上用消息 `id` 匹配并发响应。

这些功能主要是为了实验展示，不代表已经达到生产环境安全或稳定性要求。

### 8. 基本交互流程

Agent 上线：

```text
Agent -> Relay: TCP connect
Agent -> Relay: HELLO(role=agent)
Relay -> Agent: HELLO_OK(challenge)
Agent -> Relay: AUTH(auth_proof)
Relay -> Agent: AUTH_OK(token)
Agent -> Relay: PUBLISH(services)
Relay -> Agent: PUBLISH_OK
```

Client 查询服务：

```text
Client -> Relay: TCP connect
Client -> Relay: HELLO(role=client)
Relay -> Client: HELLO_OK(challenge)
Client -> Relay: AUTH(auth_proof)
Relay -> Client: AUTH_OK(token)
Client -> Relay: LIST
Relay -> Client: services[]
```

Client 调用服务：

```text
Client -> Relay: CALL(service_id, access_proof, input)
Relay: 校验 session、service_id、token proof、schema、policy、在线状态
Relay -> Agent: CALL(service_id, input)
Agent -> Relay: CALL result
Relay -> Client: CALL result
```

### 9. 运行方法

在三个终端中分别运行：

```bash
python3 relay.py --host 127.0.0.1 --port 9000
python3 agent.py --relay-host 127.0.0.1 --relay-port 9000
python3 client.py --relay-host 127.0.0.1 --relay-port 9000
```

也可以使用非交互命令：

| 目的 | 命令 |
| --- | --- |
| 查询服务列表 | `python3 client.py --list` |
| 调用文本服务 | `python3 client.py --call text --text "hello"` |
| 调用命令服务 | `python3 client.py --call command --command "pwd"` |
| 调用 HTTP page endpoint | `python3 client.py --call http --endpoint page --path /` |
| 调用 HTTP api endpoint | `python3 client.py --call http --endpoint api --endpoint-token endpoint-token --path /` |
| 错误 Service token | `python3 client.py --call text --service-token wrong-token --text "fail"` |
| 不存在的服务 | `python3 client.py --call text --service-id missing-service --text "fail"` |

如果要测试 HTTP 服务，可以先启动：

```bash
python3 -m http.server 8000
python3 -m http.server 3000
```

### 10. 扩展服务

可以复制示例配置：

```bash
cp services.example.json services.json
python3 agent.py --relay-host 127.0.0.1 --relay-port 9000 --services-config services.json
```

`services.example.json` 中包含一个 `file.transfer` 示例。它通过 `handler` 指定本地 Python 文件：

```json
{
  "handler": {
    "path": "handlers/file_transfer.py",
    "function": "handle"
  }
}
```

Relay 不执行 handler，也不理解文件服务细节，只负责检查通用认证、schema、policy，然后把调用转发给 Agent。

### 11. 测试情况

本实验中主要测试了以下情况：

| 编号 | 测试内容 | 预期现象 |
| --- | --- | --- |
| T1 | Relay、Agent、Client 正常启动 | 能完成 `HELLO`、`AUTH`、`PUBLISH` |
| T2 | Client 执行 `LIST` | 返回服务列表，包含 `online` 和 `lifecycle` |
| T3 | 调用 `note-box` | 返回文本回显 |
| T4 | 调用 `win-command` 的 `pwd` | 返回命令输出 |
| T5 | 错误 Service token | 返回 `403 SERVICE_TOKEN_INVALID` |
| T6 | 不存在的服务 | 返回 `404 SERVICE_NOT_FOUND` |
| T7 | Agent 停止后调用服务 | 返回 `503 AGENT_OFFLINE`，服务列表显示 offline |
| T8 | 输入不符合 schema | 返回 `400 SCHEMA_VALIDATION_FAILED` |
| T9 | 错误 endpoint token | 返回 `403 ENDPOINT_TOKEN_INVALID` |
| T10 | 多个 Client 同时调用 | 多个请求都能按各自 `id` 返回 |

### 12. 错误响应格式

错误响应保留 `status` 和 `message`，同时在 `payload.error` 中给出补充信息，例如：

```json
{
  "status": 403,
  "message": "SERVICE_TOKEN_INVALID",
  "payload": {
    "error": {
      "code": "SERVICE_TOKEN_INVALID",
      "category": "authz",
      "retryable": false,
      "hint": "Check the Service access token."
    }
  }
}
```

这个结构主要方便调试。当前错误分类还比较简单，后续可以继续整理得更统一。

### 13. 安全说明

本实验做了几项基础保护：

- 登录时不直接发送共享密钥，而是使用 challenge-response。
- Service token 和 endpoint token 不直接发送原文，而是发送 proof。
- 认证后的 JSON body 会加密，抓包时看不到明文 JSON。
- `LIST` 会过滤 `auth`、`handler`、真实内网地址等字段。
- `command.exec` 只允许执行白名单命令。

限制也需要说明：

- 这不是 TLS，不能替代正式传输安全。
- 帧头、长度、连接地址、时序等元数据仍然可见。
- 没有做证书校验、中间人防护、审计日志、token 轮换。
- 加密实现是课程实验用的简化实现，不建议用于真实公网环境。

### 14. 当前不足

当前版本仍有不少限制：

- `CALL` 仍是同步请求-响应，不支持任务队列、进度事件和取消。
- schema 只实现了常用 JSON Schema 子集。
- 错误消息虽然结构化了，但分类还可以更细。
- 并发没有做全局上限和背压控制。
- Agent 只用单连接发布服务，多 Agent 负载均衡还没有做。
- 没有持久化服务目录，Relay 重启后服务表会丢失。

### 15. 小结

本实验实现了一个基于 TCP socket 的应用层协议原型。它包含自定义帧格式、登录认证、服务发布、服务发现、服务调用、基础权限控制、schema 校验和错误处理。实验重点是理解应用层协议需要自己定义消息边界、字段格式和交互流程，而不是追求生产级完整系统。
