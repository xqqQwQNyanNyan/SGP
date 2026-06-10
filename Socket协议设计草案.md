# ServiceGate Protocol 协议设计草案

## 1. 选题名称

协议名称：ServiceGate Protocol，简称 SGP。

一句话定位：

ServiceGate 是一种面向个人跨设备开发场景的服务声明式远程调用协议。它让寝室 Windows 主机主动连接中继服务器，并向外声明自己可以提供的 Service。Mac 客户端不直接暴露或扫描 Windows 端口，而是先发现服务、认证、申请调用，再由 Relay 将调用转发给对应 Agent。

核心原则：

协议层只理解 Service，不理解具体服务业务。短文本、命令执行、HTTP 访问都不是协议层命令，而是第一版 Agent 内置实现的几种 Service 类型。

## 2. 课程要求对齐

本实验要求自行设计应用层协议，并基于 TCP/IP socket 实现。ServiceGate 对应关系如下：

| 课程评分点 | ServiceGate 设计 |
| --- | --- |
| 真实需求 | Mac 在外访问寝室 Windows 上的开发/课程服务 |
| 功能新颖 | 不只是聊天/网盘，而是服务声明、服务发现和服务调用 |
| 消息格式明确 | 24 字节 SGP Frame Header + UTF-8 JSON Body |
| 交互流程明确 | HELLO、AUTH、PUBLISH、LIST、CALL、PING |
| 错误处理 | 认证失败、服务不存在、Agent 离线、调用超时、payload 过大等 |
| 安全隐私 | SHA256 哈希认证、服务 access token、服务策略限制 |
| 可维护拓展 | version、cmd、service_type、contract、metadata、ext 字段保留扩展空间 |
| 代码规模 | 使用 Python 标准库，控制在数百行级别 |
| 录屏展示 | 可演示服务发现、短文本服务、命令服务、HTTP 服务和错误情况 |

## 3. 真实应用场景

用户有两台主要设备：

- Windows 主机放在寝室，可能存有课程代码、前端项目、本地 HTTP 服务。
- Mac 是随身设备，常在寝室外使用。

常见需求：

1. 在 Mac 上给 Windows 发送一段短文本，例如备忘、路径、简单参数。
2. 在 Mac 上触发 Windows 执行受控命令，例如 `dir`、`pwd`、`git status`。
3. 在 Mac 上访问 Windows 本地启动的 HTTP 服务，例如前端项目页面、课程资料 Web 目录、本地 API 服务。

SSH 可以解决一部分远程命令问题，但它更像远程终端，不强调“发布服务、发现服务、按服务授权访问”。frp/ngrok 更强调端口映射，而 ServiceGate 的重点是把 Windows 上的能力声明成服务对象，由 Relay 统一管理和转发。

## 4. 最终功能边界

为了在一天内完成作业，第一版只做统一服务调用模型，并内置三个示例 Service：

1. `text.echo`：短文本服务。Client 传入一段文本，Agent 返回确认或回显。
2. `command.exec`：受控命令服务。Client 传入命令名称，Agent 只执行白名单命令并返回输出。
3. `http.bundle`：HTTP 服务集合。一个 Service 内可以包含多个 endpoint，例如前端页面 endpoint 和 API endpoint。

明确不做：

- 大文件传输。
- 文件夹同步。
- 完整远程桌面。
- 完整 TCP 隧道。
- UDP。
- 复杂交互式 Shell。
- 前端 HMR 热更新保证。
- 工业级公网安全。

关于前端项目预览：

- 第一版支持 HTTP 页面预览和手动刷新调试。
- 如果 Windows 上运行 Vite/React/Vue/Next 等开发服务器，Mac 可以通过 ServiceGate 调用 HTTP Service 获取页面。
- 完整实时热更新通常依赖 WebSocket/HMR，属于后续扩展，不作为第一版承诺功能。

## 5. 总体架构

```text
Windows Agent  ->  Public Relay  <-  Mac Client
  内网机器           公网服务器         外部访问端
```

三类程序：

1. Agent：运行在 Windows 上，主动连接 Relay，发布本机可用 Service，并处理 CALL。
2. Relay：运行在公网或本地模拟公网，负责认证、服务目录、调用路由和错误响应。
3. Client：运行在 Mac 上，连接 Relay，查看服务目录并发起 CALL。

为什么 Agent 主动连接 Relay：

- 寝室 Windows 通常在内网或 NAT 后面，公网无法直接连接它。
- Agent 主动连出去一般更容易成功。
- Client 也连接 Relay，Relay 成为双方的中间协调点。

## 6. 核心抽象：Service

ServiceGate 不直接让用户记端口，而是让 Agent 发布 Service。

Service 是一个抽象实体，表示 Agent 对外声明的一项能力或一组能力。协议层不理解 Service 内部业务语义，只认识 Service 的通用描述和调用规则。

Service 由三部分组成：

```text
Service = 元信息 + 访问策略 + 调用约定
```

通用结构：

```json
{
  "service_id": "frontend-workspace",
  "name": "Frontend Workspace",
  "service_type": "http.bundle",
  "description": "Project-level HTTP service on Windows",
  "auth": {
    "access_token_hash": "sha256(service-token)"
  },
  "policy": {
    "max_payload_size": 65536,
    "timeout_sec": 5,
    "max_calls_per_minute": 30
  },
  "endpoints": [],
  "contract": {
    "input_schema": "service-defined",
    "output_schema": "service-defined",
    "example_input": {},
    "example_output": {}
  },
  "metadata": {}
}
```

字段说明：

| 字段 | 说明 |
| --- | --- |
| `service_id` | 服务唯一编号 |
| `name` | 服务显示名称 |
| `service_type` | 服务类型，如 `text.echo`、`command.exec`、`http.bundle` |
| `description` | 服务说明 |
| `auth` | 服务级认证配置 |
| `policy` | payload 大小、超时、调用频率等通用限制 |
| `endpoints` | 服务入口列表，可为空 |
| `contract` | 服务输入输出约定，由 Agent 和 Client 理解 |
| `metadata` | 服务实现所需的额外信息 |

## 7. endpoint（服务入口）

endpoint 可以理解为 Service 内部的具体访问点。

如果 Service 是“一个能力集合”，endpoint 就是这个集合里的某个入口。例如一个前端项目可以作为一个 Service，但它内部可能有页面服务和 API 服务：

```text
Service: frontend-workspace
  endpoint: page -> 127.0.0.1:5173
  endpoint: api  -> 127.0.0.1:3000
```

这能体现 ServiceGate 和端口映射工具的区别：

- 端口映射工具通常是一条映射对应一个端口。
- ServiceGate 可以把一个项目级能力声明为一个 Service，并在 Service 内部组织多个 endpoint。

HTTP 服务集合示例：

```json
{
  "service_id": "frontend-workspace",
  "name": "Frontend Workspace",
  "service_type": "http.bundle",
  "description": "Frontend page and local API of one Windows project",
  "auth": {
    "access_token_hash": "sha256(service-token)"
  },
  "policy": {
    "max_payload_size": 65536,
    "timeout_sec": 5
  },
  "endpoints": [
    {
      "endpoint_id": "page",
      "protocol": "http",
      "target_host": "127.0.0.1",
      "target_port": 5173,
      "allow_methods": ["GET", "POST"]
    },
    {
      "endpoint_id": "api",
      "protocol": "http",
      "target_host": "127.0.0.1",
      "target_port": 3000,
      "allow_methods": ["GET", "POST"]
    }
  ],
  "contract": {
    "example_input": {
      "endpoint_id": "page",
      "method": "GET",
      "path": "/",
      "headers": {},
      "body_base64": ""
    },
    "example_output": {
      "http_status": 200,
      "headers": {
        "Content-Type": "text/html"
      },
      "body_base64": "..."
    }
  },
  "metadata": {}
}
```

注意：

- `target_host` 和 `target_port` 是 Agent 实现细节，不应直接暴露给 Client。
- LIST 返回时可以展示 `endpoint_id`、`protocol`、说明，但要过滤真实内网地址。
- 第一版 endpoint 主要用于 HTTP Service，后续也可以扩展为脚本入口、函数入口等。

Client 看到的服务目录示例：

```json
{
  "service_id": "frontend-workspace",
  "name": "Frontend Workspace",
  "service_type": "http.bundle",
  "online": true,
  "description": "Frontend page and local API of one Windows project",
  "policy": {
    "max_payload_size": 65536,
    "timeout_sec": 5
  },
  "endpoints": [
    {
      "endpoint_id": "page",
      "protocol": "http"
    },
    {
      "endpoint_id": "api",
      "protocol": "http"
    }
  ],
  "contract": {
    "example_input": {
      "endpoint_id": "page",
      "method": "GET",
      "path": "/"
    }
  }
}
```

## 8. 与 frp/ngrok 的差异

ServiceGate 和 frp/ngrok 都使用了“内网端主动连接公网中继”的思路，因此连接模型有相似之处。

但二者抽象不同：

| 对比项 | frp/ngrok | ServiceGate |
| --- | --- | --- |
| 核心抽象 | 端口映射、隧道 | Service、endpoint、CALL |
| 用户关注点 | 公网端口映射到内网端口 | 服务是什么、如何调用、有什么策略 |
| Relay 职责 | 转发流量为主 | 服务目录、认证、策略、调用路由 |
| 扩展方式 | 新增映射或隧道类型 | 新增 `service_type` 和 `contract` |
| 第一版实现 | 原始流量代理 | 应用层请求-响应调用 |

因此，ServiceGate 不试图替代 frp，而是把内网访问抽象成服务声明和服务调用，更适合本课程展示应用层协议设计。

## 9. 传输方式与消息边界

SGP 基于 TCP socket。

TCP 是可靠字节流，但不保留消息边界。因此 SGP 采用固定的应用层帧格式：

```text
24 字节 SGP Frame Header + UTF-8 JSON Body
```

帧头为固定 24 字节二进制结构：

| 字段 | 长度 | 说明 |
| --- | --- | --- |
| `magic` | 4B | 固定为 `SGP1`，用于识别协议帧 |
| `major` / `minor` | 2B | 帧格式版本，当前为 `1.0` |
| `header_len` | 2B | 当前为 `24`，为未来扩展帧头字段预留空间 |
| `body_type` | 1B | 当前为 `1`，表示 body 是 UTF-8 JSON |
| `flags` | 1B | 标志位，当前保留，用于未来压缩、加密等扩展 |
| `reserved` | 2B | 保留字段，当前必须为 0 |
| `body_len` | 4B | JSON body 字节长度，用于解决 TCP 粘包和半包问题 |
| `seq` | 4B | 传输层帧序号，便于调试和未来多路复用 |
| `header_crc32` | 4B | 帧头 CRC32，用于检测头部损坏或协议错位 |

优点：

- 能解决 TCP 粘包、半包问题。
- 通过 `magic` 识别协议帧，避免把错误数据当成合法消息。
- 通过帧版本和 `header_len` 为后续扩展预留空间。
- 通过 `body_type` 支持未来切换编码格式。
- 通过 `seq` 为调试和未来多路复用预留基础。
- 通过 `header_crc32` 检测头部损坏或错位。
- Body 仍统一使用 JSON，便于调试和录屏展示。

Service 的输入输出放在 JSON 的 `payload.input` 和 `payload.output` 中。如果某个服务需要传少量二进制内容，可以使用 base64 字符串。第一版限制 payload 大小，因此不处理大文件。

## 10. 通用消息格式

请求消息：

```json
{
  "version": "1.0",
  "type": "REQ",
  "id": "msg-001",
  "role": "client",
  "cmd": "CALL",
  "token": "relay-session-token",
  "service_id": "frontend-workspace",
  "payload": {},
  "ext": {}
}
```

响应消息：

```json
{
  "version": "1.0",
  "type": "RESP",
  "id": "msg-001",
  "role": "relay",
  "cmd": "CALL",
  "status": 200,
  "message": "OK",
  "service_id": "frontend-workspace",
  "payload": {},
  "ext": {}
}
```

字段说明：

| 字段 | 说明 |
| --- | --- |
| `version` | 协议版本号，第一版为 `1.0` |
| `type` | `REQ`、`RESP`、`EVENT` |
| `id` | 消息编号，用于匹配请求和响应 |
| `role` | 发送方角色：`agent`、`client`、`relay` |
| `cmd` | 命令名称 |
| `token` | Relay 登录后得到的会话 token |
| `service_id` | 访问的服务编号 |
| `status` | 响应状态码 |
| `message` | 状态说明 |
| `payload` | 命令参数或返回数据 |
| `ext` | 未来扩展字段 |

## 11. 状态码

SGP 参考 HTTP/FTP 的响应码思想，用数字区分结果类型。

```text
200 OK
201 CREATED
400 BAD_REQUEST
401 UNAUTHORIZED
403 FORBIDDEN
404 NOT_FOUND
408 TIMEOUT
413 PAYLOAD_TOO_LARGE
426 VERSION_NOT_SUPPORTED
429 TOO_MANY_REQUESTS
500 SERVER_ERROR
502 BAD_GATEWAY
503 SERVICE_UNAVAILABLE
```

常见错误：

| 场景 | 状态码 |
| --- | --- |
| JSON 格式错误 | 400 |
| 协议版本不支持 | 426 |
| 未登录或 token 无效 | 401 |
| 服务 access token 错误 | 403 |
| 服务不存在 | 404 |
| payload 太大 | 413 |
| 调用超时 | 408 |
| 调用频率超限 | 429 |
| Agent 不在线 | 503 |
| Agent 内部服务处理失败 | 502 |

## 12. 核心命令

协议层核心命令只有：

```text
HELLO
AUTH
PUBLISH
LIST
CALL
PING
ERROR
```

### 12.1 HELLO

连接建立后首先发送，声明角色和协议版本。

```json
{
  "version": "1.0",
  "type": "REQ",
  "id": "1",
  "role": "agent",
  "cmd": "HELLO",
  "payload": {
    "name": "dorm-windows-agent"
  }
}
```

### 12.2 AUTH

Agent 或 Client 登录 Relay。

```json
{
  "version": "1.0",
  "type": "REQ",
  "id": "2",
  "role": "client",
  "cmd": "AUTH",
  "payload": {
    "auth_hash": "sha256(pre-shared-secret)"
  }
}
```

成功响应：

```json
{
  "version": "1.0",
  "type": "RESP",
  "id": "2",
  "role": "relay",
  "cmd": "AUTH",
  "status": 200,
  "message": "AUTH_OK",
  "payload": {
    "token": "random-session-token"
  }
}
```

### 12.3 PUBLISH

Agent 向 Relay 发布 Service。

```json
{
  "version": "1.0",
  "type": "REQ",
  "id": "3",
  "role": "agent",
  "cmd": "PUBLISH",
  "token": "random-session-token",
  "payload": {
    "services": [
      {
        "service_id": "note-box",
        "name": "Short Text Box",
        "service_type": "text.echo",
        "description": "Receive short text from remote client",
        "auth": {
          "access_token_hash": "sha256(service-token)"
        },
        "policy": {
          "max_payload_size": 2048,
          "timeout_sec": 3
        },
        "contract": {
          "example_input": {
            "text": "hello from mac"
          },
          "example_output": {
            "reply": "Agent received 14 bytes"
          }
        },
        "metadata": {}
      },
      {
        "service_id": "win-command",
        "name": "Windows Command Runner",
        "service_type": "command.exec",
        "description": "Run whitelisted commands on Windows",
        "auth": {
          "access_token_hash": "sha256(service-token)"
        },
        "policy": {
          "max_payload_size": 2048,
          "timeout_sec": 10
        },
        "contract": {
          "example_input": {
            "command": "git status"
          },
          "example_output": {
            "exit_code": 0,
            "stdout": "...",
            "stderr": ""
          }
        },
        "metadata": {
          "allow_commands": ["dir", "pwd", "git status"]
        }
      }
    ]
  }
}
```

Relay 保存服务表，但向 Client 展示时应过滤敏感字段，例如 `auth.access_token_hash`、真实内网地址等。

### 12.4 LIST

Client 查询服务目录。

```json
{
  "version": "1.0",
  "type": "REQ",
  "id": "4",
  "role": "client",
  "cmd": "LIST",
  "token": "random-session-token",
  "payload": {}
}
```

Relay 返回：

```json
{
  "version": "1.0",
  "type": "RESP",
  "id": "4",
  "role": "relay",
  "cmd": "LIST",
  "status": 200,
  "message": "OK",
  "payload": {
    "services": [
      {
        "service_id": "note-box",
        "name": "Short Text Box",
        "service_type": "text.echo",
        "online": true,
        "description": "Receive short text from remote client",
        "policy": {
          "max_payload_size": 2048,
          "timeout_sec": 3
        },
        "contract": {
          "example_input": {
            "text": "hello from mac"
          }
        }
      }
    ]
  }
}
```

### 12.5 CALL

Client 调用某个 Service。

协议层不解释 `payload.input` 的业务字段，只负责认证、限额、超时和路由。

调用文本服务：

```json
{
  "version": "1.0",
  "type": "REQ",
  "id": "5",
  "role": "client",
  "cmd": "CALL",
  "token": "random-session-token",
  "service_id": "note-box",
  "payload": {
    "access_token": "service-token",
    "input": {
      "text": "hello from mac"
    }
  }
}
```

调用命令服务：

```json
{
  "version": "1.0",
  "type": "REQ",
  "id": "6",
  "role": "client",
  "cmd": "CALL",
  "token": "random-session-token",
  "service_id": "win-command",
  "payload": {
    "access_token": "service-token",
    "input": {
      "command": "git status"
    }
  }
}
```

调用 HTTP bundle 的 page endpoint：

```json
{
  "version": "1.0",
  "type": "REQ",
  "id": "7",
  "role": "client",
  "cmd": "CALL",
  "token": "random-session-token",
  "service_id": "frontend-workspace",
  "payload": {
    "access_token": "service-token",
    "input": {
      "endpoint_id": "page",
      "method": "GET",
      "path": "/",
      "headers": {},
      "body_base64": ""
    }
  }
}
```

CALL 响应：

```json
{
  "version": "1.0",
  "type": "RESP",
  "id": "7",
  "role": "relay",
  "cmd": "CALL",
  "status": 200,
  "message": "OK",
  "service_id": "frontend-workspace",
  "payload": {
    "output": {
      "http_status": 200,
      "headers": {
        "Content-Type": "text/html"
      },
      "body_base64": "PCFkb2N0eXBlIGh0bWw+..."
    }
  }
}
```

### 12.6 PING

用于心跳和连接保活。

```json
{
  "version": "1.0",
  "type": "REQ",
  "id": "8",
  "role": "client",
  "cmd": "PING",
  "payload": {
    "ts": 1710000000
  }
}
```

## 13. 交互流程

### 13.1 Agent 上线和服务发布

```text
Agent -> Relay: TCP connect
Agent -> Relay: HELLO(role=agent)
Relay -> Agent: 200 OK
Agent -> Relay: AUTH(auth_hash)
Relay -> Agent: AUTH_OK(token)
Agent -> Relay: PUBLISH(services)
Relay -> Agent: PUBLISH_OK
```

### 13.2 Client 查看服务

```text
Client -> Relay: TCP connect
Client -> Relay: HELLO(role=client)
Relay -> Client: 200 OK
Client -> Relay: AUTH(auth_hash)
Relay -> Client: AUTH_OK(token)
Client -> Relay: LIST
Relay -> Client: services
```

### 13.3 Client 调用服务

```text
Client -> Relay: CALL(service_id, access_token, input)
Relay: 校验登录 token
Relay: 查找 service_id
Relay: 检查 Agent 是否在线
Relay: 校验 access_token
Relay: 检查 payload 大小和调用策略
Relay -> Agent: CALL(service_id, input)
Agent: 根据 service_type 和 service_id 处理 input
Agent -> Relay: CALL result(output)
Relay -> Client: CALL result(output)
```

## 14. Relay、Agent、Client 的职责边界

Relay 理解：

- 连接角色。
- 登录状态。
- 服务表。
- 服务 access token。
- 服务在线状态。
- 通用 policy，例如 max payload size、timeout。
- CALL 的路由。

Relay 不理解：

- `input.text` 是什么。
- `input.command` 是什么。
- `input.method` / `input.path` 是什么。
- HTTP、命令、文本的具体处理逻辑。

Agent 理解：

- 自己发布了哪些服务。
- 每种 `service_type` 如何处理。
- endpoint 如何映射到本机资源。
- 命令白名单、HTTP 本地目标等实现细节。

Client 理解：

- 从 LIST 看到服务说明和 contract。
- 按 contract 构造 input。
- 展示 output。

## 15. 安全与隐私

基础安全设计：

1. Agent 和 Client 登录 Relay 时使用预共享密钥的 SHA256 哈希。
2. Relay 登录成功后发放随机 session token。
3. 每个 Service 单独设置 access token，Relay 保存 token 的 SHA256 哈希。
4. Client 调用具体 Service 时必须提供正确的 access token。
5. Relay 根据 Service policy 限制 payload 大小、调用超时和调用频率。
6. `command.exec` 这类危险能力由 Agent 使用白名单限制，不开放任意 shell。
7. `http.bundle` 这类能力由 Agent 限制 endpoint、method、body 大小。
8. Agent 断开后，Relay 将相关服务标记为 offline。

安全边界说明：

- SHA256 和 token 只能满足课程原型中的基础认证要求。
- 第一版没有实现 TLS，因此真实公网部署时不应直接传输明文 token。
- 真实环境中还需要 TLS、访问日志、命令审计、权限隔离和更严格的 token 管理。

## 16. 错误处理

必须处理：

1. TCP 连接断开。
2. JSON 格式错误。
3. 消息长度异常。
4. 协议版本不支持。
5. 未认证访问。
6. 服务不存在。
7. 服务 access token 错误。
8. Agent 离线。
9. payload 超过服务限制。
10. CALL 超时。
11. Agent 内部服务处理失败。
12. Client、Agent 任意一端断开。

示例：

```json
{
  "version": "1.0",
  "type": "RESP",
  "id": "9",
  "role": "relay",
  "cmd": "CALL",
  "status": 403,
  "message": "SERVICE_TOKEN_INVALID",
  "service_id": "frontend-workspace",
  "payload": {},
  "ext": {}
}
```

## 17. 代码结构建议

```text
protocol.py
relay.py
agent.py
client.py
README.md
```

`protocol.py`：

- `send_msg(sock, obj)`：发送 SGP Frame Header + JSON Body。
- `recv_msg(sock)`：接收一条完整 JSON 消息。
- `make_msg(...)`：构造通用消息。
- `sha256_text(text)`：计算 SHA256。
- `b64_encode(data)` / `b64_decode(text)`：处理少量二进制内容。

`relay.py`：

- 监听 Agent 和 Client 连接。
- 处理 HELLO、AUTH、PUBLISH、LIST、CALL、PING。
- 维护服务表。
- 校验登录 token 和 service access token。
- 按 service_id 将 CALL 转发给 Agent。
- 将 Agent 的 output 原样返回给 Client。

`agent.py`：

- 连接 Relay。
- 登录并发布服务。
- 根据 service_type 分发 CALL。
- 内置示例服务：
  - `text.echo`
  - `command.exec`
  - `http.bundle`

`client.py`：

- 连接 Relay。
- 登录并查看服务列表。
- 提供命令行菜单：
  - LIST 服务。
  - CALL 短文本服务。
  - CALL 命令服务。
  - CALL HTTP endpoint。

## 18. 最小可演示版本

第一版录屏只展示以下内容：

1. 启动 Relay。
2. 启动 Agent，发布三个 Service：
   - `note-box`，类型 `text.echo`。
   - `win-command`，类型 `command.exec`。
   - `frontend-workspace`，类型 `http.bundle`，包含 `page` 和 `api` 两个 endpoint。
3. 启动 Client，LIST 显示三个服务在线。
4. Client 对 `note-box` 发起 CALL，Agent 返回收到确认。
5. Client 对 `win-command` 发起 CALL，执行白名单命令，例如 `dir` 或 `git status`。
6. Windows 启动一个本地 HTTP 服务，例如 Python 静态页面或前端 dev server。
7. Client 对 `frontend-workspace` 的 `page` endpoint 发起 CALL，显示返回的 HTML 或 JSON 内容。
8. 用错误 access token 调用服务，展示 403。
9. 调用不存在的 service_id，展示 404。
10. 停止 Agent，Client 再访问服务，展示 503。

## 19. 实验文档结构建议

```text
1. 实验目的与背景
2. 应用场景：Mac 远程访问寝室 Windows 的服务能力
3. 协议总体设计：Agent/Relay/Client
4. 核心抽象：Service 与 endpoint
5. 消息格式：SGP Frame Header + JSON Body
6. 命令设计：HELLO、AUTH、PUBLISH、LIST、CALL、PING
7. 服务调用流程
8. 安全认证与权限控制
9. 错误处理
10. 代码结构与运行方法
11. 测试用例和录屏说明
12. 与 frp/ngrok 的区别
13. 局限性与未来扩展
14. LLM 使用说明
```

## 20. LLM 使用说明建议

实验文档中应单开一章说明：

- LLM 辅助进行了选题讨论、协议命名、消息格式整理、错误码设计、文档结构整理和代码实现建议。
- 用户自己提出了真实需求：Mac 需要访问寝室 Windows 上的开发服务。
- 用户自己完成了方案取舍：放弃大文件传输、复杂指令处理和完整前端热更新，选择统一 Service/CALL 抽象作为协议主体。
- 用户自己进一步提出关键设计：协议层不应理解具体服务，服务只是抽象实体；HTTP、命令和文本只是 Agent 侧示例服务。
- 用户自己负责最终代码测试、录屏、运行结果确认和提交材料整理。

## 21. 后续扩展方向

如果未来继续完善，可以增加：

- TLS 加密。
- WebSocket 转发，用于支持前端 HMR 热更新。
- 完整 TCP 隧道。
- 多 Agent、多用户和权限分组。
- 服务访问日志和命令审计。
- 文件传输，但需要分块、校验、续传和大小限制。
- Web 管理界面。
