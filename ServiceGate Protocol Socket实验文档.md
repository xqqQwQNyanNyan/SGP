# 网络 Socket 编程实验文档

## ServiceGate Protocol：面向个人跨设备服务发现与受控调用的应用层协议

### 1. 实验目的

本实验基于 TCP/IP socket 自行设计并实现一个应用层协议 ServiceGate Protocol（SGP）。实验目标包括：

- 理解 TCP socket 提供的是可靠字节流，应用层协议需要自行定义消息边界和消息格式。
- 围绕真实跨设备开发场景，设计具备认证、服务发现、服务调用和错误处理能力的应用层协议。
- 使用 Python 标准库 socket 实现协议原型，包括 Relay、服务发布 Node 和服务调用 Node。
- 通过测试用例验证正常流程、错误 token、服务不存在、Agent 离线、payload 限制等协议行为。

### 2. 应用场景与需求分析

目标场景是个人跨设备开发：Windows 主机放在寝室或内网环境中，Mac 是随身设备。用户希望在外部设备上发现并访问 Windows 上的开发服务，例如短文本投递、受控命令执行、本地 HTTP 页面预览或受限文件读取。

传统 SSH 更偏远程终端，frp/ngrok 更偏端口映射。SGP 将这些能力抽象为 Service，由发布方声明服务能力、访问策略和调用约定，由 Relay 统一维护服务目录并完成受控调用。

| 需求 | SGP 设计 |
| --- | --- |
| 真实需求 | Mac 在外访问 NAT 后 Windows 上的开发或课程服务 |
| 新颖性 | 把服务发布、服务发现、中继路由、服务级授权和策略限制统一进一个轻量协议 |
| 安全性 | Relay 共享密钥认证、session token、Service access token、命令白名单 |
| 扩展性 | 通过 version、service_type、contract、metadata、ext 扩展，不增加协议核心命令 |

### 3. 协议总体设计

#### 3.1 体系结构

```text
Windows Agent / Node  ->  Public Relay  <-  Mac Client / Node
       发布 Service            维护目录与路由          发现并调用 Service
```

SGP 的对等性是“逻辑对等、物理中继”。协议中的设备都可以抽象为 Node，但为了演示清晰，代码中保留 `agent.py` 和 `client.py` 两个入口。`agent.py` 演示服务发布行为，`client.py` 演示服务调用行为。

#### 3.2 消息边界与通用格式

TCP 不保留消息边界，因此 SGP 使用固定应用层帧格式：

```text
24 字节 SGP Frame Header + UTF-8 JSON Body
```

SGP Frame Header 采用固定 24 字节二进制结构：

| 字段 | 长度 | 说明 |
| --- | --- | --- |
| `magic` | 4B | 固定为 `SGP1`，用于识别 SGP 协议帧 |
| `major` / `minor` | 2B | 帧格式版本，当前为 `1.0` |
| `header_len` | 2B | 当前为 `24`，为未来扩展帧头字段预留空间 |
| `body_type` | 1B | 当前为 `1`，表示 body 是 UTF-8 JSON |
| `flags` | 1B | 标志位，当前保留，用于未来压缩、加密等扩展 |
| `reserved` | 2B | 保留字段，当前必须为 0 |
| `body_len` | 4B | JSON body 字节长度，用于解决 TCP 粘包和半包问题 |
| `seq` | 4B | 传输层帧序号，便于调试和未来多路复用 |
| `header_crc32` | 4B | 帧头 CRC32，用于检测头部损坏或协议错位 |

这样设计后，SGP 不再只是“长度前缀 + JSON”，而是具有协议识别、版本协商、类型判断、扩展预留、长度控制和头部校验能力的正式应用层帧格式。

通用消息字段：

| 字段 | 说明 |
| --- | --- |
| `version` | 协议版本，第一版为 `1.0` |
| `type` | `REQ`、`RESP` 或 `EVENT` |
| `id` | 消息编号，用于匹配请求和响应 |
| `role` | 发送方角色，如 `agent`、`client`、`relay` |
| `cmd` | 协议命令，如 `HELLO`、`AUTH`、`PUBLISH`、`LIST`、`CALL` |
| `token` | Relay 登录后得到的 session token |
| `service_id` | 被调用或发布的服务编号 |
| `payload` | 命令参数或返回数据 |
| `status` / `message` | 响应状态码和状态说明 |
| `ext` | 保留扩展字段 |

#### 3.3 核心命令

SGP 核心命令只有：

```text
HELLO, AUTH, PUBLISH, LIST, CALL, PING, ERROR
```

| 命令 | 方向 | 功能 |
| --- | --- | --- |
| `HELLO` | Node -> Relay | 声明角色、名称和协议版本 |
| `AUTH` | Node -> Relay | 使用共享密钥哈希登录 Relay |
| `PUBLISH` | Agent -> Relay | 发布 Service 列表、contract 和 policy |
| `LIST` | Client -> Relay | 查询可见服务目录 |
| `CALL` | Client -> Relay -> Agent | 按 `service_id` 路由一次服务调用 |
| `PING` | 任意方向 | 心跳和连接保活 |
| `ERROR` | 任意方向 | 保留错误事件类型 |

#### 3.4 Service 抽象

Service 是 SGP 的一等对象，表示发布方对外声明的一项能力或一组能力。协议层只处理 Service 的通用元信息、认证、策略和调用路由，不理解 Service 的具体业务字段。

| 组成 | 典型字段 |
| --- | --- |
| 元信息 | `service_id`、`name`、`service_type`、`description` |
| 访问策略 | `access_token_hash`、`max_payload_size`、`timeout_sec`、`max_calls_per_minute` |
| 调用约定 | `contract.example_input`、`contract.example_output`、`endpoints`、`metadata` |

文本、命令、HTTP 和文件服务都只是运行在协议之上的示例或扩展 Service，不是协议层命令。

### 4. 交互流程

#### 4.1 Agent 上线和服务发布

```text
Agent -> Relay: TCP connect
Agent -> Relay: HELLO(role=agent)
Relay -> Agent: 200 HELLO_OK
Agent -> Relay: AUTH(auth_hash)
Relay -> Agent: 200 AUTH_OK(token)
Agent -> Relay: PUBLISH(services)
Relay -> Agent: 201 PUBLISH_OK
```

#### 4.2 Client 查看服务

```text
Client -> Relay: TCP connect
Client -> Relay: HELLO(role=client)
Client -> Relay: AUTH(auth_hash)
Client -> Relay: LIST
Relay -> Client: services[]
```

#### 4.3 Client 调用服务

```text
Client -> Relay: CALL(service_id, access_token, input)
Relay: 校验 session token、service_id、access_token、payload、频率和在线状态
Relay -> Agent: CALL(service_id, input)
Agent: 根据 service_type 或 handler 处理 input
Agent -> Relay -> Client: CALL result(output)
```

### 5. 程序实现

| 文件 | 职责 |
| --- | --- |
| `protocol.py` | 实现 SGP 二进制帧头、JSON body 收发、消息构造、SHA256、base64 工具 |
| `relay.py` | 维护 session 和 services，处理 `HELLO`、`AUTH`、`PUBLISH`、`LIST`、`CALL`、`PING` |
| `agent.py` | 登录 Relay，发布 Service，处理内置和自定义 Service 调用 |
| `client.py` | 登录 Relay，查询服务目录，提供交互菜单和非交互式调用 |
| `services.example.json` | 扩展 Service 配置示例 |
| `handlers/file_transfer.py` | `file.transfer` 扩展示例 handler |

实现中 Relay 不关心 `text.echo`、`command.exec`、`http.bundle` 或 `file.transfer` 的业务语义，只将 `CALL` 路由到发布服务的 Node。这样新增 Service 时不需要修改 Relay 的核心协议命令。

### 6. 运行方法

在三个终端中分别执行：

```bash
python3 relay.py --host 127.0.0.1 --port 9000
python3 agent.py --relay-host 127.0.0.1 --relay-port 9000
python3 client.py --relay-host 127.0.0.1 --relay-port 9000
```

也可以使用非交互式命令完成关键演示：

| 目的 | 命令 |
| --- | --- |
| 列出服务目录 | `python3 client.py --list` |
| 调用文本服务 | `python3 client.py --call text --text "hello from mac"` |
| 调用命令服务 | `python3 client.py --call command --command "pwd"` |
| 启动 HTTP 服务 | `python3 -m http.server 8000` |
| 调用 HTTP 服务 | `python3 client.py --call http --endpoint page --method GET --path /` |
| 错误 token | `python3 client.py --call text --service-token wrong-token --text "should fail"` |
| 服务不存在 | `python3 client.py --call text --service-id missing-service --text "should fail"` |

### 7. 示例 Service 与扩展 Service

#### 7.1 示例 Service

默认 `agent.py` 会发布三个示例 Service：

| Service | 类型 | 作用 |
| --- | --- | --- |
| `note-box` | `text.echo` | 短文本回显，演示最小 `CALL` 流程 |
| `win-command` | `command.exec` | 执行白名单命令，演示 Service 级策略 |
| `frontend-workspace` | `http.bundle` | 访问本地 HTTP endpoint，演示 Service 内部 endpoint |

#### 7.2 扩展 Service

扩展 Service 用来展示 SGP 的可维护性和扩展性。扩展时不需要修改 Relay 的协议命令，只需要让发布方 Node 声明新的 `service_type`、`contract`、`policy`，并在本机提供对应 handler。

```bash
cp services.example.json services.json
python3 agent.py --relay-host 127.0.0.1 --relay-port 9000 --services-config services.json
```

通用 JSON 调用示例：

```bash
python3 client.py --call generic --service-id custom-note --input-json '{"text":"hello custom"}'
python3 client.py --call generic --service-id custom-command --input-json '{"command":"pwd"}'
python3 client.py --call generic --service-id custom-web --input-json '{"endpoint_id":"page","method":"GET","path":"/","headers":{},"body_base64":""}'
```

`services.example.json` 中还提供了一个类 FTP 的受限文件服务 `file-box`：

```bash
python3 client.py --call generic --service-id file-box --input-json '{"op":"list","path":"."}'
python3 client.py --call generic --service-id file-box --input-json '{"op":"read_chunk","path":"hello.txt","offset":0,"size":8192}'
python3 client.py --call generic --service-id file-box --input-json '{"op":"write_chunk","path":"upload.txt","offset":0,"data_base64":"aGVsbG8="}'
```

`file.transfer` 是扩展示例，用于展示协议可扩展性；它不是 SGP 第一版的核心功能。

### 8. 测试用例与预期结果

| 编号 | 测试内容 | 预期结果 |
| --- | --- | --- |
| T1 | Relay、Agent、Client 按顺序启动并认证 | 返回 `HELLO_OK`、`AUTH_OK`、`PUBLISH_OK` |
| T2 | Client 执行 `LIST` | 返回 `note-box`、`win-command`、`frontend-workspace` 等服务目录 |
| T3 | 调用 `note-box` 文本服务 | 返回 `200 OK` 和文本回显 |
| T4 | 调用 `win-command` 中的 `pwd` 或 `git status` | 返回 `exit_code`、`stdout`、`stderr` |
| T5 | 调用 `frontend-workspace` 的 `page` endpoint | 返回 `http_status`、`headers` 和 body preview |
| T6 | 使用错误 service token | 返回 `403 SERVICE_TOKEN_INVALID` |
| T7 | 调用不存在的 `service_id` | 返回 `404 SERVICE_NOT_FOUND` |
| T8 | Agent 断开后再次调用已发布服务 | 返回 `503 AGENT_OFFLINE` |
| T9 | payload 超过服务 policy 限制 | 返回 `413 PAYLOAD_TOO_LARGE` |
| T10 | 短时间内超过调用频率限制 | 返回 `429 TOO_MANY_REQUESTS` |

### 9. 错误处理、安全与隐私

SGP 使用统一状态码描述协议结果，参考 HTTP/FTP 的响应码思想。

常见状态码：

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
502 BAD_GATEWAY
503 SERVICE_UNAVAILABLE
```

安全设计：

- Relay 登录使用预共享密钥的 SHA256 哈希。
- Relay 登录成功后发放随机 session token。
- 每个 Service 具有独立 access token，Relay 保存 token 哈希。
- Relay 根据 Service policy 检查 payload 大小、超时和调用频率。
- `command.exec` 由 Agent 使用白名单限制，不开放任意 shell。
- `LIST` 返回时过滤 `auth`、`handler` 和真实内网地址等敏感信息。

安全边界：本实验原型没有实现 TLS，token 会明文经过 TCP 连接。真实公网部署时应加入 TLS、访问日志、权限隔离、token 轮换和更细粒度授权。

### 10. 与 RPC、frp/ngrok 的关系

SGP 承认并采用 RPC-style 的请求响应模型。RPC 是调用范式，SGP 是承载该范式的具体应用层协议。SGP 的差异在于协议内置服务发布、服务发现、中继路由、服务级授权和通用策略检查。

| 对比项 | 普通 RPC | SGP |
| --- | --- | --- |
| 调用对象 | 函数或方法 | Relay 目录中的 Service |
| 发现机制 | 常依赖固定地址或外部注册中心 | 协议内置 `PUBLISH` 和 `LIST` |
| 网络模型 | 调用方常直连服务端 | Agent 和 Client 都主动连接 Relay |
| 授权策略 | 多为全局认证 | session token + Service access token + policy |

与 frp/ngrok 相比，SGP 不直接暴露端口，而是暴露 Service 能力。Client 不需要知道内网 IP 和真实端口，只通过服务目录和 contract 构造调用。

### 11. LLM 使用说明

本实验允许并鼓励使用 LLM 辅助开发。本人主要使用 LLM 进行以下工作：

- 协助梳理协议文档结构，包括消息格式、命令语义、错误码和交互流程。
- 辅助检查协议是否容易被理解为普通 RPC，并调整表述为 RPC-style 应用层协议。
- 辅助生成和润色 README、实验文档、测试用例和录屏建议。
- 在代码实现阶段辅助排查 socket 粘包/半包、JSON 帧格式、错误处理和服务扩展结构。

本人完成的核心设计包括：确定个人跨设备服务发现与受控调用的应用场景，定义 Service/endpoint/contract/policy 抽象，确定 Relay 中继模型、核心命令集、演示服务边界和录屏展示流程。LLM 输出经过本人筛选、修改和整合，最终协议设计和实现取舍由本人完成。

### 12. 当前协议可优化方向

| 方向 | 当前情况 | 可优化方案 |
| --- | --- | --- |
| 认证安全 | SHA256 哈希和明文 TCP 满足课程原型 | 加入 TLS、challenge-response、token 过期和轮换 |
| 消息语义 | `CALL` 为同步请求响应 | 增加异步 `CALL`、进度事件和取消调用 |
| 服务契约 | `contract` 目前以示例输入输出为主 | 引入 JSON Schema 或更严格的字段约束 |
| 并发能力 | 每个 Service 调用对 Agent 连接加锁 | 支持多连接 Agent、调用队列和 request multiplexing |
| 错误细粒度 | 已有统一状态码 | 区分 Relay 错误、Agent 错误、Service 业务错误 |
| 服务生命周期 | 断开后标记 offline | 增加 TTL、心跳续租、服务下线 `UNPUBLISH` |
| 权限模型 | Service token 粒度较粗 | 支持只读/写入/endpoint 级权限和审计日志 |

### 13. 总结

本实验完成了一个基于 TCP socket 的自定义应用层协议 SGP。SGP 使用明确的帧格式和 JSON 消息结构，定义了认证、服务发布、服务发现、服务调用、错误处理和扩展机制。虽然它采用 RPC-style 的调用模型，但协议的核心价值在于面向 NAT 后个人设备的服务声明、服务发现、中继路由和受控调用。实验原型能够完成正常调用和多种异常场景演示，满足课程对协议功能、逻辑、安全隐私、可维护性和实验文档的基本要求。
