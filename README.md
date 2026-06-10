# ServiceGate Protocol Demo

ServiceGate Protocol (SGP) 是一个基于 TCP socket 的轻量应用层协议示例。它采用 RPC-style 的请求响应模型，但设计重点不是“远程调用某个固定函数”，而是让 NAT 后的个人设备主动连接 Relay，发布本机 Service；另一台设备先发现 Service，再按 Service 的 contract、auth 和 policy 发起受控调用。

SGP 的核心抽象是 Service，而不是端口、文件或命令。`text.echo`、`command.exec`、`http.bundle`、`file.transfer` 都只是跑在协议之上的示例或扩展 Service，不属于协议层命令。

SGP 的对等性是“逻辑对等、物理中继”：设备在协议角色上都可以是 Node，但跨网络通信仍然依赖 Relay 作为公网协调点。当前 demo 保留 `agent.py` 和 `client.py` 两个入口，分别演示 Node 的服务发布行为和服务调用行为；协议设计上的抽象主体是 Node。

## 协议核心

SGP 消息使用：

```text
24 字节 SGP Frame Header + UTF-8 JSON Body
```

帧头字段：

| 字段 | 长度 | 作用 |
| --- | --- | --- |
| `magic` | 4B | 固定为 `SGP1`，用于识别协议帧 |
| `major/minor` | 2B | 帧格式版本，用于兼容性判断 |
| `header_len` | 2B | 当前为 `24`，为后续扩展头预留空间 |
| `body_type` | 1B | `1` 表示 JSON body，`2` 表示认证后的加密 JSON body |
| `flags` | 1B | 标志位，当前保留 |
| `reserved` | 2B | 保留字段，当前必须为 0 |
| `body_len` | 4B | JSON body 字节长度，解决 TCP 粘包/半包 |
| `seq` | 4B | 传输层帧序号，便于调试和未来多路复用 |
| `header_crc32` | 4B | 帧头 CRC32，检测头部损坏或错位 |

通用消息字段包括：

```text
version, type, id, role, cmd, token, service_id, payload, status, message, ext
```

核心命令只有：

```text
HELLO, AUTH, PUBLISH, LIST, CALL, PING, ERROR
```

Relay 只理解连接角色、登录状态、Service 目录、Service access proof、endpoint access proof、生命周期状态、通用 policy、Service schema 和 CALL 路由；Relay 支持多个 Node 并发连接，并通过消息 id 在同一 Agent 连接上复用多个并发 `CALL`。Relay 不解释 `payload.input` 中的具体业务语义，但会按 `contract.input_schema` 做通用结构校验，并在 endpoint 声明鉴权时做 endpoint 级授权。具体 Service 由发布服务的 Node 处理。

## 文件结构

- `protocol.py`：SGP 二进制帧头、JSON/加密 JSON body 收发、消息构造、SHA256、HMAC、base64 工具。
- `relay.py`：中继服务器，处理认证、服务目录、LIST、CALL 转发和错误响应。
- `agent.py`：Node 的服务发布入口，发布 Service 并把 CALL 分发给 handler。
- `client.py`：Node 的服务调用入口，支持 LIST、示例 CALL 和通用 JSON CALL。
- `services.example.json`：扩展 Service 示例配置。
- `handlers/text_echo.py`：`text.echo` 示例 handler。
- `handlers/command_exec.py`：`command.exec` 示例 handler。
- `handlers/http_bundle.py`：`http.bundle` 示例 handler。
- `handlers/file_transfer.py`：扩展示例 `file.transfer` 的本地 handler。
- `Socket协议设计草案.md`：协议设计说明。

## 默认口令

- Relay 登录共享密钥：`sgp-demo-secret`
- Service 访问 token：`service-token`
- Endpoint 访问 token：`endpoint-token`

真实公网环境不应使用默认口令。本实验原型没有 TLS，因此仍不具备工业级传输安全；当前版本通过 challenge-response 派生会话密钥，认证成功后的帧 body 使用 HMAC keystream 加密，抓包时看不到 JSON 明文，也不会直接看到共享密钥、密钥哈希或 Service token。

## 最小协议演示

打开三个终端，均在本目录下运行。

### 1. 启动 Relay

```bash
python3 relay.py --host 127.0.0.1 --port 9000
```

Relay 负责接受 Node 连接、维护 Service 目录、校验认证信息，并把 `CALL` 路由到发布对应 Service 的 Node。Relay 还会维护服务租约并向空闲 Agent 发送 `PING` 保活，Agent 失联后会把相关 Service 标记为 offline。

### 2. 启动发布服务的 Node

```bash
python3 agent.py --relay-host 127.0.0.1 --relay-port 9000
```

该 Node 会通过 `HELLO -> AUTH -> PUBLISH` 流程发布三个示例 Service：

- `note-box`：`text.echo`
- `win-command`：`command.exec`
- `frontend-workspace`：`http.bundle`，包含 `page` 和 `api` endpoint

### 3. 启动调用服务的 Node

```bash
python3 client.py --relay-host 127.0.0.1 --relay-port 9000
```

菜单中可以执行：

- LIST 服务目录。
- CALL 短文本示例 Service。
- CALL 白名单命令示例 Service。
- CALL HTTP bundle 示例 Service。
- 演示错误 token 的 `403 SERVICE_TOKEN_INVALID`。
- 演示不存在服务的 `404 SERVICE_NOT_FOUND`。

## 示例 Service 调用

以下命令用于演示协议中的 `LIST` 和 `CALL`，它们不是新增协议命令，只是不同 Service 的 `payload.input` 示例。

### 保存 Client 连接配置

如果 Relay 不在本机，第一次运行时可以保存连接参数：

```bash
python3 client.py --relay-host 81.70.233.96 --relay-port 9000 --secret demo_secret --save-config
```

也可以直接复制并编辑配置文件：

```bash
cp client.config.example.json client.config.json
```

`client.config.json` 示例：

```json
{
  "relay_host": "81.70.233.96",
  "relay_port": 9000,
  "secret": "demo_secret",
  "service_token": "service-token",
  "endpoint_token": "endpoint-token"
}
```

之后 `client.py` 会默认读取 `client.config.json`，常用命令可以简化为：

```bash
python3 client.py
python3 client.py --list
python3 client.py --call text --text "hello"
python3 client.py --call command --command "pwd"
```

直接运行 `python3 client.py` 会登录一次并进入长连接交互模式，不需要每次重新认证。进入后可反复执行：

```text
sgp> list
sgp> text hello
sgp> cmd pwd
sgp> http /
sgp> call
sgp> config
sgp> set service-token your_service_token
sgp> save-config
sgp> quit
```

默认输出会整理成服务表格或调用结果；如果需要查看完整协议 JSON，可加：

```bash
python3 client.py --list --json
```

注意：`secret` 用于登录 Relay；`service_token` 用于调用 Agent 发布的 Service。若 `CALL` 返回 `SERVICE_TOKEN_INVALID`，说明 Relay 在转发前已拒绝请求，Agent 端不会收到这次调用。

### 查询服务目录

```bash
python3 client.py --list
```

对应协议动作是：

```text
Client -> Relay: LIST
Relay -> Client: services[]
```

服务目录中的 `contract` 包含 `input_schema`、`output_schema` 和示例输入输出。Client 可按 schema 构造请求，Relay 会在转发前校验 `payload.input`。

### 调用文本示例 Service

```bash
python3 client.py --call text --text "hello from mac"
```

对应协议动作是：

```text
Client -> Relay: CALL(service_id=note-box, input={"text": ...})
Relay -> Agent: CALL(service_id=note-box, input={"text": ...})
Agent -> Relay -> Client: output
```

### 调用白名单命令示例 Service

```bash
python3 client.py --call command --command "pwd"
python3 client.py --call command --command "git status"
```

该示例用于展示 Service 级策略：Agent 只执行 `metadata.allow_commands` 中声明的命令。

### 调用 HTTP bundle 示例 Service

先在本机启动一个简单 HTTP 服务：

```bash
python3 -m http.server 8000
```

再通过 SGP 调用 `frontend-workspace` 的 `page` endpoint：

```bash
python3 client.py --call http --endpoint page --method GET --path /
```

如果需要演示 `api` endpoint，可另起一个 3000 端口 HTTP 服务，或启动自己的本地 API。默认配置中 `page` 只需要 Service token，`api` 还需要 endpoint token：

```bash
python3 -m http.server 3000
python3 client.py --call http --endpoint api --endpoint-token endpoint-token --method GET --path /
```

### 演示错误处理

错误响应保留 `status/message`，并在 `payload.error` 中提供分级信息：`code`、`category`、`retryable`、`hint`，必要时还会带 `detail`。

错误 service token：

```bash
python3 client.py --call text --service-token wrong-token --text "should fail"
```

不存在的 service：

```bash
python3 client.py --call text --service-id missing-service --text "should fail"
```

停止发布服务的 Node 后再次发起调用，可观察到：

```text
503 AGENT_OFFLINE
```

## 扩展 Service 示例

扩展 Service 用来展示 SGP 的可维护性和扩展性。扩展时不需要修改 Relay 的协议命令，只需要让发布方 Node 声明新的 `service_type`、`contract`、`policy`，并在本机提供对应 handler。

### 1. 准备扩展配置

```bash
cp services.example.json services.json
```

编辑 `services.json` 后启动发布服务的 Node：

```bash
python3 agent.py --relay-host 127.0.0.1 --relay-port 9000 --services-config services.json
```

配置文件中的每个 Service 都会被发布到 Relay。Service 可以使用 Node 内置处理器，也可以绑定本地 handler 文件来自定义新的 `service_type`。

自定义 `service_type` 可以在 Service 中增加：

```json
{
  "service_id": "file-box",
  "service_type": "file.transfer",
  "handler": {
    "path": "handlers/file_transfer.py",
    "function": "handle"
  }
}
```

handler 文件中的函数签名为：

```python
def handle(service, input_obj):
    return 200, "OK", {"your": "output"}
```

handler 是发布方本机代码，调用方不能远程上传或修改 handler。Relay 不关心 handler 业务语义，只负责认证、策略检查和 CALL 转发。

### 2. 通用 JSON CALL

通用调用入口用于演示“协议不绑定具体业务类型”。调用方只要知道 Service 的 `contract`，就可以构造 `payload.input`。

```bash
python3 client.py --call generic --service-id custom-note --input-json '{"text":"hello custom"}'
python3 client.py --call generic --service-id custom-command --input-json '{"command":"pwd"}'
python3 client.py --call generic --service-id custom-web --input-json '{"endpoint_id":"page","method":"GET","path":"/","headers":{},"body_base64":""}'
```

### 3. 类 FTP 文件扩展示例

`services.example.json` 中提供了一个受限文件服务 `file-box`，其 `service_type` 为 `file.transfer`。它支持：

- `list`：列目录。
- `stat`：查看文件或目录信息。
- `read_chunk`：按 offset 分块读取文件，返回 base64。
- `write_chunk`：按 offset 分块写入文件，需要 `metadata.allow_upload=true`。

示例命令：

```bash
python3 client.py --call generic --service-id file-box --input-json '{"op":"list","path":"."}'
python3 client.py --call generic --service-id file-box --input-json '{"op":"read_chunk","path":"hello.txt","offset":0,"size":8192}'
python3 client.py --call generic --service-id file-box --input-json '{"op":"write_chunk","path":"upload.txt","offset":0,"data_base64":"aGVsbG8="}'
```

文件服务只能访问 `metadata.root_dir` 指定的目录，默认是 `shared_files`，路径会做越界检查。该服务是扩展示例，不是 SGP 第一版的核心功能。

## 录屏建议

1. 启动 `relay.py`，说明 Relay 是协议中继和服务目录。
2. 启动 `agent.py`，展示 Node 通过 `PUBLISH` 发布 3 个示例 Service。
3. 启动 `client.py`，选择 LIST，展示服务目录、endpoint、contract 和 lifecycle。
4. 调用 `note-box`，展示统一 `CALL` 可以承载文本示例。
5. 调用 `win-command`，输入 `pwd` 或 `git status`，展示 Service 级白名单。
6. 启动 `python3 -m http.server 8000`。
7. 调用 `frontend-workspace` 的 `page` endpoint，展示 HTTP body preview。
8. 选择错误 token 演示，展示 `403 SERVICE_TOKEN_INVALID`。
9. 选择不存在服务演示，展示 `404 SERVICE_NOT_FOUND`。
10. 停止发布服务的 Node 后再次调用服务，展示 `503 AGENT_OFFLINE`。
11. 如时间允许，再用 `services.example.json` 展示扩展 Service，强调 Relay 代码不需要理解文件业务。

## 与普通 RPC 的关系

SGP 承认并采用 RPC-style 的请求响应调用模型。它与普通 RPC 的区别在于：

- 调用对象不是固定函数，而是 Relay 目录中的 Service。
- 协议内置 `PUBLISH` 和 `LIST`，调用方可以动态发现服务。
- Agent 和 Client 都主动连接 Relay，适合 NAT 后个人设备服务暴露。
- 同一个 Agent 可以发布多个 Service；多个 Client 可以同时调用，Relay 按消息 id 分发响应。
- Relay 不仅转发，还做 session 校验、Service token 校验、payload 大小限制、超时、频率限制、服务租约和在线状态维护。
- Service 的具体输入输出由 `contract.input_schema`、`contract.output_schema` 和 example 描述，协议核心命令不随业务类型增加。

因此，SGP 可以被描述为“面向个人跨设备服务发现与受控调用的 RPC-style 应用层协议”。
