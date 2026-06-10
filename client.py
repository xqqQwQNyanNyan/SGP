import argparse
import json
import shlex
import socket
import sys
from pathlib import Path

from protocol import (
    b64_decode,
    b64_encode,
    auth_proof,
    close_quietly,
    endpoint_access_proof,
    make_msg,
    recv_msg,
    send_msg,
    service_access_proof,
    session_key_from_secret,
)

DEFAULT_CONFIG_PATH = "client.config.json"
DEFAULTS = {
    "relay_host": "127.0.0.1",
    "relay_port": 9000,
    "secret": "sgp-demo-secret",
    "service_token": "service-token",
    "endpoint_token": "endpoint-token",
}


def request(sock, msg, cipher_key=None):
    send_msg(sock, msg, cipher_key=cipher_key)
    return recv_msg(sock, cipher_key=cipher_key)


def login(sock, role, secret, name):
    resp = request(sock, make_msg("HELLO", role, payload={"name": name}))
    if resp.get("status") != 200:
        raise RuntimeError(resp.get("message"))
    challenge = resp.get("payload", {}).get("challenge")
    if not challenge:
        raise RuntimeError("AUTH_CHALLENGE_MISSING")
    cipher_key = session_key_from_secret(secret, challenge)
    send_msg(sock, make_msg("AUTH", role, payload={"auth_proof": auth_proof(secret, challenge)}))
    resp = recv_msg(sock, cipher_key=cipher_key)
    if resp.get("status") != 200:
        raise RuntimeError(resp.get("message"))
    return resp.get("payload", {}).get("token"), cipher_key


def print_json(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def error_hint(message):
    hints = {
        "AUTH_FAILED": "认证失败：共享密钥不对，请检查 --secret 或 client.config.json。",
        "SERVICE_TOKEN_INVALID": "Service token 不对。Relay 已拒绝本次 CALL，请求没有转发到 agent。",
        "ENDPOINT_TOKEN_INVALID": "Endpoint token 不对。Relay 已拒绝本次 CALL，请求没有转发到 agent。",
        "SERVICE_NOT_FOUND": "没有这个 service_id，先执行 --list 查看可用服务。",
        "AGENT_OFFLINE": "服务发布方不在线，等 agent 重连后再试。",
        "SCHEMA_VALIDATION_FAILED": "输入字段不符合该服务的 contract。",
        "CALL_TIMEOUT": "调用超时，可能是 agent 或后端 HTTP 服务响应太慢。",
        "HTTP_REQUEST_FAILED": "agent 后面的本地 HTTP 服务没起来或不可访问。",
    }
    return hints.get(message, message or "未知错误")


def print_status(resp):
    status = resp.get("status")
    message = resp.get("message", "")
    if status and status >= 400:
        print(f"失败 {status}: {error_hint(message)}")
        error = resp.get("payload", {}).get("error", {})
        if isinstance(error, dict):
            code = error.get("code")
            category = error.get("category")
            retryable = error.get("retryable")
            hint = error.get("hint")
            if code:
                print(f"错误码: {code}")
            if category:
                print(f"类型: {category}")
            if retryable is not None:
                print(f"可重试: {'是' if retryable else '否'}")
            if message == "SERVICE_TOKEN_INVALID":
                print("怎么改: 在 client.config.json 里设置 service_token，或在交互模式输入 set service-token <token>。")
            elif message == "ENDPOINT_TOKEN_INVALID":
                print("怎么改: 在 client.config.json 里设置 endpoint_token，或在交互模式输入 set endpoint-token <token>。")
            elif hint:
                print(f"提示: {hint}")
    else:
        print(f"成功 {status}: {message}")


def endpoint_summary(service):
    endpoints = service.get("endpoints", [])
    if not endpoints:
        return "-"
    parts = []
    for endpoint in endpoints:
        mark = " auth" if endpoint.get("auth_required") else ""
        methods = ",".join(endpoint.get("allow_methods", [])) or "-"
        parts.append(f"{endpoint.get('endpoint_id')}[{methods}{mark}]")
    return "; ".join(parts)


def print_services(resp):
    if resp.get("status") != 200:
        print_status(resp)
        return
    services = resp.get("payload", {}).get("services", [])
    if not services:
        print("当前没有发布中的服务。")
        return
    rows = []
    for item in services:
        lifecycle = item.get("lifecycle", {})
        rows.append(
            {
                "service_id": item.get("service_id", ""),
                "type": item.get("service_type", ""),
                "state": lifecycle.get("state", "online" if item.get("online") else "offline"),
                "timeout": str(item.get("policy", {}).get("timeout_sec", "-")),
                "endpoints": endpoint_summary(item),
            }
        )
    columns = [
        ("service_id", "SERVICE"),
        ("type", "TYPE"),
        ("state", "STATE"),
        ("timeout", "TIMEOUT"),
        ("endpoints", "ENDPOINTS"),
    ]
    widths = {
        key: max(len(title), *(len(str(row[key])) for row in rows))
        for key, title in columns
    }
    print(f"发现 {len(rows)} 个服务：")
    print("  ".join(title.ljust(widths[key]) for key, title in columns))
    print("  ".join("-" * widths[key] for key, _ in columns))
    for row in rows:
        print("  ".join(str(row[key]).ljust(widths[key]) for key, _ in columns))


def print_call_result(resp, show_http_preview=True):
    if resp.get("status", 0) >= 400:
        print_status(resp)
        return
    output = resp.get("payload", {}).get("output")
    print_status(resp)
    if output is None:
        return
    if isinstance(output, dict) and set(output.keys()) == {"reply"}:
        print(output.get("reply", ""))
        return
    if isinstance(output, dict) and "entries" in output:
        entries = output.get("entries", [])
        print(f"path: {output.get('path', '.')}")
        if not entries:
            print("(empty)")
            return
        for item in entries:
            kind = "dir " if item.get("is_dir") else "file"
            print(f"{kind:4} {str(item.get('size', '-')).rjust(8)}  {item.get('name')}")
        return
    if isinstance(output, dict) and {"path", "is_dir", "size"} <= set(output.keys()):
        kind = "dir" if output.get("is_dir") else "file"
        print(f"{output.get('path')}  {kind}  {output.get('size')} bytes")
        return
    if isinstance(output, dict) and "data_base64" in output:
        data = b64_decode(output.get("data_base64", ""))
        print(f"path: {output.get('path')}")
        print(f"offset: {output.get('offset')}  next: {output.get('next_offset')}  size: {output.get('size')}  eof: {output.get('eof')}")
        print("\n--- data preview ---")
        print(data[:2000].decode("utf-8", errors="replace"))
        print("--- end preview ---")
        return
    if isinstance(output, dict) and "written" in output:
        print(f"wrote {output.get('written')} bytes to {output.get('path')} (size: {output.get('size')})")
        return
    if isinstance(output, dict) and "body_base64" in output:
        http_status = output.get("http_status")
        if http_status:
            print(f"HTTP {http_status}")
        preview = output.get("body_preview")
        if preview:
            print("\n--- body preview ---")
            print(preview)
            print("--- end preview ---")
        elif show_http_preview:
            show_http_body(resp)
        return
    if isinstance(output, dict) and {"exit_code", "stdout", "stderr"} <= set(output.keys()):
        print(f"exit_code: {output.get('exit_code')}")
        stdout = output.get("stdout") or ""
        stderr = output.get("stderr") or ""
        if stdout:
            print("\n--- stdout ---")
            print(stdout.rstrip())
        if stderr:
            print("\n--- stderr ---")
            print(stderr.rstrip())
        return
    print_json(output)


def list_services(sock, token, cipher_key, raw_json=False, quiet=False):
    resp = request(sock, make_msg("LIST", "client", token=token), cipher_key=cipher_key)
    if quiet:
        return resp
    if raw_json:
        print_json(resp)
    else:
        print_services(resp)
    return resp


def call_service(sock, token, cipher_key, service_id, access_token, input_obj, endpoint_token=None, raw_json=False):
    msg = make_msg(
        "CALL",
        "client",
        token=token,
        service_id=service_id,
        payload={"input": input_obj},
    )
    msg["payload"]["access_proof"] = service_access_proof(access_token, msg["id"])
    endpoint_id = input_obj.get("endpoint_id") if isinstance(input_obj, dict) else None
    if endpoint_token and endpoint_id:
        msg["payload"]["endpoint_access_proof"] = endpoint_access_proof(endpoint_token, msg["id"], service_id, endpoint_id)
    resp = request(
        sock,
        msg,
        cipher_key=cipher_key,
    )
    if raw_json:
        print_json(resp)
    else:
        print_call_result(resp)
    return resp


def show_http_body(resp):
    output = resp.get("payload", {}).get("output", {})
    body_base64 = output.get("body_base64")
    if not body_base64:
        return
    body = b64_decode(body_base64)
    print("\n--- HTTP body preview ---")
    print(body[:1000].decode("utf-8", errors="replace"))
    print("--- end preview ---")


def services_from_response(resp):
    if resp.get("status") != 200:
        return []
    services = resp.get("payload", {}).get("services", [])
    return services if isinstance(services, list) else []


def find_service(services, service_type=None, service_id=None):
    for service in services:
        if service_id and service.get("service_id") != service_id:
            continue
        if service_type and service.get("service_type") != service_type:
            continue
        return service
    return None


def find_service_by_name(services, name):
    for service in services:
        if service.get("service_id") == name or service.get("service_type") == name:
            return service
    return None


def print_service_help(service):
    service_id = service.get("service_id")
    service_type = service.get("service_type")
    print(f"{service_id} ({service_type})")
    if service.get("description"):
        print(service.get("description"))

    if service_type == "text.echo":
        print("\n用法:")
        print(f"  text hello")
        print(f"  generic {service_id} '{{\"text\":\"hello\"}}'")
        return

    if service_type == "command.exec":
        allowed = service.get("metadata", {}).get("allow_commands", [])
        print("\n用法:")
        print("  cmd pwd")
        print(f"  generic {service_id} '{{\"command\":\"pwd\"}}'")
        if allowed:
            print("\n允许的命令:")
            for item in allowed:
                print(f"  {item}")
        return

    if service_type == "http.bundle":
        print("\n用法:")
        print("  http /")
        print(f"  generic {service_id} '{{\"endpoint_id\":\"page\",\"method\":\"GET\",\"path\":\"/\",\"headers\":{{}},\"body_base64\":\"\"}}'")
        endpoints = service.get("endpoints", [])
        if endpoints:
            print("\nEndpoints:")
            for endpoint in endpoints:
                auth = " auth" if endpoint.get("auth_required") else ""
                methods = ",".join(endpoint.get("allow_methods", [])) or "-"
                print(f"  {endpoint.get('endpoint_id')} [{methods}{auth}] {endpoint.get('description', '')}")
        return

    if service_type == "file.transfer":
        print("\n用法:")
        print("  file ls [path]")
        print("  file stat <path>")
        print("  file read <path> [offset] [size]")
        print("  file write <path> <text>")
        print(f"  generic {service_id} '{{\"op\":\"list\",\"path\":\".\"}}'")
        return

    print("\n通用调用:")
    print(f"  generic {service_id} '<JSON input>'")
    contract = service.get("contract", {})
    example = contract.get("example_input")
    if example is not None:
        print("\n示例 input:")
        print_json(example)


def print_shell_help():
    print(
        """
可用命令：
  list                         刷新并显示服务列表
  help <service_id>            查看某个服务怎么用
  call                         从服务列表选择一个服务并调用
  text <内容>                  调用第一个 text.echo 服务
  cmd <命令>                   调用第一个 command.exec 服务
  http [路径]                  调用第一个 http.bundle 的 page endpoint
  file ls [path]               列出 file.transfer 目录
  file stat <path>             查看 file.transfer 文件信息
  file read <path> [offset]    读取 file.transfer 文件块
  file write <path> <text>     写入 file.transfer 文件
  generic <service_id> <JSON>  通用 JSON 调用
  config                       显示当前配置文件和连接配置
  set service-token <token>    修改当前会话的 Service token
  set endpoint-token <token>   修改当前会话的 Endpoint token
  save-config                  保存当前配置到 client.config.json
  raw on|off                   开关原始 JSON 输出
  help                         显示帮助
  quit                         退出
""".strip()
    )


def choose_service(services):
    if not services:
        print("当前没有服务，先执行 list。")
        return None
    print("选择服务：")
    for index, service in enumerate(services, 1):
        state = service.get("lifecycle", {}).get("state", "online" if service.get("online") else "offline")
        print(f"  {index}. {service.get('service_id')} ({service.get('service_type')}, {state})")
    raw = input("service number/id: ").strip()
    if not raw:
        return None
    if raw.isdigit():
        index = int(raw)
        if 1 <= index <= len(services):
            return services[index - 1]
    return find_service(services, service_id=raw)


def prompt_json(default="{}"):
    while True:
        raw = input(f"input JSON [{default}]: ").strip() or default
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            print(f"bad JSON: {exc}")
            continue
        if not isinstance(value, dict):
            print("input JSON must be an object")
            continue
        return value


def call_selected_service(sock, token, cipher_key, service, service_token, endpoint_token, raw_json=False):
    service_id = service.get("service_id")
    service_type = service.get("service_type")
    if service_type == "text.echo":
        text = input("text: ")
        call_service(sock, token, cipher_key, service_id, service_token, {"text": text}, raw_json=raw_json)
    elif service_type == "command.exec":
        allowed = service.get("metadata", {}).get("allow_commands", [])
        if allowed:
            print("allowed:", ", ".join(allowed))
        command = input("command: ").strip()
        call_service(sock, token, cipher_key, service_id, service_token, {"command": command}, raw_json=raw_json)
    elif service_type == "http.bundle":
        endpoints = service.get("endpoints", [])
        endpoint_ids = [item.get("endpoint_id") for item in endpoints if item.get("endpoint_id")]
        default_endpoint = endpoint_ids[0] if endpoint_ids else "page"
        endpoint_id = input(f"endpoint [{default_endpoint}]: ").strip() or default_endpoint
        endpoint_auth = any(item.get("endpoint_id") == endpoint_id and item.get("auth_required") for item in endpoints)
        selected_endpoint_token = endpoint_token if endpoint_auth else None
        if endpoint_auth:
            selected_endpoint_token = input("endpoint token [default]: ").strip() or endpoint_token
        method = input("method [GET]: ").strip().upper() or "GET"
        path = input("path [/]: ").strip() or "/"
        body = ""
        if method == "POST":
            body = b64_encode(input("body: "))
        call_service(
            sock,
            token,
            cipher_key,
            service_id,
            service_token,
            {"endpoint_id": endpoint_id, "method": method, "path": path, "headers": {}, "body_base64": body},
            endpoint_token=selected_endpoint_token,
            raw_json=raw_json,
        )
    else:
        input_obj = prompt_json()
        call_service(sock, token, cipher_key, service_id, service_token, input_obj, raw_json=raw_json)


def refresh_services(sock, token, cipher_key, raw_json=False, quiet=False):
    resp = list_services(sock, token, cipher_key, raw_json=raw_json, quiet=quiet)
    return services_from_response(resp)


def ensure_services(services, sock, token, cipher_key, raw_json):
    if services:
        return services
    return refresh_services(sock, token, cipher_key, raw_json=raw_json, quiet=True)


def call_file_service(sock, token, cipher_key, service, service_token, args, raw_json=False):
    if not args:
        print("用法: file ls/stat/read/write ...，或 help <file-service-id>")
        return
    op = args[0]
    if op in ("ls", "list"):
        input_obj = {"op": "list", "path": args[1] if len(args) > 1 else "."}
    elif op == "stat":
        if len(args) < 2:
            print("用法: file stat <path>")
            return
        input_obj = {"op": "stat", "path": args[1]}
    elif op == "read":
        if len(args) < 2:
            print("用法: file read <path> [offset] [size]")
            return
        input_obj = {"op": "read_chunk", "path": args[1]}
        try:
            if len(args) > 2:
                input_obj["offset"] = int(args[2])
            if len(args) > 3:
                input_obj["size"] = int(args[3])
        except ValueError:
            print("offset 和 size 必须是数字")
            return
    elif op == "write":
        if len(args) < 3:
            print("用法: file write <path> <text>")
            return
        input_obj = {"op": "write_chunk", "path": args[1], "offset": 0, "data_base64": b64_encode(" ".join(args[2:]))}
    else:
        print("未知 file 操作。可用: ls, stat, read, write")
        return
    call_service(sock, token, cipher_key, service.get("service_id"), service_token, input_obj, raw_json=raw_json)


def mask_secret(value):
    if not value:
        return ""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def print_config(settings):
    print(f"配置文件: {settings['config']}")
    print(f"relay_host: {settings['relay_host']}")
    print(f"relay_port: {settings['relay_port']}")
    print(f"secret: {mask_secret(settings['secret'])}")
    print(f"service_token: {mask_secret(settings['service_token'])}")
    print(f"endpoint_token: {mask_secret(settings['endpoint_token'])}")


def menu(sock, token, cipher_key, settings, raw_json=False):
    services = []
    current_raw_json = raw_json
    print(f"已登录 Relay。配置文件：{settings['config']}。输入 help 查看命令，输入 quit 退出。")
    while True:
        raw = input("sgp> ").strip()
        if not raw:
            continue
        try:
            parts = shlex.split(raw)
        except ValueError as exc:
            print(f"bad command: {exc}")
            continue
        if not parts:
            continue
        command = parts[0].lower()
        args = parts[1:]

        if command in ("quit", "exit", "q", "0"):
            return
        if command in ("help", "h", "?"):
            if args:
                services = ensure_services(services, sock, token, cipher_key, current_raw_json)
                service = find_service_by_name(services, args[0])
                if service:
                    print_service_help(service)
                else:
                    print(f"没有找到服务: {args[0]}")
            else:
                print_shell_help()
            continue
        if command == "config":
            print_config(settings)
            continue
        if command == "set":
            if len(args) < 2 or args[0] not in ("service-token", "endpoint-token"):
                print("用法: set service-token <token> 或 set endpoint-token <token>")
                continue
            if args[0] == "service-token":
                settings["service_token"] = " ".join(args[1:])
                print("已更新当前会话的 service_token。需要持久化请输入 save-config。")
            else:
                settings["endpoint_token"] = " ".join(args[1:])
                print("已更新当前会话的 endpoint_token。需要持久化请输入 save-config。")
            continue
        if command == "save-config":
            save_config(settings["config"], settings)
            continue
        if command in ("list", "ls", "1"):
            services = refresh_services(sock, token, cipher_key, raw_json=current_raw_json)
            continue
        if command == "raw":
            if not args or args[0] not in ("on", "off"):
                print("用法: raw on 或 raw off")
                continue
            current_raw_json = args[0] == "on"
            print(f"原始 JSON 输出已{'开启' if current_raw_json else '关闭'}")
            continue

        services = ensure_services(services, sock, token, cipher_key, current_raw_json)

        if command == "call":
            service = choose_service(services)
            if service:
                call_selected_service(sock, token, cipher_key, service, settings["service_token"], settings["endpoint_token"], raw_json=current_raw_json)
            continue
        if command == "text":
            service = find_service(services, service_type="text.echo")
            if not service:
                print("没有 text.echo 服务。")
                continue
            text = " ".join(args) if args else input("text: ")
            call_service(sock, token, cipher_key, service.get("service_id"), settings["service_token"], {"text": text}, raw_json=current_raw_json)
            continue
        if command in ("cmd", "command"):
            service = find_service(services, service_type="command.exec")
            if not service:
                print("没有 command.exec 服务。")
                continue
            run_command = " ".join(args) if args else input("command: ").strip()
            call_service(sock, token, cipher_key, service.get("service_id"), settings["service_token"], {"command": run_command}, raw_json=current_raw_json)
            continue
        if command == "http":
            service = find_service(services, service_type="http.bundle")
            if not service:
                print("没有 http.bundle 服务。")
                continue
            path = args[0] if args else "/"
            call_service(
                sock,
                token,
                cipher_key,
                service.get("service_id"),
                settings["service_token"],
                {"endpoint_id": "page", "method": "GET", "path": path, "headers": {}, "body_base64": ""},
                raw_json=current_raw_json,
            )
            continue
        if command == "file":
            service = find_service(services, service_type="file.transfer")
            if not service:
                print("没有 file.transfer 服务。")
                continue
            call_file_service(sock, token, cipher_key, service, settings["service_token"], args, raw_json=current_raw_json)
            continue
        if command == "generic":
            if len(args) < 2:
                print("用法: generic <service_id> '<JSON>'")
                continue
            service_id = args[0]
            try:
                input_obj = json.loads(" ".join(args[1:]))
            except json.JSONDecodeError as exc:
                print(f"bad JSON: {exc}")
                continue
            if not isinstance(input_obj, dict):
                print("input JSON must be an object")
                continue
            call_service(sock, token, cipher_key, service_id, settings["service_token"], input_obj, endpoint_token=settings["endpoint_token"], raw_json=current_raw_json)
            continue

        print("未知命令，输入 help 查看用法。")


def load_config(path):
    config_path = Path(path)
    if not config_path.exists():
        return {}
    try:
        with config_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"配置文件读取失败 {config_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"配置文件格式错误 {config_path}: 顶层必须是 object")
    return data


def config_value(source, key):
    if isinstance(source, dict):
        return source[key]
    return getattr(source, key)


def save_config(path, source):
    config_path = Path(path)
    data = {
        "relay_host": config_value(source, "relay_host"),
        "relay_port": config_value(source, "relay_port"),
        "secret": config_value(source, "secret"),
        "service_token": config_value(source, "service_token"),
        "endpoint_token": config_value(source, "endpoint_token"),
    }
    with config_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"已保存配置：{config_path}")


def apply_config(args):
    config = load_config(args.config)
    for key, default in DEFAULTS.items():
        value = getattr(args, key)
        if value is None:
            setattr(args, key, config.get(key, default))
    return args


def settings_from_args(args):
    return {
        "config": args.config,
        "relay_host": args.relay_host,
        "relay_port": args.relay_port,
        "secret": args.secret,
        "service_token": args.service_token,
        "endpoint_token": args.endpoint_token,
    }


def main():
    parser = argparse.ArgumentParser(description="ServiceGate Protocol client")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="client config file")
    parser.add_argument("--save-config", action="store_true", help="save connection options to config file")
    parser.add_argument("--json", action="store_true", help="print raw protocol JSON")
    parser.add_argument("--relay-host")
    parser.add_argument("--relay-port", type=int)
    parser.add_argument("--secret")
    parser.add_argument("--service-token")
    parser.add_argument("--endpoint-token")
    parser.add_argument("--name", default=socket.gethostname())
    parser.add_argument("--list", action="store_true", help="list services and exit")
    parser.add_argument("--call", choices=["text", "command", "http", "generic"], help="run one call and exit")
    parser.add_argument("--service-id", help="override default service_id for one-shot calls")
    parser.add_argument("--input-json", default="{}", help="input object for --call generic")
    parser.add_argument("--text", default="hello from client")
    parser.add_argument("--command", default="pwd")
    parser.add_argument("--endpoint", default="page")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--path", default="/")
    args = parser.parse_args()
    args = apply_config(args)
    settings = settings_from_args(args)

    if args.save_config:
        save_config(args.config, settings)
        if not (args.list or args.call):
            return

    sock = socket.create_connection((args.relay_host, args.relay_port), timeout=5)
    sock.settimeout(None)
    try:
        token, cipher_key = login(sock, "client", args.secret, args.name)
        if args.list:
            list_services(sock, token, cipher_key, raw_json=args.json)
            return
        if args.call == "text":
            call_service(sock, token, cipher_key, args.service_id or "note-box", args.service_token, {"text": args.text}, raw_json=args.json)
            return
        if args.call == "command":
            call_service(sock, token, cipher_key, args.service_id or "win-command", args.service_token, {"command": args.command}, raw_json=args.json)
            return
        if args.call == "http":
            resp = call_service(
                sock,
                token,
                cipher_key,
                args.service_id or "frontend-workspace",
                args.service_token,
                {"endpoint_id": args.endpoint, "method": args.method.upper(), "path": args.path, "headers": {}, "body_base64": ""},
                endpoint_token=args.endpoint_token,
                raw_json=args.json,
            )
            if args.json:
                show_http_body(resp)
            return
        if args.call == "generic":
            if not args.service_id:
                raise RuntimeError("--service-id is required for --call generic")
            input_obj = json.loads(args.input_json)
            if not isinstance(input_obj, dict):
                raise RuntimeError("--input-json must be a JSON object")
            call_service(sock, token, cipher_key, args.service_id, args.service_token, input_obj, endpoint_token=args.endpoint_token, raw_json=args.json)
            return
        menu(sock, token, cipher_key, settings, raw_json=args.json)
    except KeyboardInterrupt:
        print("\n[client] stopped")
    except Exception as exc:
        print(f"[client] error: {error_hint(str(exc))}", file=sys.stderr)
        sys.exit(1)
    finally:
        close_quietly(sock)


if __name__ == "__main__":
    main()
