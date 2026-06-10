import argparse
import http.client
import importlib.util
import json
import os
import shlex
import socket
import subprocess
import sys
from urllib.parse import urlsplit

from protocol import b64_decode, b64_encode, close_quietly, make_msg, make_resp, recv_msg, send_msg, sha256_text


DEFAULT_SERVICE_TOKEN = "service-token"


def build_services(service_token, http_page_port, http_api_port):
    token_hash = sha256_text(service_token)
    return [
        {
            "service_id": "note-box",
            "name": "Short Text Box",
            "service_type": "text.echo",
            "description": "Receive short text from remote client",
            "auth": {"access_token_hash": token_hash},
            "policy": {"max_payload_size": 2048, "timeout_sec": 3, "max_calls_per_minute": 30},
            "endpoints": [],
            "contract": {
                "example_input": {"text": "hello from mac"},
                "example_output": {"reply": "Agent received text"},
            },
            "metadata": {},
        },
        {
            "service_id": "win-command",
            "name": "Windows Command Runner",
            "service_type": "command.exec",
            "description": "Run whitelisted local commands",
            "auth": {"access_token_hash": token_hash},
            "policy": {"max_payload_size": 2048, "timeout_sec": 10, "max_calls_per_minute": 20},
            "endpoints": [],
            "contract": {
                "example_input": {"command": "git status"},
                "example_output": {"exit_code": 0, "stdout": "...", "stderr": ""},
            },
            "metadata": {
                "allow_commands": ["pwd", "dir", "ls", "git status", "python --version", "python3 --version"]
            },
        },
        {
            "service_id": "frontend-workspace",
            "name": "Frontend Workspace",
            "service_type": "http.bundle",
            "description": "Project-level HTTP service with page and API endpoints",
            "auth": {"access_token_hash": token_hash},
            "policy": {"max_payload_size": 65536, "timeout_sec": 5, "max_calls_per_minute": 30},
            "endpoints": [
                {
                    "endpoint_id": "page",
                    "protocol": "http",
                    "target_host": "127.0.0.1",
                    "target_port": http_page_port,
                    "allow_methods": ["GET", "POST"],
                    "description": "Local page server",
                },
                {
                    "endpoint_id": "api",
                    "protocol": "http",
                    "target_host": "127.0.0.1",
                    "target_port": http_api_port,
                    "allow_methods": ["GET", "POST"],
                    "description": "Local API server",
                },
            ],
            "contract": {
                "example_input": {
                    "endpoint_id": "page",
                    "method": "GET",
                    "path": "/",
                    "headers": {},
                    "body_base64": "",
                },
                "example_output": {"http_status": 200, "headers": {"Content-Type": "text/html"}, "body_base64": "..."},
            },
            "metadata": {},
        },
    ]


def normalize_service_auth(service, default_service_token):
    auth = service.setdefault("auth", {})
    if auth.get("access_token_hash"):
        return service
    token = auth.pop("access_token", None) or service.pop("access_token", None) or default_service_token
    auth["access_token_hash"] = sha256_text(token)
    return service


def load_services_config(path, default_service_token):
    base_dir = os.path.dirname(os.path.abspath(path))
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    services = data.get("services") if isinstance(data, dict) else data
    if not isinstance(services, list):
        raise ValueError("services config must be a list or an object with services list")
    normalized = []
    for service in services:
        if not isinstance(service, dict):
            raise ValueError("each service must be an object")
        if not service.get("service_id") or not service.get("service_type"):
            raise ValueError("each service needs service_id and service_type")
        handler = service.get("handler")
        if isinstance(handler, dict) and handler.get("path"):
            handler["path"] = os.path.abspath(os.path.join(base_dir, handler["path"]))
        normalized.append(normalize_service_auth(service, default_service_token))
    return normalized


def service_for_publish(service):
    published = dict(service)
    published.pop("handler", None)
    return published


def load_handler(service):
    handler = service.get("handler")
    if not isinstance(handler, dict):
        return None
    path = handler.get("path")
    function_name = handler.get("function", "handle")
    if not path:
        return None
    if not os.path.exists(path):
        raise ValueError(f"handler file not found for {service.get('service_id')}: {path}")
    module_name = "sgp_handler_" + service.get("service_id", "unknown").replace("-", "_")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load handler file: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    func = getattr(module, function_name, None)
    if not callable(func):
        raise ValueError(f"handler function not found: {function_name} in {path}")
    return func


def load_custom_handlers(services):
    handlers = {}
    for service in services:
        func = load_handler(service)
        if func:
            handlers[service["service_id"]] = func
            print(f"[agent] loaded handler for {service['service_id']} ({service['service_type']})")
    return handlers


def handle_text_echo(input_obj):
    text = str(input_obj.get("text", ""))
    return 200, "OK", {"reply": f"Agent received {len(text.encode('utf-8'))} bytes: {text}"}


def command_args(command):
    if os.name == "nt":
        if command == "dir":
            return ["cmd", "/c", "dir"]
        if command == "pwd":
            return ["cmd", "/c", "cd"]
    if command == "dir":
        return ["ls"]
    return shlex.split(command)


def handle_command(service, input_obj):
    command = str(input_obj.get("command", "")).strip()
    allowed = service.get("metadata", {}).get("allow_commands", [])
    if command not in allowed:
        return 403, "COMMAND_NOT_ALLOWED", {"allowed": allowed}
    try:
        result = subprocess.run(
            command_args(command),
            capture_output=True,
            text=True,
            timeout=float(service.get("policy", {}).get("timeout_sec", 10)),
            shell=False,
        )
        return 200, "OK", {
            "exit_code": result.returncode,
            "stdout": result.stdout[-4000:],
            "stderr": result.stderr[-4000:],
        }
    except subprocess.TimeoutExpired:
        return 408, "COMMAND_TIMEOUT", {"exit_code": -1, "stdout": "", "stderr": "timeout"}
    except OSError as exc:
        return 502, "COMMAND_FAILED", {"exit_code": -1, "stdout": "", "stderr": str(exc)}


def safe_path(path):
    if not path:
        return "/"
    parsed = urlsplit(path)
    value = parsed.path or "/"
    if parsed.query:
        value += "?" + parsed.query
    return value


def handle_http(service, input_obj):
    endpoint_id = input_obj.get("endpoint_id")
    method = str(input_obj.get("method", "GET")).upper()
    endpoint = None
    for item in service.get("endpoints", []):
        if item.get("endpoint_id") == endpoint_id:
            endpoint = item
            break
    if not endpoint:
        return 404, "ENDPOINT_NOT_FOUND", {}
    if method not in endpoint.get("allow_methods", ["GET"]):
        return 403, "METHOD_NOT_ALLOWED", {"allow_methods": endpoint.get("allow_methods", [])}

    body = b64_decode(input_obj.get("body_base64", ""))
    if len(body) > int(service.get("policy", {}).get("max_payload_size", 65536)):
        return 413, "BODY_TOO_LARGE", {}
    headers = input_obj.get("headers", {})
    if not isinstance(headers, dict):
        headers = {}

    conn = http.client.HTTPConnection(
        endpoint.get("target_host", "127.0.0.1"),
        int(endpoint.get("target_port", 80)),
        timeout=float(service.get("policy", {}).get("timeout_sec", 5)),
    )
    try:
        conn.request(method, safe_path(input_obj.get("path", "/")), body=body if method == "POST" else None, headers=headers)
        resp = conn.getresponse()
        data = resp.read(65536)
        return 200, "OK", {
            "http_status": resp.status,
            "headers": dict(resp.getheaders()),
            "body_base64": b64_encode(data),
            "body_preview": data[:500].decode("utf-8", errors="replace"),
        }
    except (OSError, http.client.HTTPException) as exc:
        return 502, "HTTP_REQUEST_FAILED", {"error": str(exc)}
    finally:
        conn.close()


def normalize_handler_result(result):
    if isinstance(result, tuple) and len(result) == 3:
        status, message, output = result
        return int(status), str(message), output
    if isinstance(result, dict) and {"status", "message", "output"} <= set(result.keys()):
        return int(result["status"]), str(result["message"]), result["output"]
    return 200, "OK", result


def handle_call(services_by_id, custom_handlers, req):
    service_id = req.get("service_id")
    service = services_by_id.get(service_id)
    if not service:
        return make_resp(req, "agent", 404, "SERVICE_NOT_FOUND")
    input_obj = req.get("payload", {}).get("input", {})
    service_type = service.get("service_type")
    if service_type == "text.echo":
        status, message, output = handle_text_echo(input_obj)
    elif service_type == "command.exec":
        status, message, output = handle_command(service, input_obj)
    elif service_type == "http.bundle":
        status, message, output = handle_http(service, input_obj)
    elif service_id in custom_handlers:
        try:
            result = custom_handlers[service_id](service, input_obj)
            status, message, output = normalize_handler_result(result)
        except Exception as exc:
            status, message, output = 502, "CUSTOM_HANDLER_FAILED", {"error": str(exc)}
    else:
        status, message, output = 502, "UNSUPPORTED_SERVICE_TYPE", {}
    return make_resp(req, "agent", status, message, {"output": output})


def login(sock, role, secret, name):
    hello = make_msg("HELLO", role, payload={"name": name})
    send_msg(sock, hello)
    resp = recv_msg(sock)
    if resp.get("status") != 200:
        raise RuntimeError(resp.get("message"))
    auth = make_msg("AUTH", role, payload={"auth_hash": sha256_text(secret)})
    send_msg(sock, auth)
    resp = recv_msg(sock)
    if resp.get("status") != 200:
        raise RuntimeError(resp.get("message"))
    return resp.get("payload", {}).get("token")


def main():
    parser = argparse.ArgumentParser(description="ServiceGate Protocol agent")
    parser.add_argument("--relay-host", default="127.0.0.1")
    parser.add_argument("--relay-port", type=int, default=9000)
    parser.add_argument("--secret", default="sgp-demo-secret")
    parser.add_argument("--service-token", default=DEFAULT_SERVICE_TOKEN)
    parser.add_argument("--page-port", type=int, default=8000)
    parser.add_argument("--api-port", type=int, default=3000)
    parser.add_argument("--services-config", help="JSON file that defines custom services")
    parser.add_argument("--name", default=socket.gethostname())
    args = parser.parse_args()

    if args.services_config:
        services = load_services_config(args.services_config, args.service_token)
    else:
        services = build_services(args.service_token, args.page_port, args.api_port)
    services_by_id = {item["service_id"]: item for item in services}
    custom_handlers = load_custom_handlers(services)
    sock = socket.create_connection((args.relay_host, args.relay_port), timeout=5)
    sock.settimeout(None)
    try:
        token = login(sock, "agent", args.secret, args.name)
        publish_services = [service_for_publish(service) for service in services]
        publish = make_msg("PUBLISH", "agent", token=token, payload={"services": publish_services})
        send_msg(sock, publish)
        resp = recv_msg(sock)
        if resp.get("status") not in (200, 201):
            raise RuntimeError(resp.get("message"))
        print(f"[agent] published {len(services)} services")
        print("[agent] waiting for CALL requests")
        while True:
            req = recv_msg(sock)
            if req.get("cmd") == "CALL":
                send_msg(sock, handle_call(services_by_id, custom_handlers, req))
            elif req.get("cmd") == "PING":
                send_msg(sock, make_resp(req, "agent", 200, "PONG"))
            else:
                send_msg(sock, make_resp(req, "agent", 400, "UNKNOWN_CMD"))
    except KeyboardInterrupt:
        print("\n[agent] stopped")
    except Exception as exc:
        print(f"[agent] error: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        close_quietly(sock)


if __name__ == "__main__":
    main()
