import argparse
import importlib.util
import json
import os
import socket
import sys
import threading

from protocol import (
    auth_proof,
    close_quietly,
    make_msg,
    make_resp,
    recv_msg,
    send_msg,
    session_key_from_secret,
    sha256_text,
)


DEFAULT_SERVICE_TOKEN = "service-token"
DEFAULT_ENDPOINT_TOKEN = "endpoint-token"


def builtin_handler_path(filename):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "handlers", filename)


def build_services(service_token, endpoint_token, http_page_port, http_api_port):
    token_hash = sha256_text(service_token)
    endpoint_token_hash = sha256_text(endpoint_token)
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
                "input_schema": {
                    "type": "object",
                    "required": ["text"],
                    "properties": {
                        "text": {"type": "string", "maxLength": 1024}
                    },
                    "additionalProperties": False,
                },
                "output_schema": {
                    "type": "object",
                    "required": ["reply"],
                    "properties": {
                        "reply": {"type": "string"}
                    },
                    "additionalProperties": False,
                },
                "example_input": {"text": "hello from mac"},
                "example_output": {"reply": "Agent received text"},
            },
            "metadata": {},
            "handler": {"path": builtin_handler_path("text_echo.py"), "function": "handle"},
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
                "input_schema": {
                    "type": "object",
                    "required": ["command"],
                    "properties": {
                        "command": {"type": "string", "enum": ["pwd", "dir", "ls", "git status", "python --version", "python3 --version"]}
                    },
                    "additionalProperties": False,
                },
                "output_schema": {
                    "type": "object",
                    "required": ["exit_code", "stdout", "stderr"],
                    "properties": {
                        "exit_code": {"type": "integer"},
                        "stdout": {"type": "string"},
                        "stderr": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
                "example_input": {"command": "git status"},
                "example_output": {"exit_code": 0, "stdout": "...", "stderr": ""},
            },
            "metadata": {
                "allow_commands": ["pwd", "dir", "ls", "git status", "python --version", "python3 --version"]
            },
            "handler": {"path": builtin_handler_path("command_exec.py"), "function": "handle"},
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
                    "auth": {"access_token_hash": endpoint_token_hash},
                    "description": "Local API server",
                },
            ],
            "contract": {
                "input_schema": {
                    "type": "object",
                    "required": ["endpoint_id", "method", "path"],
                    "properties": {
                        "endpoint_id": {"type": "string", "enum": ["page", "api"]},
                        "method": {"type": "string", "enum": ["GET", "POST"]},
                        "path": {"type": "string", "minLength": 1, "maxLength": 2048},
                        "headers": {"type": "object"},
                        "body_base64": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
                "output_schema": {
                    "type": "object",
                    "required": ["http_status", "headers", "body_base64"],
                    "properties": {
                        "http_status": {"type": "integer"},
                        "headers": {"type": "object"},
                        "body_base64": {"type": "string"},
                        "body_preview": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
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
            "handler": {"path": builtin_handler_path("http_bundle.py"), "function": "handle"},
        },
    ]


def normalize_service_auth(service, default_service_token):
    auth = service.setdefault("auth", {})
    if auth.get("access_token_hash"):
        return service
    token = auth.pop("access_token", None) or service.pop("access_token", None) or default_service_token
    auth["access_token_hash"] = sha256_text(token)
    return service


def normalize_endpoint_auth(service, default_endpoint_token):
    for endpoint in service.get("endpoints", []):
        if not isinstance(endpoint, dict):
            continue
        auth = endpoint.get("auth")
        if not isinstance(auth, dict):
            continue
        if auth.get("access_token_hash"):
            continue
        token = auth.pop("access_token", None)
        if token is None and auth.get("required"):
            token = default_endpoint_token
        if token is not None:
            auth["access_token_hash"] = sha256_text(token)
    return service


def load_services_config(path, default_service_token, default_endpoint_token):
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
        normalize_endpoint_auth(service, default_endpoint_token)
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
    if service_id in custom_handlers:
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
    challenge = resp.get("payload", {}).get("challenge")
    if not challenge:
        raise RuntimeError("AUTH_CHALLENGE_MISSING")
    cipher_key = session_key_from_secret(secret, challenge)
    auth = make_msg("AUTH", role, payload={"auth_proof": auth_proof(secret, challenge)})
    send_msg(sock, auth)
    resp = recv_msg(sock, cipher_key=cipher_key)
    if resp.get("status") != 200:
        raise RuntimeError(resp.get("message"))
    return resp.get("payload", {}).get("token"), cipher_key


def send_locked(sock, msg, cipher_key, send_lock):
    with send_lock:
        send_msg(sock, msg, cipher_key=cipher_key)


def handle_call_worker(sock, cipher_key, send_lock, services_by_id, custom_handlers, req):
    service_id = req.get("service_id")
    print(f"[agent] CALL received service_id={service_id} id={req.get('id')}")
    resp = handle_call(services_by_id, custom_handlers, req)
    print(f"[agent] CALL completed service_id={service_id} status={resp.get('status')} message={resp.get('message')}")
    try:
        send_locked(sock, resp, cipher_key, send_lock)
    except OSError:
        pass


def main():
    parser = argparse.ArgumentParser(description="ServiceGate Protocol agent")
    parser.add_argument("--relay-host", default="127.0.0.1")
    parser.add_argument("--relay-port", type=int, default=9000)
    parser.add_argument("--secret", default="sgp-demo-secret")
    parser.add_argument("--service-token", default=DEFAULT_SERVICE_TOKEN)
    parser.add_argument("--endpoint-token", default=DEFAULT_ENDPOINT_TOKEN)
    parser.add_argument("--page-port", type=int, default=8000)
    parser.add_argument("--api-port", type=int, default=3000)
    parser.add_argument("--services-config", help="JSON file that defines custom services")
    parser.add_argument("--name", default=socket.gethostname())
    args = parser.parse_args()

    if args.services_config:
        services = load_services_config(args.services_config, args.service_token, args.endpoint_token)
    else:
        services = build_services(args.service_token, args.endpoint_token, args.page_port, args.api_port)
    services_by_id = {item["service_id"]: item for item in services}
    custom_handlers = load_custom_handlers(services)
    sock = socket.create_connection((args.relay_host, args.relay_port), timeout=5)
    sock.settimeout(None)
    send_lock = threading.Lock()
    try:
        token, cipher_key = login(sock, "agent", args.secret, args.name)
        publish_services = [service_for_publish(service) for service in services]
        publish = make_msg("PUBLISH", "agent", token=token, payload={"services": publish_services})
        send_locked(sock, publish, cipher_key, send_lock)
        resp = recv_msg(sock, cipher_key=cipher_key)
        if resp.get("status") not in (200, 201):
            raise RuntimeError(resp.get("message"))
        print(f"[agent] published {len(services)} services")
        print("[agent] waiting for CALL requests")
        while True:
            req = recv_msg(sock, cipher_key=cipher_key)
            if req.get("cmd") == "CALL":
                threading.Thread(
                    target=handle_call_worker,
                    args=(sock, cipher_key, send_lock, services_by_id, custom_handlers, req),
                    daemon=True,
                ).start()
            elif req.get("cmd") == "PING":
                send_locked(sock, make_resp(req, "agent", 200, "PONG"), cipher_key, send_lock)
            else:
                send_locked(sock, make_resp(req, "agent", 400, "UNKNOWN_CMD"), cipher_key, send_lock)
    except KeyboardInterrupt:
        print("\n[agent] stopped")
    except Exception as exc:
        print(f"[agent] error: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        close_quietly(sock)


if __name__ == "__main__":
    main()
