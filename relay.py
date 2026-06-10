import argparse
import copy
import json
import secrets
import socket
import threading
import time
from collections import deque

from protocol import ProtocolError, close_quietly, make_msg, make_resp, recv_msg, send_msg, sha256_text


class RelayState:
    def __init__(self, shared_secret):
        self.shared_secret_hash = sha256_text(shared_secret)
        self.sessions = {}
        self.services = {}
        self.lock = threading.Lock()

    def new_session(self, role, conn):
        token = secrets.token_hex(16)
        with self.lock:
            self.sessions[token] = {"role": role, "conn": conn, "created_at": time.time()}
        return token

    def check_session(self, token, role=None):
        with self.lock:
            session = self.sessions.get(token)
        if not session:
            return False
        return role is None or session["role"] == role

    def remove_conn(self, conn):
        with self.lock:
            dead_tokens = [t for t, s in self.sessions.items() if s["conn"] is conn]
            for token in dead_tokens:
                self.sessions.pop(token, None)
            for item in self.services.values():
                if item["conn"] is conn:
                    item["online"] = False
                    item["conn"] = None

    def publish(self, services, conn, agent_token):
        with self.lock:
            for service in services:
                service_id = service.get("service_id")
                if not service_id:
                    continue
                old = self.services.get(service_id, {})
                self.services[service_id] = {
                    "service": service,
                    "conn": conn,
                    "agent_token": agent_token,
                    "online": True,
                    "lock": old.get("lock") or threading.Lock(),
                    "call_times": old.get("call_times") or deque(),
                }

    def list_public_services(self):
        with self.lock:
            items = list(self.services.values())
        return [public_service(item["service"], item["online"]) for item in items]

    def get_service(self, service_id):
        with self.lock:
            return self.services.get(service_id)


def public_service(service, online):
    safe = copy.deepcopy(service)
    safe["online"] = online
    safe.pop("auth", None)
    safe.pop("handler", None)
    safe["endpoints"] = [
        {
            "endpoint_id": ep.get("endpoint_id"),
            "protocol": ep.get("protocol"),
            "description": ep.get("description", ""),
            "allow_methods": ep.get("allow_methods", []),
        }
        for ep in safe.get("endpoints", [])
    ]
    metadata = safe.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("target_host", None)
        metadata.pop("target_port", None)
    return safe


def payload_size(obj):
    return len(json.dumps(obj, ensure_ascii=False).encode("utf-8"))


def check_rate_limit(item):
    service = item["service"]
    limit = service.get("policy", {}).get("max_calls_per_minute")
    if not limit:
        return True
    now = time.time()
    calls = item["call_times"]
    while calls and now - calls[0] > 60:
        calls.popleft()
    if len(calls) >= int(limit):
        return False
    calls.append(now)
    return True


def handle_client_call(state, req):
    token = req.get("token")
    if not state.check_session(token, "client"):
        return make_resp(req, "relay", 401, "UNAUTHORIZED")

    service_id = req.get("service_id")
    item = state.get_service(service_id)
    if not item:
        return make_resp(req, "relay", 404, "SERVICE_NOT_FOUND")
    if not item.get("online") or item.get("conn") is None:
        return make_resp(req, "relay", 503, "AGENT_OFFLINE")

    service = item["service"]
    access_token = req.get("payload", {}).get("access_token", "")
    expected_hash = service.get("auth", {}).get("access_token_hash", "")
    if sha256_text(access_token) != expected_hash:
        return make_resp(req, "relay", 403, "SERVICE_TOKEN_INVALID")

    max_payload = int(service.get("policy", {}).get("max_payload_size", 65536))
    input_obj = req.get("payload", {}).get("input", {})
    if payload_size(input_obj) > max_payload:
        return make_resp(req, "relay", 413, "PAYLOAD_TOO_LARGE")
    if not check_rate_limit(item):
        return make_resp(req, "relay", 429, "TOO_MANY_REQUESTS")

    timeout = float(service.get("policy", {}).get("timeout_sec", 5))
    agent_req = make_msg(
        "CALL",
        "relay",
        msg_type="REQ",
        msg_id=req.get("id"),
        service_id=service_id,
        payload={"input": input_obj},
    )
    with item["lock"]:
        conn = item.get("conn")
        if conn is None:
            return make_resp(req, "relay", 503, "AGENT_OFFLINE")
        old_timeout = conn.gettimeout()
        try:
            conn.settimeout(timeout)
            send_msg(conn, agent_req)
            agent_resp = recv_msg(conn)
        except socket.timeout:
            return make_resp(req, "relay", 408, "CALL_TIMEOUT")
        except (EOFError, OSError):
            item["online"] = False
            item["conn"] = None
            return make_resp(req, "relay", 503, "AGENT_OFFLINE")
        except ProtocolError as exc:
            return make_resp(req, "relay", exc.status, exc.message)
        finally:
            try:
                conn.settimeout(old_timeout)
            except OSError:
                pass

    return make_resp(
        req,
        "relay",
        agent_resp.get("status", 502),
        agent_resp.get("message", "AGENT_ERROR"),
        payload=agent_resp.get("payload", {}),
    )


def handle_connection(state, conn, addr):
    role = None
    token = None
    print(f"[relay] connected {addr}")
    try:
        while True:
            req = recv_msg(conn)
            cmd = req.get("cmd")
            if cmd == "HELLO":
                role = req.get("role")
                if role not in ("agent", "client"):
                    send_msg(conn, make_resp(req, "relay", 400, "BAD_ROLE"))
                else:
                    send_msg(conn, make_resp(req, "relay", 200, "HELLO_OK", {"role": role}))
            elif cmd == "AUTH":
                auth_hash = req.get("payload", {}).get("auth_hash")
                if auth_hash != state.shared_secret_hash:
                    send_msg(conn, make_resp(req, "relay", 401, "AUTH_FAILED"))
                else:
                    token = state.new_session(role or req.get("role"), conn)
                    send_msg(conn, make_resp(req, "relay", 200, "AUTH_OK", {"token": token}))
            elif cmd == "PUBLISH":
                if not state.check_session(req.get("token"), "agent"):
                    send_msg(conn, make_resp(req, "relay", 401, "UNAUTHORIZED"))
                    continue
                services = req.get("payload", {}).get("services", [])
                state.publish(services, conn, req.get("token"))
                print(f"[relay] published {len(services)} services")
                send_msg(conn, make_resp(req, "relay", 201, "PUBLISH_OK", {"count": len(services)}))
                if role == "agent":
                    while True:
                        time.sleep(3600)
            elif cmd == "LIST":
                if not state.check_session(req.get("token"), "client"):
                    send_msg(conn, make_resp(req, "relay", 401, "UNAUTHORIZED"))
                else:
                    send_msg(conn, make_resp(req, "relay", 200, "OK", {"services": state.list_public_services()}))
            elif cmd == "CALL":
                send_msg(conn, handle_client_call(state, req))
            elif cmd == "PING":
                send_msg(conn, make_resp(req, "relay", 200, "PONG", {"ts": time.time()}))
            else:
                send_msg(conn, make_resp(req, "relay", 400, "UNKNOWN_CMD"))
    except EOFError:
        pass
    except Exception as exc:
        print(f"[relay] connection error {addr}: {exc}")
    finally:
        state.remove_conn(conn)
        close_quietly(conn)
        print(f"[relay] disconnected {addr}")


def main():
    parser = argparse.ArgumentParser(description="ServiceGate Protocol relay")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--secret", default="sgp-demo-secret")
    args = parser.parse_args()

    state = RelayState(args.secret)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen()
    print(f"[relay] listening on {args.host}:{args.port}")
    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_connection, args=(state, conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[relay] stopped")
    finally:
        close_quietly(server)


if __name__ == "__main__":
    main()
