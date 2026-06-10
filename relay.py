import argparse
import copy
import json
import queue
import secrets
import socket
import threading
import time
from collections import deque

from protocol import (
    ProtocolError,
    SchemaValidationError,
    close_quietly,
    constant_time_equal,
    make_msg,
    make_resp,
    recv_msg,
    send_msg,
    hmac_sha256_text,
    session_key_from_secret_hash,
    sha256_text,
    validate_schema,
)


SESSION_TTL_SEC = 60 * 60
SERVICE_LEASE_TTL_SEC = 45
HEARTBEAT_INTERVAL_SEC = 15
HEARTBEAT_TIMEOUT_SEC = 3
HEARTBEAT_FAIL_LIMIT = 2


def relay_log(event, **fields):
    entry = {"ts": round(time.time(), 3), "component": "relay", "event": event}
    entry.update(fields)
    print(json.dumps(entry, ensure_ascii=False, separators=(",", ":")))


class AgentChannel:
    def __init__(self, state, conn, cipher_key):
        self.state = state
        self.conn = conn
        self.cipher_key = cipher_key
        self.send_lock = threading.Lock()
        self.pending = {}
        self.pending_lock = threading.Lock()
        self.closed = threading.Event()

    def start(self):
        threading.Thread(target=self._reader, daemon=True).start()

    def request(self, msg, timeout):
        msg_id = msg.get("id")
        waiter = queue.Queue(maxsize=1)
        with self.pending_lock:
            if self.closed.is_set():
                raise EOFError("agent channel closed")
            self.pending[msg_id] = waiter
        try:
            with self.send_lock:
                send_msg(self.conn, msg, cipher_key=self.cipher_key)
            result = waiter.get(timeout=timeout)
            if isinstance(result, BaseException):
                raise result
            return result
        except queue.Empty as exc:
            raise socket.timeout("agent response timeout") from exc
        except OSError:
            self.close()
            raise
        finally:
            with self.pending_lock:
                self.pending.pop(msg_id, None)

    def close(self):
        if not self.closed.is_set():
            self.closed.set()
            self.state.mark_conn_offline(self.conn, "offline")
            self._fail_pending(EOFError("agent channel closed"))

    def _reader(self):
        try:
            while not self.closed.is_set():
                msg = recv_msg(self.conn, cipher_key=self.cipher_key)
                msg_id = msg.get("id")
                with self.pending_lock:
                    waiter = self.pending.get(msg_id)
                if waiter:
                    waiter.put(msg)
        except (EOFError, OSError, ProtocolError):
            pass
        finally:
            self.close()

    def _fail_pending(self, exc):
        with self.pending_lock:
            waiters = list(self.pending.values())
            self.pending.clear()
        for waiter in waiters:
            try:
                waiter.put_nowait(exc)
            except queue.Full:
                pass


class RelayState:
    def __init__(self, shared_secret):
        self.shared_secret_hash = sha256_text(shared_secret)
        self.sessions = {}
        self.services = {}
        self.lock = threading.Lock()

    def new_session(self, role, conn, cipher_key):
        token = secrets.token_hex(16)
        with self.lock:
            self.sessions[token] = {
                "role": role,
                "conn": conn,
                "cipher_key": cipher_key,
                "channel": None,
                "created_at": time.time(),
            }
        return token

    def attach_channel(self, token, channel):
        with self.lock:
            session = self.sessions.get(token)
            if session:
                session["channel"] = channel

    def check_session(self, token, role=None):
        with self.lock:
            session = self.sessions.get(token)
            if not session:
                return False
            if time.time() - session["created_at"] > SESSION_TTL_SEC:
                self.sessions.pop(token, None)
                return False
            if session["conn"] is None:
                return False
            session_role = session["role"]
        return role is None or session_role == role

    def validate_auth_proof(self, challenge, proof):
        if not challenge or not proof:
            return False
        expected = hmac_sha256_text(self.shared_secret_hash, f"sgp-auth:{challenge}")
        return constant_time_equal(proof, expected)

    def validate_service_proof(self, access_proof, msg_id, expected_hash):
        if not access_proof or not msg_id or not expected_hash:
            return False
        expected = hmac_sha256_text(expected_hash, f"sgp-service:{msg_id}")
        return constant_time_equal(access_proof, expected)

    def validate_endpoint_proof(self, access_proof, msg_id, service_id, endpoint_id, expected_hash):
        if not access_proof or not msg_id or not service_id or not endpoint_id or not expected_hash:
            return False
        expected = hmac_sha256_text(expected_hash, f"sgp-endpoint:{msg_id}:{service_id}:{endpoint_id}")
        return constant_time_equal(access_proof, expected)

    def remove_conn(self, conn):
        with self.lock:
            dead_tokens = [t for t, s in self.sessions.items() if s["conn"] is conn]
            for token in dead_tokens:
                self.sessions.pop(token, None)
        self.mark_conn_offline(conn, "offline")

    def publish(self, services, conn, agent_token):
        now = time.time()
        with self.lock:
            session = self.sessions.get(agent_token, {})
            for service in services:
                service_id = service.get("service_id")
                if not service_id:
                    continue
                old = self.services.get(service_id, {})
                self.services[service_id] = {
                    "service": service,
                    "conn": conn,
                    "agent_token": agent_token,
                    "cipher_key": session.get("cipher_key"),
                    "channel": session.get("channel"),
                    "online": True,
                    "lifecycle": "online",
                    "call_times": old.get("call_times") or deque(),
                    "published_at": old.get("published_at") or now,
                    "last_seen": now,
                    "last_ping_at": 0,
                    "heartbeat_failures": 0,
                }

    def list_public_services(self):
        with self.lock:
            items = list(self.services.values())
        return [add_lifecycle_view(public_service(item["service"], item["online"]), item) for item in items]

    def get_service(self, service_id):
        with self.lock:
            return self.services.get(service_id)

    def touch_conn(self, conn):
        now = time.time()
        with self.lock:
            for item in self.services.values():
                if item.get("conn") is conn:
                    item["last_seen"] = now
                    item["heartbeat_failures"] = 0
                    item["lifecycle"] = "online"
                    item["online"] = True

    def mark_conn_unhealthy(self, conn):
        with self.lock:
            for item in self.services.values():
                if item.get("conn") is conn:
                    item["heartbeat_failures"] = item.get("heartbeat_failures", 0) + 1
                    item["lifecycle"] = "suspect"
                    if item["heartbeat_failures"] >= HEARTBEAT_FAIL_LIMIT:
                        item["online"] = False
                        item["conn"] = None
                        item["lifecycle"] = "offline"

    def mark_conn_offline(self, conn, lifecycle="offline"):
        with self.lock:
            for item in self.services.values():
                if item.get("conn") is conn:
                    item["online"] = False
                    item["conn"] = None
                    item["lifecycle"] = lifecycle

    def agents_due_for_heartbeat(self):
        now = time.time()
        due = {}
        with self.lock:
            for item in self.services.values():
                conn = item.get("conn")
                if not item.get("online") or conn is None:
                    continue
                if now - item.get("last_seen", 0) <= HEARTBEAT_INTERVAL_SEC:
                    continue
                if now - item.get("last_ping_at", 0) <= HEARTBEAT_INTERVAL_SEC:
                    continue
                key = id(conn)
                if key not in due:
                    due[key] = {
                        "conn": conn,
                        "channel": item.get("channel"),
                    }
                item["last_ping_at"] = now
                item["lifecycle"] = "probing"
        return list(due.values())

    def expire_stale_services(self):
        now = time.time()
        with self.lock:
            for item in self.services.values():
                conn = item.get("conn")
                if not item.get("online") or conn is None:
                    continue
                if now - item.get("last_seen", 0) > SERVICE_LEASE_TTL_SEC:
                    item["online"] = False
                    item["conn"] = None
                    item["lifecycle"] = "expired"


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
            "auth_required": bool(ep.get("auth", {}).get("access_token_hash")),
        }
        for ep in safe.get("endpoints", [])
    ]
    metadata = safe.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("target_host", None)
        metadata.pop("target_port", None)
    return safe


def add_lifecycle_view(service, item):
    service["lifecycle"] = {
        "state": item.get("lifecycle", "online" if item.get("online") else "offline"),
        "lease_ttl_sec": SERVICE_LEASE_TTL_SEC,
        "heartbeat_interval_sec": HEARTBEAT_INTERVAL_SEC,
        "last_seen_age_sec": max(0, int(time.time() - item.get("last_seen", time.time()))),
    }
    return service


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


def find_endpoint(service, endpoint_id):
    if not endpoint_id:
        return None
    for endpoint in service.get("endpoints", []):
        if endpoint.get("endpoint_id") == endpoint_id:
            return endpoint
    return None


def handle_client_call(state, req):
    service_id = req.get("service_id")
    started_at = time.time()
    relay_log("call_received", id=req.get("id"), service_id=service_id)
    token = req.get("token")
    if not state.check_session(token, "client"):
        resp = make_resp(req, "relay", 401, "UNAUTHORIZED")
        relay_log("call_rejected", id=req.get("id"), service_id=service_id, status=401, message="UNAUTHORIZED")
        return resp

    item = state.get_service(service_id)
    if not item:
        resp = make_resp(req, "relay", 404, "SERVICE_NOT_FOUND")
        relay_log("call_rejected", id=req.get("id"), service_id=service_id, status=404, message="SERVICE_NOT_FOUND")
        return resp
    if not item.get("online") or item.get("conn") is None:
        resp = make_resp(req, "relay", 503, "AGENT_OFFLINE")
        relay_log("call_rejected", id=req.get("id"), service_id=service_id, status=503, message="AGENT_OFFLINE")
        return resp

    service = item["service"]
    access_proof = req.get("payload", {}).get("access_proof", "")
    expected_hash = service.get("auth", {}).get("access_token_hash", "")
    if not state.validate_service_proof(access_proof, req.get("id"), expected_hash):
        resp = make_resp(req, "relay", 403, "SERVICE_TOKEN_INVALID")
        relay_log("call_rejected", id=req.get("id"), service_id=service_id, status=403, message="SERVICE_TOKEN_INVALID")
        return resp

    max_payload = int(service.get("policy", {}).get("max_payload_size", 65536))
    input_obj = req.get("payload", {}).get("input", {})
    if payload_size(input_obj) > max_payload:
        resp = make_resp(req, "relay", 413, "PAYLOAD_TOO_LARGE")
        relay_log("call_rejected", id=req.get("id"), service_id=service_id, status=413, message="PAYLOAD_TOO_LARGE")
        return resp
    input_schema = service.get("contract", {}).get("input_schema")
    if input_schema:
        try:
            validate_schema(input_obj, input_schema)
        except SchemaValidationError as exc:
            resp = make_resp(
                req,
                "relay",
                400,
                "SCHEMA_VALIDATION_FAILED",
                {"schema_error": exc.to_detail()},
            )
            relay_log("call_rejected", id=req.get("id"), service_id=service_id, status=400, message="SCHEMA_VALIDATION_FAILED")
            return resp
    endpoint_id = input_obj.get("endpoint_id")
    endpoint = find_endpoint(service, endpoint_id)
    endpoint_hash = ""
    if endpoint:
        endpoint_hash = endpoint.get("auth", {}).get("access_token_hash", "")
    if endpoint_hash:
        endpoint_proof = req.get("payload", {}).get("endpoint_access_proof", "")
        if not state.validate_endpoint_proof(endpoint_proof, req.get("id"), service_id, endpoint_id, endpoint_hash):
            resp = make_resp(
                req,
                "relay",
                403,
                "ENDPOINT_TOKEN_INVALID",
                {"endpoint_id": endpoint_id},
            )
            relay_log("call_rejected", id=req.get("id"), service_id=service_id, status=403, message="ENDPOINT_TOKEN_INVALID")
            return resp
    if not check_rate_limit(item):
        resp = make_resp(req, "relay", 429, "TOO_MANY_REQUESTS")
        relay_log("call_rejected", id=req.get("id"), service_id=service_id, status=429, message="TOO_MANY_REQUESTS")
        return resp

    timeout = float(service.get("policy", {}).get("timeout_sec", 5))
    agent_req = make_msg(
        "CALL",
        "relay",
        msg_type="REQ",
        msg_id=req.get("id"),
        service_id=service_id,
        payload={"input": input_obj},
    )
    conn = item.get("conn")
    channel = item.get("channel")
    if conn is None or channel is None:
        resp = make_resp(req, "relay", 503, "AGENT_OFFLINE")
        relay_log("call_rejected", id=req.get("id"), service_id=service_id, status=503, message="AGENT_OFFLINE")
        return resp
    try:
        agent_resp = channel.request(agent_req, timeout)
        state.touch_conn(conn)
    except socket.timeout:
        resp = make_resp(req, "relay", 408, "CALL_TIMEOUT")
        relay_log("call_failed", id=req.get("id"), service_id=service_id, status=408, message="CALL_TIMEOUT")
        return resp
    except (EOFError, OSError):
        state.mark_conn_offline(conn, "offline")
        resp = make_resp(req, "relay", 503, "AGENT_OFFLINE")
        relay_log("call_failed", id=req.get("id"), service_id=service_id, status=503, message="AGENT_OFFLINE")
        return resp
    except ProtocolError as exc:
        resp = make_resp(req, "relay", exc.status, exc.message)
        relay_log("call_failed", id=req.get("id"), service_id=service_id, status=exc.status, message=exc.message)
        return resp

    resp = make_resp(
        req,
        "relay",
        agent_resp.get("status", 502),
        agent_resp.get("message", "AGENT_ERROR"),
        payload=agent_resp.get("payload", {}),
    )
    relay_log(
        "call_completed",
        id=req.get("id"),
        service_id=service_id,
        status=resp.get("status"),
        message=resp.get("message"),
        duration_ms=int((time.time() - started_at) * 1000),
    )
    return resp


def handle_connection(state, conn, addr):
    role = None
    token = None
    auth_challenge = None
    cipher_key = None
    relay_log("connection_open", peer=f"{addr[0]}:{addr[1]}")
    try:
        while True:
            req = recv_msg(conn, cipher_key=cipher_key)
            cmd = req.get("cmd")
            if cmd == "HELLO":
                role = req.get("role")
                if role not in ("agent", "client"):
                    send_msg(conn, make_resp(req, "relay", 400, "BAD_ROLE"))
                else:
                    auth_challenge = secrets.token_hex(16)
                    send_msg(
                        conn,
                        make_resp(
                            req,
                            "relay",
                            200,
                            "HELLO_OK",
                            {
                                "role": role,
                                "auth_method": "sha256-challenge-v1",
                                "challenge": auth_challenge,
                                "session_ttl_sec": SESSION_TTL_SEC,
                            },
                        ),
                    )
            elif cmd == "AUTH":
                proof = req.get("payload", {}).get("auth_proof")
                if not role or not auth_challenge:
                    send_msg(conn, make_resp(req, "relay", 400, "BAD_AUTH_FLOW"))
                elif not state.validate_auth_proof(auth_challenge, proof):
                    send_msg(conn, make_resp(req, "relay", 401, "AUTH_FAILED"))
                    relay_log("auth_failed", peer=f"{addr[0]}:{addr[1]}", role=role)
                else:
                    cipher_key = session_key_from_secret_hash(state.shared_secret_hash, auth_challenge)
                    token = state.new_session(role, conn, cipher_key)
                    auth_challenge = None
                    send_msg(
                        conn,
                        make_resp(req, "relay", 200, "AUTH_OK", {"token": token, "expires_in": SESSION_TTL_SEC}),
                        cipher_key=cipher_key,
                    )
                    relay_log("auth_ok", peer=f"{addr[0]}:{addr[1]}", role=role)
            elif cmd == "PUBLISH":
                if not state.check_session(req.get("token"), "agent"):
                    send_msg(conn, make_resp(req, "relay", 401, "UNAUTHORIZED"), cipher_key=cipher_key)
                    continue
                services = req.get("payload", {}).get("services", [])
                channel = AgentChannel(state, conn, cipher_key)
                state.attach_channel(req.get("token"), channel)
                state.publish(services, conn, req.get("token"))
                channel.start()
                relay_log("publish", peer=f"{addr[0]}:{addr[1]}", count=len(services), service_ids=[s.get("service_id") for s in services])
                send_msg(
                    conn,
                    make_resp(
                        req,
                        "relay",
                        201,
                        "PUBLISH_OK",
                        {
                            "count": len(services),
                            "lease_ttl_sec": SERVICE_LEASE_TTL_SEC,
                            "heartbeat_interval_sec": HEARTBEAT_INTERVAL_SEC,
                        },
                    ),
                    cipher_key=cipher_key,
                )
                if role == "agent":
                    channel.closed.wait()
                    return
            elif cmd == "LIST":
                if not state.check_session(req.get("token"), "client"):
                    send_msg(conn, make_resp(req, "relay", 401, "UNAUTHORIZED"), cipher_key=cipher_key)
                    relay_log("list_rejected", peer=f"{addr[0]}:{addr[1]}", status=401, message="UNAUTHORIZED")
                else:
                    services = state.list_public_services()
                    send_msg(
                        conn,
                        make_resp(req, "relay", 200, "OK", {"services": services}),
                        cipher_key=cipher_key,
                    )
                    relay_log("list", peer=f"{addr[0]}:{addr[1]}", count=len(services))
            elif cmd == "CALL":
                send_msg(conn, handle_client_call(state, req), cipher_key=cipher_key)
            elif cmd == "PING":
                send_msg(conn, make_resp(req, "relay", 200, "PONG", {"ts": time.time()}), cipher_key=cipher_key)
            else:
                send_msg(conn, make_resp(req, "relay", 400, "UNKNOWN_CMD"), cipher_key=cipher_key)
    except EOFError:
        pass
    except Exception as exc:
        relay_log("connection_error", peer=f"{addr[0]}:{addr[1]}", error=str(exc))
    finally:
        state.remove_conn(conn)
        close_quietly(conn)
        relay_log("connection_close", peer=f"{addr[0]}:{addr[1]}")


def heartbeat_monitor(state):
    while True:
        time.sleep(HEARTBEAT_INTERVAL_SEC)
        state.expire_stale_services()
        for agent in state.agents_due_for_heartbeat():
            conn = agent["conn"]
            channel = agent.get("channel")
            if channel is None:
                state.mark_conn_unhealthy(conn)
                continue
            try:
                ping = make_msg("PING", "relay", payload={"ts": time.time()})
                resp = channel.request(ping, HEARTBEAT_TIMEOUT_SEC)
                if resp.get("cmd") == "PING" and resp.get("status") == 200:
                    state.touch_conn(conn)
                else:
                    state.mark_conn_unhealthy(conn)
            except (EOFError, OSError, socket.timeout, ProtocolError):
                state.mark_conn_unhealthy(conn)


def main():
    parser = argparse.ArgumentParser(description="ServiceGate Protocol relay")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--secret", default="sgp-demo-secret")
    args = parser.parse_args()

    state = RelayState(args.secret)
    threading.Thread(target=heartbeat_monitor, args=(state,), daemon=True).start()
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
