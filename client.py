import argparse
import json
import socket
import sys

from protocol import b64_decode, b64_encode, close_quietly, make_msg, recv_msg, send_msg, sha256_text


def request(sock, msg):
    send_msg(sock, msg)
    return recv_msg(sock)


def login(sock, role, secret, name):
    resp = request(sock, make_msg("HELLO", role, payload={"name": name}))
    if resp.get("status") != 200:
        raise RuntimeError(resp.get("message"))
    resp = request(sock, make_msg("AUTH", role, payload={"auth_hash": sha256_text(secret)}))
    if resp.get("status") != 200:
        raise RuntimeError(resp.get("message"))
    return resp.get("payload", {}).get("token")


def print_json(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def list_services(sock, token):
    resp = request(sock, make_msg("LIST", "client", token=token))
    print_json(resp)
    return resp


def call_service(sock, token, service_id, access_token, input_obj):
    resp = request(
        sock,
        make_msg(
            "CALL",
            "client",
            token=token,
            service_id=service_id,
            payload={"access_token": access_token, "input": input_obj},
        ),
    )
    print_json(resp)
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


def menu(sock, token, default_service_token):
    while True:
        print("\nServiceGate Client")
        print("1. LIST services")
        print("2. CALL note-box text.echo")
        print("3. CALL win-command command.exec")
        print("4. CALL frontend-workspace http.bundle")
        print("5. Demo 403 with bad service token")
        print("6. Demo 404 with missing service")
        print("7. Generic CALL with JSON input")
        print("0. Exit")
        choice = input("> ").strip()
        if choice == "1":
            list_services(sock, token)
        elif choice == "2":
            text = input("text: ")
            call_service(sock, token, "note-box", default_service_token, {"text": text})
        elif choice == "3":
            command = input("command (pwd/dir/ls/git status): ").strip()
            call_service(sock, token, "win-command", default_service_token, {"command": command})
        elif choice == "4":
            endpoint_id = input("endpoint (page/api) [page]: ").strip() or "page"
            method = input("method [GET]: ").strip().upper() or "GET"
            path = input("path [/]: ").strip() or "/"
            body = ""
            if method == "POST":
                body = b64_encode(input("body: "))
            resp = call_service(
                sock,
                token,
                "frontend-workspace",
                default_service_token,
                {"endpoint_id": endpoint_id, "method": method, "path": path, "headers": {}, "body_base64": body},
            )
            show_http_body(resp)
        elif choice == "5":
            call_service(sock, token, "note-box", "wrong-token", {"text": "should fail"})
        elif choice == "6":
            call_service(sock, token, "missing-service", default_service_token, {"text": "should fail"})
        elif choice == "7":
            service_id = input("service_id: ").strip()
            access_token = input("access_token [default]: ").strip() or default_service_token
            raw = input("input JSON: ").strip() or "{}"
            try:
                input_obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                print(f"bad JSON: {exc}")
                continue
            if not isinstance(input_obj, dict):
                print("input JSON must be an object")
                continue
            call_service(sock, token, service_id, access_token, input_obj)
        elif choice == "0":
            return
        else:
            print("unknown choice")


def main():
    parser = argparse.ArgumentParser(description="ServiceGate Protocol client")
    parser.add_argument("--relay-host", default="127.0.0.1")
    parser.add_argument("--relay-port", type=int, default=9000)
    parser.add_argument("--secret", default="sgp-demo-secret")
    parser.add_argument("--service-token", default="service-token")
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

    sock = socket.create_connection((args.relay_host, args.relay_port), timeout=5)
    sock.settimeout(None)
    try:
        token = login(sock, "client", args.secret, args.name)
        if args.list:
            list_services(sock, token)
            return
        if args.call == "text":
            call_service(sock, token, args.service_id or "note-box", args.service_token, {"text": args.text})
            return
        if args.call == "command":
            call_service(sock, token, args.service_id or "win-command", args.service_token, {"command": args.command})
            return
        if args.call == "http":
            resp = call_service(
                sock,
                token,
                args.service_id or "frontend-workspace",
                args.service_token,
                {"endpoint_id": args.endpoint, "method": args.method.upper(), "path": args.path, "headers": {}, "body_base64": ""},
            )
            show_http_body(resp)
            return
        if args.call == "generic":
            if not args.service_id:
                raise RuntimeError("--service-id is required for --call generic")
            input_obj = json.loads(args.input_json)
            if not isinstance(input_obj, dict):
                raise RuntimeError("--input-json must be a JSON object")
            call_service(sock, token, args.service_id, args.service_token, input_obj)
            return
        menu(sock, token, args.service_token)
    except KeyboardInterrupt:
        print("\n[client] stopped")
    except Exception as exc:
        print(f"[client] error: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        close_quietly(sock)


if __name__ == "__main__":
    main()
