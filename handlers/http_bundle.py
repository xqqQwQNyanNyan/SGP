import http.client
from urllib.parse import urlsplit

from protocol import b64_decode, b64_encode


def safe_path(path):
    if not path:
        return "/"
    parsed = urlsplit(path)
    value = parsed.path or "/"
    if parsed.query:
        value += "?" + parsed.query
    return value


def handle(service, input_obj):
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
