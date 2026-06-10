import base64
import hashlib
import hmac
import itertools
import json
import secrets
import socket
import struct
import threading
import uuid
import zlib


VERSION = "1.0"
MAX_FRAME_SIZE = 1024 * 1024
FRAME_MAGIC = b"SGP1"
FRAME_MAJOR = 1
FRAME_MINOR = 0
FRAME_HEADER_LEN = 24
FRAME_BODY_JSON = 1
FRAME_BODY_ENCRYPTED_JSON = 2
FRAME_FLAG_NONE = 0
ENCRYPTION_NONCE_LEN = 12
ENCRYPTION_TAG_LEN = 32
FRAME_HEADER_STRUCT = struct.Struct("!4sBBHBBHIII")

ERROR_CATALOG = {
    "BAD_FRAME_HEADER": ("protocol", "frame", "Frame header is malformed."),
    "BAD_FRAME_MAGIC": ("protocol", "frame", "Frame magic does not match SGP."),
    "FRAME_VERSION_NOT_SUPPORTED": ("protocol", "version", "Frame version is not supported."),
    "BAD_FRAME_HEADER_LENGTH": ("protocol", "frame", "Frame header length is invalid."),
    "FRAME_BODY_TYPE_NOT_SUPPORTED": ("protocol", "frame", "Frame body type is not supported."),
    "BAD_FRAME_RESERVED": ("protocol", "frame", "Reserved frame fields are invalid."),
    "BAD_FRAME_LENGTH": ("protocol", "frame", "Frame body length is invalid."),
    "BAD_FRAME_HEADER_CRC": ("protocol", "frame", "Frame header checksum validation failed."),
    "FRAME_TOO_LARGE": ("protocol", "frame", "Frame body exceeds the maximum size."),
    "BAD_JSON": ("protocol", "body", "Frame body is not valid JSON."),
    "VERSION_NOT_SUPPORTED": ("protocol", "version", "Message version is not supported."),
    "BAD_ENCRYPTED_BODY": ("protocol", "crypto", "Encrypted frame body is malformed."),
    "BAD_ENCRYPTED_BODY_TAG": ("protocol", "crypto", "Encrypted frame authentication failed."),
    "ENCRYPTION_KEY_REQUIRED": ("protocol", "crypto", "Encrypted frame received before session key setup."),
    "UNAUTHORIZED": (None, "auth", "Session token is missing, invalid, or expired."),
    "AUTH_FAILED": (None, "auth", "Authentication proof validation failed."),
    "BAD_AUTH_FLOW": (None, "auth", "Authentication command sequence is invalid."),
    "BAD_ROLE": (None, "request", "Connection role is invalid."),
    "SERVICE_TOKEN_INVALID": ("relay", "authz", "Service access proof validation failed."),
    "ENDPOINT_TOKEN_INVALID": ("relay", "authz", "Endpoint access proof validation failed."),
    "SERVICE_NOT_FOUND": ("relay", "routing", "Service id is not registered."),
    "AGENT_OFFLINE": ("relay", "routing", "Service publisher is not online."),
    "PAYLOAD_TOO_LARGE": ("relay", "policy", "Request payload exceeds service policy."),
    "SCHEMA_VALIDATION_FAILED": ("relay", "schema", "Request input does not match service schema."),
    "TOO_MANY_REQUESTS": ("relay", "policy", "Service rate limit exceeded."),
    "CALL_TIMEOUT": ("relay", "routing", "Agent did not respond before the call timeout."),
    "UNKNOWN_CMD": (None, "request", "Command is not supported."),
    "COMMAND_NOT_ALLOWED": ("agent", "handler", "Service handler rejected the request."),
    "COMMAND_TIMEOUT": ("agent", "handler", "Service handler timed out."),
    "COMMAND_FAILED": ("agent", "handler", "Service handler failed to execute."),
    "ENDPOINT_NOT_FOUND": ("agent", "handler", "Service handler could not resolve the endpoint."),
    "METHOD_NOT_ALLOWED": ("agent", "handler", "Service handler rejected the HTTP method."),
    "BODY_TOO_LARGE": ("agent", "handler", "Service handler rejected the request body size."),
    "HTTP_REQUEST_FAILED": ("agent", "handler", "Service handler could not complete the HTTP request."),
    "CUSTOM_HANDLER_FAILED": ("agent", "handler", "Service handler raised an exception."),
    "UNSUPPORTED_SERVICE_TYPE": ("agent", "handler", "No handler is registered for this service."),
    "DIR_NOT_FOUND": ("agent", "handler", "Service handler could not resolve the directory."),
    "PATH_NOT_FOUND": ("agent", "handler", "Service handler could not resolve the path."),
    "FILE_NOT_FOUND": ("agent", "handler", "Service handler could not resolve the file."),
    "UPLOAD_DISABLED": ("agent", "handler", "Service handler rejected the write request."),
    "CHUNK_TOO_LARGE": ("agent", "handler", "Service handler rejected the chunk size."),
    "UNKNOWN_FILE_OP": ("agent", "handler", "Service handler rejected the file operation."),
}

_seq_lock = threading.Lock()
_seq_counter = itertools.count(1)


class ProtocolError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


class SchemaValidationError(Exception):
    def __init__(self, path, message):
        super().__init__(f"{path}: {message}")
        self.path = path
        self.message = message

    def to_detail(self):
        return {"path": self.path, "reason": self.message}


def _schema_type_matches(value, expected_type):
    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "number":
        return (isinstance(value, int) or isinstance(value, float)) and not isinstance(value, bool)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "null":
        return value is None
    return True


def _type_name(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    return type(value).__name__


def validate_schema(value, schema, path="$"):
    if not isinstance(schema, dict):
        return

    expected_type = schema.get("type")
    if isinstance(expected_type, list):
        if not any(_schema_type_matches(value, item) for item in expected_type):
            raise SchemaValidationError(path, f"expected one of {expected_type}, got {_type_name(value)}")
    elif expected_type and not _schema_type_matches(value, expected_type):
        raise SchemaValidationError(path, f"expected {expected_type}, got {_type_name(value)}")

    if "enum" in schema and value not in schema["enum"]:
        raise SchemaValidationError(path, f"expected one of {schema['enum']}")

    if isinstance(value, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                raise SchemaValidationError(f"{path}.{key}", "required field is missing")

        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for key, child_schema in properties.items():
                if key in value:
                    validate_schema(value[key], child_schema, f"{path}.{key}")

        if schema.get("additionalProperties") is False and isinstance(properties, dict):
            allowed = set(properties.keys())
            extra = sorted(set(value.keys()) - allowed)
            if extra:
                raise SchemaValidationError(path, f"unexpected field: {extra[0]}")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < int(schema["minItems"]):
            raise SchemaValidationError(path, f"expected at least {schema['minItems']} items")
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            raise SchemaValidationError(path, f"expected at most {schema['maxItems']} items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                validate_schema(item, item_schema, f"{path}[{index}]")

    if isinstance(value, str):
        if "minLength" in schema and len(value) < int(schema["minLength"]):
            raise SchemaValidationError(path, f"expected length >= {schema['minLength']}")
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            raise SchemaValidationError(path, f"expected length <= {schema['maxLength']}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise SchemaValidationError(path, f"expected value >= {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            raise SchemaValidationError(path, f"expected value <= {schema['maximum']}")


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hmac_sha256_text(key, text):
    return hmac.new(key.encode("utf-8"), text.encode("utf-8"), hashlib.sha256).hexdigest()


def hmac_sha256_bytes(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def constant_time_equal(left, right):
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return hmac.compare_digest(left, right)


def auth_proof(secret, challenge):
    secret_hash = sha256_text(secret)
    return hmac_sha256_text(secret_hash, f"sgp-auth:{challenge}")


def session_key_from_secret(secret, challenge):
    return session_key_from_secret_hash(sha256_text(secret), challenge)


def session_key_from_secret_hash(secret_hash, challenge):
    return hmac_sha256_bytes(secret_hash.encode("utf-8"), f"sgp-session:{challenge}".encode("utf-8"))


def service_access_proof(access_token, msg_id):
    token_hash = sha256_text(access_token)
    return hmac_sha256_text(token_hash, f"sgp-service:{msg_id}")


def endpoint_access_proof(access_token, msg_id, service_id, endpoint_id):
    token_hash = sha256_text(access_token)
    return hmac_sha256_text(token_hash, f"sgp-endpoint:{msg_id}:{service_id}:{endpoint_id}")


def _xor_bytes(data, mask):
    return bytes(left ^ right for left, right in zip(data, mask))


def _keystream(key, nonce, size):
    blocks = []
    counter = 0
    produced = 0
    while produced < size:
        counter_bytes = counter.to_bytes(4, "big")
        block = hmac_sha256_bytes(key, b"sgp-stream:" + nonce + counter_bytes)
        blocks.append(block)
        produced += len(block)
        counter += 1
    return b"".join(blocks)[:size]


def _encrypt_body(plaintext, key):
    nonce = secrets.token_bytes(ENCRYPTION_NONCE_LEN)
    ciphertext = _xor_bytes(plaintext, _keystream(key, nonce, len(plaintext)))
    tag = hmac_sha256_bytes(key, b"sgp-frame:" + nonce + ciphertext)
    return nonce + tag + ciphertext


def _decrypt_body(data, key):
    if len(data) < ENCRYPTION_NONCE_LEN + ENCRYPTION_TAG_LEN:
        raise ProtocolError(400, "BAD_ENCRYPTED_BODY")
    nonce = data[:ENCRYPTION_NONCE_LEN]
    tag = data[ENCRYPTION_NONCE_LEN:ENCRYPTION_NONCE_LEN + ENCRYPTION_TAG_LEN]
    ciphertext = data[ENCRYPTION_NONCE_LEN + ENCRYPTION_TAG_LEN:]
    expected_tag = hmac_sha256_bytes(key, b"sgp-frame:" + nonce + ciphertext)
    if not hmac.compare_digest(tag, expected_tag):
        raise ProtocolError(401, "BAD_ENCRYPTED_BODY_TAG")
    return _xor_bytes(ciphertext, _keystream(key, nonce, len(ciphertext)))


def b64_encode(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.b64encode(data).decode("ascii")


def b64_decode(text):
    if not text:
        return b""
    return base64.b64decode(text.encode("ascii"))


def _recvn(sock, n):
    chunks = []
    left = n
    while left > 0:
        chunk = sock.recv(left)
        if not chunk:
            raise EOFError("socket closed")
        chunks.append(chunk)
        left -= len(chunk)
    return b"".join(chunks)


def _next_seq():
    with _seq_lock:
        return next(_seq_counter) & 0xFFFFFFFF


def _pack_frame_header(body_len, seq, body_type=FRAME_BODY_JSON, flags=FRAME_FLAG_NONE):
    header_without_crc = FRAME_HEADER_STRUCT.pack(
        FRAME_MAGIC,
        FRAME_MAJOR,
        FRAME_MINOR,
        FRAME_HEADER_LEN,
        body_type,
        flags,
        0,
        body_len,
        seq,
        0,
    )
    header_crc = zlib.crc32(header_without_crc) & 0xFFFFFFFF
    return FRAME_HEADER_STRUCT.pack(
        FRAME_MAGIC,
        FRAME_MAJOR,
        FRAME_MINOR,
        FRAME_HEADER_LEN,
        body_type,
        flags,
        0,
        body_len,
        seq,
        header_crc,
    )


def _unpack_frame_header(raw):
    try:
        magic, major, minor, header_len, body_type, flags, reserved, body_len, seq, header_crc = (
            FRAME_HEADER_STRUCT.unpack(raw)
        )
    except struct.error as exc:
        raise ProtocolError(400, "BAD_FRAME_HEADER") from exc

    if magic != FRAME_MAGIC:
        raise ProtocolError(400, "BAD_FRAME_MAGIC")
    if major != FRAME_MAJOR:
        raise ProtocolError(426, "FRAME_VERSION_NOT_SUPPORTED")
    if minor > FRAME_MINOR:
        raise ProtocolError(426, "FRAME_VERSION_NOT_SUPPORTED")
    if header_len != FRAME_HEADER_LEN:
        raise ProtocolError(400, "BAD_FRAME_HEADER_LENGTH")
    if body_type not in (FRAME_BODY_JSON, FRAME_BODY_ENCRYPTED_JSON):
        raise ProtocolError(415, "FRAME_BODY_TYPE_NOT_SUPPORTED")
    if reserved != 0:
        raise ProtocolError(400, "BAD_FRAME_RESERVED")
    if body_len <= 0 or body_len > MAX_FRAME_SIZE:
        raise ProtocolError(400, "BAD_FRAME_LENGTH")

    header_without_crc = FRAME_HEADER_STRUCT.pack(
        magic,
        major,
        minor,
        header_len,
        body_type,
        flags,
        reserved,
        body_len,
        seq,
        0,
    )
    expected_crc = zlib.crc32(header_without_crc) & 0xFFFFFFFF
    if header_crc != expected_crc:
        raise ProtocolError(400, "BAD_FRAME_HEADER_CRC")
    return body_len, seq, body_type, flags


def send_msg(sock, obj, cipher_key=None):
    data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    body_type = FRAME_BODY_JSON
    if cipher_key is not None:
        data = _encrypt_body(data, cipher_key)
        body_type = FRAME_BODY_ENCRYPTED_JSON
    if len(data) > MAX_FRAME_SIZE:
        raise ProtocolError(413, "FRAME_TOO_LARGE")
    sock.sendall(_pack_frame_header(len(data), _next_seq(), body_type=body_type) + data)


def recv_msg(sock, cipher_key=None):
    header = _recvn(sock, FRAME_HEADER_LEN)
    length, _, body_type, _ = _unpack_frame_header(header)
    raw = _recvn(sock, length)
    if body_type == FRAME_BODY_ENCRYPTED_JSON:
        if cipher_key is None:
            raise ProtocolError(401, "ENCRYPTION_KEY_REQUIRED")
        raw = _decrypt_body(raw, cipher_key)
    try:
        msg = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(400, "BAD_JSON") from exc
    if msg.get("version") != VERSION:
        raise ProtocolError(426, "VERSION_NOT_SUPPORTED")
    if msg.get("protocol_version", VERSION) != VERSION:
        raise ProtocolError(426, "VERSION_NOT_SUPPORTED")
    return msg


def make_msg(cmd, role, msg_type="REQ", msg_id=None, token=None, service_id=None,
             payload=None, status=None, message=None, ext=None):
    obj = {
        "version": VERSION,
        "protocol_version": VERSION,
        "type": msg_type,
        "id": msg_id or uuid.uuid4().hex,
        "role": role,
        "cmd": cmd,
        "payload": payload or {},
        "ext": ext or {},
    }
    if token is not None:
        obj["token"] = token
    if service_id is not None:
        obj["service_id"] = service_id
    if status is not None:
        obj["status"] = status
    if message is not None:
        obj["message"] = message
    return obj


def _default_error_category(status):
    if status == 401:
        return "auth"
    if status == 403:
        return "authz"
    if status == 404:
        return "routing"
    if status == 408:
        return "timeout"
    if status in (413, 429):
        return "policy"
    if status == 503:
        return "lifecycle"
    if status >= 500:
        return "runtime"
    return "request"


def make_error(message, status, detail=None, role=None):
    layer, component, text = ERROR_CATALOG.get(
        message,
        (None, _default_error_category(status), "Request failed."),
    )
    error = {
        "layer": layer or role or "protocol",
        "component": component,
        "code": message,
        "message": text,
    }
    if detail not in (None, {}, []):
        error["detail"] = detail
    return error


def make_resp(req, role, status=200, message="OK", payload=None, service_id=None):
    resp_payload = dict(payload or {})
    if status >= 400 and "error" not in resp_payload:
        detail = resp_payload.get("output") if set(resp_payload.keys()) == {"output"} else dict(resp_payload)
        if detail == {}:
            detail = None
        resp_payload["error"] = make_error(message, status, detail=detail, role=role)
    return make_msg(
        req.get("cmd", "ERROR"),
        role,
        msg_type="RESP",
        msg_id=req.get("id"),
        service_id=service_id if service_id is not None else req.get("service_id"),
        status=status,
        message=message,
        payload=resp_payload,
    )


def close_quietly(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass
