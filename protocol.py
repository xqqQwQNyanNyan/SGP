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
    "BAD_FRAME_HEADER": ("protocol", False, "Frame header cannot be decoded."),
    "BAD_FRAME_MAGIC": ("protocol", False, "The peer did not send an SGP frame."),
    "FRAME_VERSION_NOT_SUPPORTED": ("protocol", False, "Use a supported SGP frame version."),
    "BAD_FRAME_HEADER_LENGTH": ("protocol", False, "Frame header length is invalid."),
    "FRAME_BODY_TYPE_NOT_SUPPORTED": ("protocol", False, "Use JSON or encrypted JSON body type."),
    "BAD_FRAME_RESERVED": ("protocol", False, "Reserved frame fields must be zero."),
    "BAD_FRAME_LENGTH": ("protocol", False, "Frame body length is empty or too large."),
    "BAD_FRAME_HEADER_CRC": ("protocol", True, "Retry the request if the connection is otherwise healthy."),
    "FRAME_TOO_LARGE": ("policy", False, "Reduce the message size."),
    "BAD_JSON": ("protocol", False, "Send valid UTF-8 JSON."),
    "VERSION_NOT_SUPPORTED": ("protocol", False, "Use a compatible SGP version."),
    "BAD_ENCRYPTED_BODY": ("security", False, "Encrypted frame body is malformed."),
    "BAD_ENCRYPTED_BODY_TAG": ("security", False, "Encrypted frame authentication failed."),
    "ENCRYPTION_KEY_REQUIRED": ("security", False, "Complete AUTH before sending encrypted frames."),
    "UNAUTHORIZED": ("auth", False, "Login again and use a valid session token."),
    "AUTH_FAILED": ("auth", False, "Check the shared secret."),
    "BAD_AUTH_FLOW": ("auth", False, "Send HELLO before AUTH."),
    "BAD_ROLE": ("request", False, "Role must be agent or client."),
    "SERVICE_TOKEN_INVALID": ("authz", False, "Check the Service access token."),
    "ENDPOINT_TOKEN_INVALID": ("authz", False, "Check the endpoint access token."),
    "SERVICE_NOT_FOUND": ("routing", False, "Refresh LIST and choose an existing service_id."),
    "AGENT_OFFLINE": ("lifecycle", True, "Wait for the Agent to reconnect or choose another online service."),
    "PAYLOAD_TOO_LARGE": ("policy", False, "Reduce payload.input size."),
    "SCHEMA_VALIDATION_FAILED": ("schema", False, "Adjust payload.input to match the service contract input_schema."),
    "TOO_MANY_REQUESTS": ("policy", True, "Retry later after the rate limit window resets."),
    "CALL_TIMEOUT": ("timeout", True, "Retry later or increase the service timeout."),
    "UNKNOWN_CMD": ("request", False, "Use a supported SGP command."),
    "COMMAND_NOT_ALLOWED": ("service_policy", False, "Choose a command from the service whitelist."),
    "COMMAND_TIMEOUT": ("service_timeout", True, "Retry or choose a faster command."),
    "COMMAND_FAILED": ("service_runtime", True, "Check the Agent environment and command availability."),
    "ENDPOINT_NOT_FOUND": ("service_routing", False, "Choose an endpoint from the service contract."),
    "METHOD_NOT_ALLOWED": ("service_policy", False, "Use an allowed HTTP method for this endpoint."),
    "BODY_TOO_LARGE": ("service_policy", False, "Reduce the HTTP request body size."),
    "HTTP_REQUEST_FAILED": ("service_runtime", True, "Check the local HTTP service behind the Agent."),
    "CUSTOM_HANDLER_FAILED": ("service_runtime", False, "Check the custom handler implementation."),
    "UNSUPPORTED_SERVICE_TYPE": ("service_runtime", False, "Add a handler for this service_type."),
    "DIR_NOT_FOUND": ("service_routing", False, "Choose an existing directory under the service root."),
    "PATH_NOT_FOUND": ("service_routing", False, "Choose an existing path under the service root."),
    "FILE_NOT_FOUND": ("service_routing", False, "Choose an existing file under the service root."),
    "UPLOAD_DISABLED": ("service_policy", False, "Enable allow_upload before writing files."),
    "CHUNK_TOO_LARGE": ("service_policy", False, "Reduce chunk size."),
    "UNKNOWN_FILE_OP": ("request", False, "Use one of the supported file operations."),
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
    return msg


def make_msg(cmd, role, msg_type="REQ", msg_id=None, token=None, service_id=None,
             payload=None, status=None, message=None, ext=None):
    obj = {
        "version": VERSION,
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


def make_error(message, status, detail=None, hint=None, retryable=None):
    category, default_retryable, default_hint = ERROR_CATALOG.get(
        message,
        (_default_error_category(status), status in (408, 429, 502, 503), "Check request parameters and service state."),
    )
    error = {
        "code": message,
        "category": category,
        "retryable": default_retryable if retryable is None else bool(retryable),
    }
    if detail not in (None, {}, []):
        error["detail"] = detail
    final_hint = default_hint if hint is None else hint
    if final_hint:
        error["hint"] = final_hint
    return error


def make_resp(req, role, status=200, message="OK", payload=None, service_id=None):
    resp_payload = dict(payload or {})
    if status >= 400 and "error" not in resp_payload:
        detail = resp_payload.get("output") if set(resp_payload.keys()) == {"output"} else dict(resp_payload)
        if detail == {}:
            detail = None
        resp_payload["error"] = make_error(message, status, detail=detail)
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
