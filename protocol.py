import base64
import hashlib
import itertools
import json
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
FRAME_FLAG_NONE = 0
FRAME_HEADER_STRUCT = struct.Struct("!4sBBHBBHIII")

_seq_lock = threading.Lock()
_seq_counter = itertools.count(1)


class ProtocolError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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
    if body_type != FRAME_BODY_JSON:
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
    return body_len, seq, flags


def send_msg(sock, obj):
    data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_FRAME_SIZE:
        raise ProtocolError(413, "FRAME_TOO_LARGE")
    sock.sendall(_pack_frame_header(len(data), _next_seq()) + data)


def recv_msg(sock):
    header = _recvn(sock, FRAME_HEADER_LEN)
    length, _, _ = _unpack_frame_header(header)
    raw = _recvn(sock, length)
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


def make_resp(req, role, status=200, message="OK", payload=None, service_id=None):
    return make_msg(
        req.get("cmd", "ERROR"),
        role,
        msg_type="RESP",
        msg_id=req.get("id"),
        service_id=service_id if service_id is not None else req.get("service_id"),
        status=status,
        message=message,
        payload=payload or {},
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
