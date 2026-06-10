import base64
import os


DEFAULT_CHUNK_SIZE = 8192
MAX_CHUNK_SIZE = 65536


def _root(service):
    metadata = service.get("metadata", {})
    root_dir = metadata.get("root_dir", "shared_files")
    root_dir = os.path.abspath(root_dir)
    os.makedirs(root_dir, exist_ok=True)
    return root_dir


def _safe_path(root_dir, user_path):
    user_path = str(user_path or ".").replace("\\", "/").lstrip("/")
    full_path = os.path.abspath(os.path.join(root_dir, user_path))
    if full_path != root_dir and not full_path.startswith(root_dir + os.sep):
        raise ValueError("path escapes service root")
    return full_path


def _rel(root_dir, full_path):
    value = os.path.relpath(full_path, root_dir)
    return "." if value == "." else value.replace("\\", "/")


def list_files(service, input_obj):
    root_dir = _root(service)
    folder = _safe_path(root_dir, input_obj.get("path", "."))
    if not os.path.isdir(folder):
        return 404, "DIR_NOT_FOUND", {}

    entries = []
    for name in sorted(os.listdir(folder)):
        full_path = os.path.join(folder, name)
        stat = os.stat(full_path)
        entries.append({
            "name": name,
            "path": _rel(root_dir, full_path),
            "is_dir": os.path.isdir(full_path),
            "size": stat.st_size,
        })
    return 200, "OK", {"path": _rel(root_dir, folder), "entries": entries}


def stat_file(service, input_obj):
    root_dir = _root(service)
    path = _safe_path(root_dir, input_obj.get("path", "."))
    if not os.path.exists(path):
        return 404, "PATH_NOT_FOUND", {}
    stat = os.stat(path)
    return 200, "OK", {
        "path": _rel(root_dir, path),
        "is_dir": os.path.isdir(path),
        "size": stat.st_size,
    }


def read_chunk(service, input_obj):
    root_dir = _root(service)
    path = _safe_path(root_dir, input_obj.get("path"))
    if not os.path.isfile(path):
        return 404, "FILE_NOT_FOUND", {}

    offset = max(0, int(input_obj.get("offset", 0)))
    size = int(input_obj.get("size", DEFAULT_CHUNK_SIZE))
    size = max(1, min(size, MAX_CHUNK_SIZE))
    total_size = os.path.getsize(path)

    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read(size)

    next_offset = offset + len(data)
    return 200, "OK", {
        "path": _rel(root_dir, path),
        "offset": offset,
        "next_offset": next_offset,
        "size": total_size,
        "eof": next_offset >= total_size,
        "data_base64": base64.b64encode(data).decode("ascii"),
    }


def write_chunk(service, input_obj):
    metadata = service.get("metadata", {})
    if not metadata.get("allow_upload", False):
        return 403, "UPLOAD_DISABLED", {}

    root_dir = _root(service)
    path = _safe_path(root_dir, input_obj.get("path"))
    data = base64.b64decode(str(input_obj.get("data_base64", "")).encode("ascii"))
    if len(data) > MAX_CHUNK_SIZE:
        return 413, "CHUNK_TOO_LARGE", {"max_chunk_size": MAX_CHUNK_SIZE}

    offset = int(input_obj.get("offset", 0))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "r+b" if os.path.exists(path) else "wb"
    with open(path, mode) as f:
        f.seek(max(0, offset))
        f.write(data)

    return 200, "OK", {
        "path": _rel(root_dir, path),
        "written": len(data),
        "next_offset": max(0, offset) + len(data),
        "size": os.path.getsize(path),
    }


def handle(service, input_obj):
    op = str(input_obj.get("op", "list"))
    if op == "list":
        return list_files(service, input_obj)
    if op == "stat":
        return stat_file(service, input_obj)
    if op == "read_chunk":
        return read_chunk(service, input_obj)
    if op == "write_chunk":
        return write_chunk(service, input_obj)
    return 400, "UNKNOWN_FILE_OP", {"allowed_ops": ["list", "stat", "read_chunk", "write_chunk"]}
