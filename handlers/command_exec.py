import os
import shlex
import subprocess


def command_args(command):
    if os.name == "nt":
        if command == "dir":
            return ["cmd", "/c", "dir"]
        if command == "pwd":
            return ["cmd", "/c", "cd"]
    if command == "dir":
        return ["ls"]
    return shlex.split(command)


def handle(service, input_obj):
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
