"""Shared helpers."""

import dataclasses
import os
import subprocess

TIMEOUT = "timeout"


def default_run(argv, timeout=None, input=None):
    """Execute one argv and return (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, input=input
        )
    except subprocess.TimeoutExpired:
        return TIMEOUT, "", ""
    return proc.returncode, proc.stdout, proc.stderr


@dataclasses.dataclass
class Receipt:
    """What happened to one op."""

    op: object
    argv: tuple
    executed: bool
    ok: bool
    parked: bool = False
    note: str = ""

    def __str__(self):
        """Render the receipt as its state, argv, and note."""
        state = "ok" if self.ok else "parked" if self.parked else "FAILED"
        body = " ".join(self.argv) if self.argv else "(no invocation)"
        tail = f" # {self.note}" if self.note else ""
        return f"[{state}] {body}{tail}"


def write_if_changed(path, text):
    """Atomically write a file when its content differs."""
    try:
        with open(path) as f:
            if f.read() == text:
                return False
    except OSError:
        pass
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.rename(tmp, path)
    return True
