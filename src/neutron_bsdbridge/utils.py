"""Shared helpers."""

import subprocess


def default_runner(argv):
    """Run one query argv and return stdout, or None when the target is absent."""
    proc = subprocess.run(argv, capture_output=True, text=True)
    if proc.returncode != 0:
        return None
    return proc.stdout
